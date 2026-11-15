"""Launch the experimental 9Router gateway and connect BurpAI to it."""
import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys
from tempfile import NamedTemporaryFile
import time
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import ProxyHandler, Request, build_opener
import webbrowser

ROOT = Path(__file__).resolve().parent
STATE = ROOT / ".state"
APP = ROOT / "node_modules" / "9router" / "app"
BASE_URL = "http://127.0.0.1:20128"
PRIORITY_PAGE = "burpai-top-priority.html"
BUILD = APP / ".next-cli-build"
DASHBOARD_CHUNK = BUILD / "static" / "chunks" / "5497-870732fd9d818574.js"
sys.path.insert(0, str(ROOT.parent / "provider_hub"))
from llm_hub import PROFILE, atomic


def running():
    try:
        with build_opener(ProxyHandler({})).open(BASE_URL + "/api/health", timeout=3) as response:
            return json.load(response).get("ok") is True
    except Exception:
        return False


def replace_asset(path, content):
    with NamedTemporaryFile("wb", dir=path.parent, suffix=".tmp", delete=False) as temp:
        temp.write(content)
    try:
        os.replace(temp.name, path)
    finally:
        Path(temp.name).unlink(missing_ok=True)


def install_dashboard_link():
    # Keep the first client render identical to 9Router's prebuilt HTML.
    component = "function k({onClose:e}){let t=(0,d.usePathname)()"
    navigation = "children:[v.map(t=>(0,n.jsxs)(l(),{href:t.href,onClick:e"
    header = "function C({onMenuClick:e,showMenuButton:t=!0}){let a=(0,i.usePathname)()"
    actions = 'className:"flex items-center gap-1 shrink-0",children:[s&&("OIDC"'
    try:
        original = DASHBOARD_CHUNK.read_bytes()
        chunk = original.decode("utf-8")
        if "setShowBurpPriority" not in chunk:
            if chunk.count(component) != 1 or chunk.count(navigation) != 1:
                raise ValueError("sidebar changed")
            chunk = chunk.replace(component, (
                "function k({onClose:e}){"
                "let [showBurpPriority,setShowBurpPriority]=(0,r.useState)(!1);"
                "(0,r.useEffect)(()=>{setShowBurpPriority(!0)},[]);"
                "let t=(0,d.usePathname)()"
            )).replace(navigation, (
                'children:[(showBurpPriority?[...v.slice(0,3),'
                f'{{href:"/{PRIORITY_PAGE}",label:"Provider Priority",icon:"swap_vert",fullPage:!0}},'
                '...v.slice(3)]:v).map(t=>(0,n.jsxs)(t.fullPage?"a":l(),'
                '{href:t.href,"aria-label":t.fullPage?t.label:void 0,onClick:e'
            ))
        if "setShowBurpPriorityAction" not in chunk:
            if chunk.count(header) != 1 or chunk.count(actions) != 1:
                raise ValueError("header changed")
            chunk = chunk.replace(header, (
                "function C({onMenuClick:e,showMenuButton:t=!0}){"
                "let [showBurpPriorityAction,setShowBurpPriorityAction]=(0,r.useState)(!1);"
                "(0,r.useEffect)(()=>{setShowBurpPriorityAction(!0)},[]);"
                "let a=(0,i.usePathname)()"
            )).replace(actions, (
                'className:"flex items-center gap-1 shrink-0",children:['
                'showBurpPriorityAction&&["/dashboard","/dashboard/endpoint"].includes(a)&&(0,n.jsx)("a",{'
                f'href:"/{PRIORITY_PAGE}",'
                'className:"inline-flex items-center px-3 h-8 rounded-lg bg-primary/10 text-primary '
                'hover:bg-primary/20 transition-colors text-sm font-medium whitespace-nowrap",'
                'children:"Provider Priority"}),s&&("OIDC"'
            ))
        updated = chunk.encode("utf-8")
        if updated != original:
            replace_asset(DASHBOARD_CHUNK, updated)

        # The original chunk URL is immutable. Give the dashboard a fresh URL
        # in both the script tags and the embedded React module references.
        name = DASHBOARD_CHUNK.name.encode("ascii")
        reference = re.compile(re.escape(name) + rb"(?:\?burpai=[0-9a-f]+)?")
        revision = sha256(updated).hexdigest()[:12].encode("ascii")
        for route in ("dashboard.html", "dashboard/endpoint.html"):
            pages = [BUILD / "server" / "app" / route]
            pages.extend((BUILD / "server" / "route-cache" / "APP_PAGE").glob(f"*/$/{route}"))
            for page in pages:
                content = page.read_bytes()
                revised = reference.sub(name + b"?burpai=" + revision, content)
                if revised != content:
                    replace_asset(page, revised)
    except (OSError, ValueError) as error:
        print(f"Could not install the Provider Priority link in 9Router: {error}", file=sys.stderr)


def start():
    install_dashboard_link()
    install_empty_completion_fix()
    if running():
        return
    runtime_path = ROOT / "runtime.json"
    runtime = json.loads(runtime_path.read_text(encoding="utf-8")) if runtime_path.exists() else {}
    node = runtime.get("node", "node")
    if not Path(node).is_file():
        node = shutil.which("node")
    if not node:
        raise RuntimeError("Install Node.js 24 or update nine_router/runtime.json.")
    STATE.mkdir(exist_ok=True)
    secrets_path = STATE / "server.json"
    if not secrets_path.exists():
        atomic(secrets_path, {
            "JWT_SECRET": secrets.token_urlsafe(48),
            "API_KEY_SECRET": secrets.token_urlsafe(48),
            "MACHINE_ID_SALT": secrets.token_urlsafe(32),
            "INITIAL_PASSWORD": secrets.token_urlsafe(18),
        })
    server_secrets = json.loads(secrets_path.read_text(encoding="utf-8"))
    environment = dict(os.environ, **server_secrets)
    environment.update(
        DATA_DIR=str(STATE / "data"),
        HOSTNAME="127.0.0.1",
        PORT="20128",
        NODE_ENV="production",
        NEXT_TELEMETRY_DISABLED="1",
        ENABLE_REQUEST_LOGS="false",
        BASE_URL=BASE_URL,
        NEXT_PUBLIC_BASE_URL=BASE_URL,
    )
    shutil.copyfile(ROOT / PRIORITY_PAGE, APP / "public" / PRIORITY_PAGE)
    flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    with (STATE / "server.log").open("ab") as log:
        process = subprocess.Popen(
            [node, "--dns-result-order=ipv4first", str(APP / "custom-server.js")],
            cwd=APP, env=environment, stdin=subprocess.DEVNULL,
            stdout=log, stderr=log, creationflags=flags,
            start_new_session=os.name != "nt",
        )
    atomic(STATE / "process.json", {"pid": process.pid})
    for _ in range(90):
        if running():
            return
        if process.poll() is not None:
            raise RuntimeError("9Router stopped during startup. See nine_router/.state/server.log.")
        time.sleep(0.5)
    raise RuntimeError("9Router startup timed out. See nine_router/.state/server.log.")


def install_empty_completion_fix():
    """Recover blank completions and advance the combo after a prompt block."""
    path = BUILD / "server" / "chunks" / "5308.js"
    original = path.read_bytes()
    source = original.decode("utf-8")
    old = ('g="string"==typeof c?.reasoning_content&&c.reasoning_content.trim().length>0,'
           'h=b.finish_reason;if(!e&&!f&&!g&&("stop"!==h&&"length"!==h&&"tool_calls"!==h&&'
           '"function_call"!==h||"in_progress"===h||"incomplete"===h))return!0')
    new = ('h=b.finish_reason;if(!e&&!f&&!c?.refusal&&!t(h)&&'
           '!["refusal","safety","recitation","blocklist","prohibited_content"].includes('
           'String(h||"").toLowerCase()))return!0')
    if new not in source:
        if source.count(old) != 1:
            raise RuntimeError("The installed 9Router build does not match the empty-completion fix.")
        source = source.replace(old, new)
        source = source.replace('if(b!==r.length-1&&(f.headers?.get?.("content-type")||"").includes("application/json"))',
                                'if((f.headers?.get?.("content-type")||"").includes("application/json"))')
        source = source.replace('u="Zero usable content",z=200;continue',
                                'u="Zero usable content",z=502;continue')
    if "burpEmptyRetried" not in source:
        loop = 'let u=null,y=null,z=null,A=null;for(let b=0;b<r.length;b++)'
        empty = 'h.warn("COMBO",`Model ${e} returned HTTP 200 with zero usable content, falling back to next model`)'
        if source.count(loop) != 1 or source.count(empty) != 1:
            raise RuntimeError("The installed 9Router combo retry loop has changed.")
        source = source.replace(loop,
            'let burpEmptyRetried=new Set;let u=null,y=null,z=null,A=null;for(let b=0;b<r.length;b++)')
        source = source.replace(empty,
            'if(!burpEmptyRetried.has(e)){burpEmptyRetried.add(e);'
            'h.warn("COMBO",`Model ${e} returned empty content; retrying the same model once`);'
            'b--;continue}' + empty)
    # Prompt blocks are request-scoped failures. Keep their original explanation
    # for exhaustion, and let the remaining configured models try the request.
    # The names e/f/h/j/m/s/u/z/A belong to the pinned build's combo loop.
    feedback_prefix = 'const burpPromptFeedback=a?.response?.promptFeedback||a?.promptFeedback;'
    blocked_response = (
        'new Response(JSON.stringify({error:{'
        'message:"Provider rejected this request: "+(burpPromptFeedback.blockReasonMessage||burpPromptFeedback.blockReason),'
        'type:"provider_prompt_blocked",code:"provider_prompt_blocked"}}),'
        '{status:403,headers:{"Content-Type":"application/json"}})'
    )
    old_feedback = feedback_prefix + 'if(burpPromptFeedback?.blockReason)return ' + blocked_response + ';'
    new_feedback = feedback_prefix + '''
if (burpPromptFeedback?.blockReason) {
    const blockedResponse = ''' + blocked_response + ''';
    h.warn("COMBO", `Model ${e} rejected the prompt; trying the next configured model`, {status: 403});
    if (j === "smart" && m && e === s) (0, v.F5)(i, m);
    u = "Provider rejected this request: " + (burpPromptFeedback.blockReasonMessage || burpPromptFeedback.blockReason);
    z = z || 403;
    A = A || blockedResponse;
    continue;
}
'''
    if source.count(old_feedback) == 1:
        source = source.replace(old_feedback, new_feedback)
    elif new_feedback not in source:
        anchor = 'let a=await f.clone().json();if(function(a){'
        if source.count(anchor) != 1:
            raise RuntimeError("The installed 9Router completion parser has changed.")
        source = source.replace(anchor,
            'let a=await f.clone().json();' + new_feedback + 'if(function(a){')
    updated = source.encode("utf-8")
    if updated != original:
        replace_asset(path, updated)


def connect_burp():
    connection = json.loads((STATE / "burp-connection.json").read_text(encoding="utf-8"))
    settings = json.loads(PROFILE.read_text(encoding="utf-8-sig")) if PROFILE.exists() else {}
    updates = dict(provider="hub", hub_base_url=BASE_URL + "/v1",
                   hub_model=connection["model"], hub_api_key=connection["key"])
    if connection.get("embedding_model"):
        updates.update(embedding_base_url=BASE_URL + "/v1",
                       embedding_model=connection["embedding_model"],
                       embedding_api_key=connection["key"])
    if all(settings.get(key) == value for key, value in updates.items()):
        return
    if PROFILE.exists():
        backup = PROFILE.with_name(PROFILE.name + ".9router-backup-" + str(time.time_ns()))
        backup.write_bytes(PROFILE.read_bytes())
    settings.update(updates)
    atomic(PROFILE, settings)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--no-browser", action="store_true")
    parser.add_argument("--no-connect", action="store_true")
    parser.add_argument("--top-priority", action="store_true",
                        help="Open the provider priority setting for BurpAI's chat combo")
    args = parser.parse_args()
    start()
    if not args.no_connect:
        connect_burp()
    if not args.no_browser:
        page = BASE_URL + "/dashboard"
        if args.top_priority:
            connection = json.loads((STATE / "burp-connection.json").read_text(encoding="utf-8"))
            page = BASE_URL + "/" + PRIORITY_PAGE + "?" + urlencode({"combo": connection["model"]})
            try:
                with build_opener(ProxyHandler({})).open(Request(page, method="HEAD"), timeout=3):
                    pass
            except HTTPError as error:
                if error.code == 404:
                    parser.exit(1, "Restart 9Router once to load the new Top Priority page.\n")
                raise
        webbrowser.open(page)
    print("9Router is running at " + BASE_URL)
    if not args.no_connect:
        print("BurpAI is configured for 9Router. Reload the extension if it is already open.")


if __name__ == "__main__":
    main()

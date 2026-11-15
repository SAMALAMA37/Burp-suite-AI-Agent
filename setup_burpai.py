#!/usr/bin/env python3
"""Prepare BurpAI with Python 3, using Windows Python for services from WSL."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parent
BASE = 'http://127.0.0.1:11434'
MODEL = 'embeddinggemma'
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))
JYTHON = 'jython-standalone-2.7.4.jar'
EXTENSION_FILES = (
    'BurpAI_v4_Extension.py', 'BurpAI_v4_Website.py', 'BurpAI_v4_Semantic.py',
    'BurpAI_v4_Workspace.py', 'BurpAI_v4_Documents.py', 'BurpAI_v4_Investigation.py',
    'BurpAI_v4_Lab.py', 'BurpAI_v4_LocalTools.py',
    'document_viewer/viewer.html', 'document_viewer/viewer.css',
    'document_viewer/viewer.js', 'document_viewer/vendor.js', 'document_viewer/LICENSES.txt',
)
# The adapter imports at startup and sends the helper to WSL on connection.
IMPORT_FILES = ('BurpAI_v4_WSL.py', 'burpai_wsl_runner.py')
HUB_FILES = ('provider_hub/launch_hub.py', 'provider_hub/llm_hub.py',
             'provider_hub/provider_catalog.json', 'provider_hub/dist/index.html',
             'provider_hub/dist/app.js', 'provider_hub/dist/style.css')


def api(route, payload=None, timeout=10):
    data = None if payload is None else json.dumps(payload).encode('utf-8')
    request = urllib.request.Request(BASE + route, data, {'Content-Type': 'application/json'})
    with OPENER.open(request, timeout=timeout) as response:
        return json.load(response)


def ready():
    try:
        return isinstance(api('/api/tags'), dict)
    except Exception:
        return False


def find_ollama():
    found = shutil.which('ollama')
    if found:
        return found
    for base in (os.environ.get('LOCALAPPDATA'), os.environ.get('ProgramFiles')):
        if base:
            for relative in ('Programs/Ollama/ollama.exe', 'Ollama/ollama.exe'):
                path = Path(base) / relative
                if path.is_file():
                    return str(path)
    return None


def download(url, target, maximum):
    temporary = target.with_name(target.name + '.part')
    try:
        total = 0
        with urllib.request.urlopen(url, timeout=60) as response, temporary.open('wb') as output:
            while True:
                block = response.read(1024 * 1024)
                if not block:
                    break
                total += len(block)
                if total > maximum:
                    raise RuntimeError('Download exceeds expected size: ' + target.name)
                output.write(block)
                print('\rDownloading %s: %d MiB' % (target.name, total // (1024*1024)), end='', flush=True)
        print()
        os.replace(str(temporary), str(target))
    finally:
        if temporary.exists():
            temporary.unlink()


def valid_jython(path):
    try:
        with zipfile.ZipFile(path) as archive:
            return 'org/python/util/jython.class' in archive.namelist()
    except (OSError, zipfile.BadZipFile):
        return False


def check_files(required):
    failed = False
    for name in required:
        present = (ROOT / name).is_file()
        print(name + ': ' + ('OK' if present else 'missing'))
        failed |= not present
    path = ROOT / JYTHON
    valid = valid_jython(path)
    print(JYTHON + ': ' + ('OK' if valid else 'invalid' if path.exists() else 'missing'))
    return valid and not failed


def ensure_files(required):
    missing = [name for name in required if not (ROOT / name).is_file()]
    allowed = EXTENSION_FILES + IMPORT_FILES + HUB_FILES
    for filename in ('BurpAI_v4_5_WSL_Bridge_Update.zip', 'BurpAI_v4_5_Workbench.zip',
                     'BurpAI_v4_4_Website_Analyse.zip'):
        if not missing:
            break
        archive_path = ROOT / filename
        if not archive_path.is_file():
            continue
        with zipfile.ZipFile(str(archive_path)) as archive:
            for name in missing:
                if name not in allowed or name not in archive.namelist():
                    continue
                info = archive.getinfo(name)
                if info.file_size > 2 * 1024 * 1024:
                    raise RuntimeError('Unexpected extension file size: ' + name)
                (ROOT / name).parent.mkdir(parents=True, exist_ok=True)
                (ROOT / name).write_bytes(archive.read(name))
        missing = [name for name in required if not (ROOT / name).is_file()]
    if missing:
        raise RuntimeError('Place this script beside the extension files or its ZIP. Missing: ' + ', '.join(missing))
    jar = ROOT / JYTHON
    if not jar.exists():
        print('Downloading Jython 2.7.4 from Maven Central...')
        url = 'https://repo.maven.apache.org/maven2/org/python/jython-standalone/2.7.4/jython-standalone-2.7.4.jar'
        download(url, jar, 100 * 1024 * 1024)
    if not valid_jython(jar):
        raise RuntimeError('Invalid Jython JAR: ' + str(jar))
    return jar


def ensure_server():
    if ready():
        print('Ollama is already running.')
        return
    executable = find_ollama()
    if not executable:
        if os.name != 'nt':
            raise RuntimeError('Install Ollama from https://ollama.com/download then rerun this script.')
        installer = ROOT / 'OllamaSetup.exe'
        print('Downloading the official Ollama Windows installer...')
        download('https://ollama.com/download/OllamaSetup.exe', installer, 4 * 1024**3)
        print('Installing Ollama. Complete any Windows installer prompt that appears.')
        subprocess.run([str(installer), '/VERYSILENT', '/NORESTART'], check=True)
        executable = find_ollama()
        if not executable:
            raise RuntimeError('Ollama installation finished but executable was not found. Reopen the terminal and rerun.')
    if ready():
        return
    log_path = ROOT / 'burpai_ollama.log'
    with log_path.open('ab') as log:
        options = {'stdin': subprocess.DEVNULL, 'stdout': log, 'stderr': log}
        if os.name == 'nt':
            options['creationflags'] = subprocess.CREATE_NO_WINDOW | subprocess.DETACHED_PROCESS
        else:
            options['start_new_session'] = True
        subprocess.Popen([executable, 'serve'], **options)
    print('Starting Ollama...')
    for attempt in range(120):
        if ready():
            return
        time.sleep(1)
    raise RuntimeError('Ollama did not start. See ' + str(log_path))


def pull_model(model):
    print('Downloading %s...' % model)
    request = urllib.request.Request(BASE + '/api/pull', json.dumps({'model': model, 'stream': True}).encode(),
                                     {'Content-Type': 'application/json'})
    completed = False
    with OPENER.open(request, timeout=300) as response:
        for line in response:
            if not line.strip():
                continue
            event = json.loads(line)
            if event.get('error'):
                raise RuntimeError(event['error'])
            completed |= event.get('status') == 'success'
            total = event.get('total', 0)
            progress = ' %.1f%%' % (100.0 * event.get('completed', 0) / total) if total else ''
            print('\r' + str(event.get('status', 'Downloading')) + progress + ' ' * 16, end='', flush=True)
    print()
    if not completed:
        raise RuntimeError('Ollama ended the transfer before reporting success. Rerun setup to resume.')


def model_installed(model):
    tag = model if ':' in model.rsplit('/', 1)[-1] else model + ':latest'
    response = api('/api/tags', timeout=2)
    if not isinstance(response, dict) or not isinstance(response.get('models'), list):
        raise ValueError('Ollama returned an invalid model list.')
    return any(entry.get('name') in (model, tag) or entry.get('model') in (model, tag)
               for entry in response['models'] if isinstance(entry, dict))


def ensure_model(model=MODEL):
    if not model_installed(model):
        pull_model(model)
    print('Testing the embedding model...')
    result = api('/api/embed', {'model': model, 'input': ['BurpAI setup verification'], 'truncate': False}, timeout=300)
    vectors = result.get('embeddings') or []
    if len(vectors) != 1 or not vectors[0]:
        raise RuntimeError('Embedding model did not return a vector.')
    print('Embedding model ready (%d dimensions).' % len(vectors[0]))


def configure():
    path = Path.home() / '.burpai_config.json'
    data = {}
    if path.exists():
        data = json.loads(path.read_text(encoding='utf-8-sig'))
        if not isinstance(data, dict):
            raise RuntimeError('Existing BurpAI settings are invalid; settings were not overwritten.')
        backup = path.with_name(path.name + '.setup-backup-' + str(time.time_ns()))
        shutil.copy2(str(path), str(backup))
    data.setdefault('embedding_base_url', BASE)
    data.setdefault('embedding_model', MODEL)
    data.setdefault('embedding_api_key', '')
    data.setdefault('website_root', str(Path.home() / '.burpai_website'))
    temporary = path.with_name(path.name + '.setup-tmp')
    temporary.write_text(json.dumps(data, indent=2, ensure_ascii=True), encoding='utf-8')
    os.replace(str(temporary), str(path))
    print('Saved local embedding settings. Existing chat settings were preserved.')


def in_wsl():
    if sys.platform != 'linux':
        return False
    if os.environ.get('WSL_DISTRO_NAME') or os.environ.get('WSL_INTEROP'):
        return True
    return 'microsoft' in os.uname().release.lower()


def windows_setup(arguments):
    instructions = 'Run py -3 setup_burpai.py from Windows PowerShell in the BurpAI folder, using the same Windows account as Burp.'

    def capture(args):
        try:
            return subprocess.check_output(args, encoding='utf-8-sig', timeout=10).rstrip('\r\n')
        except (OSError, ValueError, subprocess.SubprocessError):
            return ''

    wslpath = shutil.which('wslpath')
    script = capture([wslpath, '-w', str(Path(__file__).resolve())]) if wslpath else ''
    if not script:
        raise RuntimeError('Could not resolve the Windows path to setup. ' + instructions)

    # Prefer a regular per-user install over a launcher that selects a Store alias.
    candidates = []
    powershell = shutil.which('powershell.exe')
    if powershell:
        appdata = capture([powershell, '-NoProfile', '-NonInteractive', '-Command',
                           '[Console]::OutputEncoding = [Text.Encoding]::UTF8; '
                           "[Environment]::GetFolderPath('LocalApplicationData')"])
        local = capture([wslpath, '-u', appdata]) if appdata else ''
        if local:
            installs = (Path(local) / 'Programs' / 'Python').glob('Python3*/python.exe')
            candidates.extend([str(path)] for path in sorted(installs, reverse=True))
    launcher = shutil.which('py.exe')
    if launcher:
        candidates.append([launcher, '-3'])
    version_check = "import sys; print(sys.platform == 'win32' and sys.version_info >= (3, 8))"
    for command in candidates:
        if capture(command + ['-I', '-c', version_check]) == 'True':
            print('Running setup with Windows Python so it can use the Windows Burp profile and Hub credentials.', flush=True)
            # Forward the original flags and return the child's result. A failed
            # setup must not be replayed with a second interpreter.
            try:
                return subprocess.run(command + [script] + arguments).returncode
            except OSError as exc:
                raise RuntimeError('Windows setup could not launch. ' + instructions) from exc
    raise RuntimeError('Could not launch Windows Python 3.8 or newer from WSL. ' + instructions)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true', help='Report missing or invalid dependencies without installing or changing settings')
    parser.add_argument('--no-hub', action='store_true', help='Keep direct model connections instead of starting Connection Hub')
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--files-only', action='store_true', help='Prepare only extension files and Jython. Skip Ollama, Connection Hub and settings changes.')
    mode.add_argument('--with-embeddings', action='store_true', help='Also prepare and verify local Ollama and embeddinggemma for semantic search.')
    args = parser.parse_args()
    use_hub = not (args.no_hub or args.files_only)
    if (use_hub or args.with_embeddings) and in_wsl():
        return windows_setup(sys.argv[1:])
    required = EXTENSION_FILES + IMPORT_FILES + (HUB_FILES if use_hub else ())
    if args.check:
        files_ok = check_files(required)
        if args.files_only:
            return 0 if files_ok else 1
        embeddings_ready = True
        if args.with_embeddings:
            print('Ollama executable: ' + (find_ollama() or 'not found'))
            try:
                embeddings_ready = model_installed(MODEL)
                print('Ollama server: running')
                print(MODEL + ': ' + ('installed' if embeddings_ready else 'missing'))
            except (OSError, ValueError):
                embeddings_ready = False
                print('Ollama server: unavailable at ' + BASE)
        if use_hub:
            try:
                with OPENER.open('http://127.0.0.1:8765/health', timeout=2) as response:
                    hub_ready = json.load(response).get('service') == 'BurpAI Connection Hub'
            except (OSError, ValueError, AttributeError):
                hub_ready = False
            print('Connection Hub: ' + ('running' if hub_ready else 'unavailable'))
        else:
            hub_ready = True
        return 0 if files_ok and embeddings_ready and hub_ready else 1
    print('Preparing BurpAI extension files and Jython...')
    jar = ensure_files(required)
    if args.with_embeddings:
        ensure_server()
        ensure_model()
        configure()
    if use_hub:
        sys.path.insert(0, str(ROOT / 'provider_hub'))
        from launch_hub import launch
        launch(connect=True)
    print('\nSETUP COMPLETE\n')
    print('In Burp:')
    print('1. Extensions > Settings > Python environment: select\n   ' + str(jar))
    print('2. Extensions > Installed > Add > Python: select\n   ' + str(ROOT / 'BurpAI_v4_Extension.py'))
    print('   If already loaded, reload the extension instead.')
    if args.files_only:
        print('Use Local Tools > Fixture checks for offline JSON assertions.')
    else:
        print('3. AI Agent > Website Analyse: enter a scoped URL to collect and search JavaScript.')
        if not args.with_embeddings:
            print('   Keyword and identifier search works without a model. Use --with-embeddings to set up local semantic search.')
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print('\nSetup stopped. Rerun to continue.', file=sys.stderr)
        sys.exit(130)
    except Exception as error:
        print('\nSetup failed: ' + str(error), file=sys.stderr)
        sys.exit(1)

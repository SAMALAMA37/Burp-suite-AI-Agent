"""Local, authenticated OpenAI-compatible provider hub. Python standard library only."""
import argparse
import base64
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import Request, build_opener, ProxyHandler, HTTPRedirectHandler

ROOT = Path(__file__).resolve().parent
PROFILE = Path.home()/'.burpai_config.json'
SOURCE = 'https://github.com/mnfst/awesome-free-llm-apis'
OVERRIDES = {
    'Cohere':'https://api.cohere.ai/compatibility/v1',
    'Google Gemini':'https://generativelanguage.googleapis.com/v1beta/openai',
    'Cloudflare Workers AI':'https://api.cloudflare.com/client/v4/accounts/{account_id}/ai/v1',
    'Kilo Code':'https://ai-gateway.kilo.ai/api/v1',
}
OPTIONAL_KEYS = {'Local','Kilo Code','LLM7.io','OVHcloud AI Endpoints'}
CLIENT_USER_AGENT = 'BurpAI-Connection-Hub/1.0'

def atomic(path, value):
    path.parent.mkdir(parents=True,exist_ok=True)
    temp=path.with_name(path.name+'.tmp-'+secrets.token_hex(4))
    try:
        with temp.open('w',encoding='utf-8') as handle:
            json.dump(value,handle,ensure_ascii=False,indent=2)
            handle.flush(); os.fsync(handle.fileno())
        if os.name!='nt': os.chmod(temp,0o600)
        os.replace(temp,path)
    finally:
        if temp.exists(): temp.unlink()

def protect(value, decrypt=False):
    """Windows DPAPI protects all persisted tokens for the current Windows user."""
    if not value: return ''
    if decrypt and value.startswith('dpapi:') and os.name != 'nt':
        raise RuntimeError('Connection Hub credentials are protected by Windows. Start the Hub with Windows Python under the account that saved them.')
    if os.name!='nt':
        return base64.b64decode(value[6:]).decode() if decrypt else 'local:'+base64.b64encode(value.encode()).decode()
    class Blob(ctypes.Structure):
        _fields_=[('size',ctypes.c_ulong),('data',ctypes.POINTER(ctypes.c_ubyte))]
    raw=base64.b64decode(value[6:]) if decrypt else value.encode('utf-8')
    buffer=ctypes.create_string_buffer(raw)
    source=Blob(len(raw),ctypes.cast(buffer,ctypes.POINTER(ctypes.c_ubyte))); target=Blob()
    fn=ctypes.windll.crypt32.CryptUnprotectData if decrypt else ctypes.windll.crypt32.CryptProtectData
    args=(ctypes.byref(source),None,None,None,None,1,ctypes.byref(target))
    if not fn(*args): raise OSError('Windows credential protection failed')
    try: result=ctypes.string_at(target.data,target.size)
    finally:
        free=ctypes.windll.kernel32.LocalFree
        free.argtypes=[ctypes.c_void_p]; free.restype=ctypes.c_void_p
        free(target.data)
    return result.decode('utf-8') if decrypt else 'dpapi:'+base64.b64encode(result).decode()

def identifier(name): return re.sub('[^a-z0-9]+','-',name.lower()).strip('-')

def endpoint(base, account=''):
    if '{account_id}' in base:
        if not re.fullmatch('[A-Za-z0-9_-]+',account or ''): raise ValueError('Enter the Cloudflare account ID.')
        base=base.replace('{account_id}',account)
    parsed=urlsplit(base)
    if parsed.username or parsed.password or parsed.query or parsed.fragment or not parsed.hostname:
        raise ValueError('Use an API base URL without credentials or query strings.')
    loopback=parsed.hostname in ('127.0.0.1','localhost','::1')
    if parsed.scheme!='https' and not (parsed.scheme=='http' and loopback):
        raise ValueError('Cloud endpoints require HTTPS; HTTP is allowed only on loopback.')
    return base.rstrip('/')

class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs): return None

class UpstreamError(Exception):
    def __init__(self,status,message,retry_after=0,kind='upstream_error'):
        self.status,self.message,self.retry_after=status,message,retry_after
        self.kind=kind
        super().__init__(message)

def upstream_reason(status,body,headers):
    """Classify failures without exposing upstream bodies, keys or echoed prompts."""
    body=body.lower()
    if status==403:
        if any(marker in body for marker in ('error-1010','error 1010',"browser's signature")):
            return 'client_signature_blocked','Cloudflare blocked the client signature (HTTP 403, error 1010). Contact the provider if this persists.'
        if headers.get('CF-Mitigated','').lower()=='challenge' or (
                'cloudflare' in headers.get('Server','').lower() and
                'text/html' in headers.get('Content-Type','').lower()):
            return 'gateway_blocked','The provider gateway returned an access-denied page (HTTP 403). This does not establish whether the API key is valid; contact the provider for access.'
        return 'access_denied','Access denied (HTTP 403). Check account/model permissions, regional availability and provider policy.'
    if status==401:
        return 'authentication_failed','The provider did not accept the API key (HTTP 401). Check or replace the saved key.'
    if status==429:
        return 'rate_or_quota_limit','Rate or quota limit reached (HTTP 429). Check the provider usage, limits and account tier before retrying.'
    if status==404:
        return 'resource_unavailable','The endpoint or model is unavailable to this account (HTTP 404). Check the API base URL and current model availability.'
    if status==503:
        return 'temporarily_unavailable','The provider is temporarily unavailable or overloaded (HTTP 503). Try again shortly or choose another live model.'
    if any(t in body for t in ('context length','context window','too many tokens','prompt is too long')):
        return 'context_limit','Context window exceeded; reduce the working context.'
    if 'tool' in body and status in (400,422):
        return 'tools_unsupported','Provider rejected native tools; use JSON-in-text compatibility.'
    return 'upstream_error','Provider rejected the request (HTTP %s).'%status

class Hub:
    def __init__(self,state_dir=None,profile=PROFILE,port=8765,transport=None):
        self.path=Path(state_dir or ROOT/'.state')/'connections.json'
        self.profile=Path(profile); self.port=port
        self.lock=threading.RLock(); self.events=[]; self.cooldowns={}
        self.transport=transport or self.request
        self.opener=build_opener(ProxyHandler({}),NoRedirect())
        self.catalog=json.loads((ROOT/'provider_catalog.json').read_text(encoding='utf-8'))
        if self.path.exists():
            self.config=json.loads(self.path.read_text(encoding='utf-8'))
        else:
            self.config=self.initial(); self.save()
        self.token=protect(self.config['token'],True)

    def initial(self):
        old=json.loads(self.profile.read_text(encoding='utf-8-sig')) if self.profile.exists() else {}
        providers=[]
        for source in self.catalog['providers']:
            name=source['name']; model=source.get('models',[{}])[0].get('id','')
            key=old.get('openrouter_api_key','') if name=='OpenRouter' else ''
            imported=old.get('model_name',model) if name=='OpenRouter' else model
            if name=='OpenRouter' and not (imported.endswith(':free') or imported=='openrouter/free'): imported='openrouter/free'
            providers.append({'id':identifier(name),'name':name,'base_url':OVERRIDES.get(name,source['baseUrl']),
                'account_id':'','key':protect(key),'enabled':bool(key),'model':imported,
                'key_url':source.get('url',''),'description':source.get('description',''),
                'models':source.get('models',[]),'optional_key':name in OPTIONAL_KEYS})
        local=old.get('local_base_url','http://127.0.0.1:11434/v1')
        providers.append({'id':'local','name':'Local','base_url':local,'account_id':'',
            'key':protect(old.get('local_api_key','')),'enabled':True,'model':old.get('local_model',''),
            'key_url':'','description':'Your local OpenAI-compatible server or Ollama.','models':[],'optional_key':True})
        order=['local','openrouter'] if old.get('provider')=='local' else ['openrouter','local']
        order += [p['id'] for p in providers if p['id'] not in order]
        embed_base=old.get('embedding_base_url','http://127.0.0.1:11434')
        embed_provider='openrouter' if urlsplit(embed_base).hostname=='openrouter.ai' else 'local'
        return {'token':protect(secrets.token_urlsafe(32)),'providers':providers,'order':order,
            'embedding':{'provider':embed_provider,'model':old.get('embedding_model','embeddinggemma')},
            'fallback':True,'source':SOURCE,'catalog_date':self.catalog.get('lastUpdated')}

    def save(self): atomic(self.path,self.config)

    def provider(self,pid):
        return next((p for p in self.config['providers'] if p['id']==pid),None)

    def embedding_alias(self):
        selection=self.config['embedding']; p=self.provider(selection['provider'])
        fingerprint=hashlib.sha256(json.dumps([p['id'],p['base_url'],p.get('account_id',''),selection['model']],sort_keys=True).encode()).hexdigest()[:20]
        return 'hub-embed-'+fingerprint

    def state(self):
        with self.lock:
            providers=[]
            for p in self.config['providers']:
                item={k:v for k,v in p.items() if k!='key'}
                item['has_key']=bool(p.get('key'))
                item['cooldown_seconds']=max(0,int(self.cooldowns.get(p['id'],0)-time.time()))
                item['ready']=bool(p['enabled'] and p['model'] and (item['has_key'] or p['optional_key']) and
                                   ('{account_id}' not in p['base_url'] or p.get('account_id')))
                providers.append(item)
            return {'providers':providers,'order':self.config['order'],'fallback':self.config['fallback'],
                'embedding':self.config['embedding'],'embedding_model_id':self.embedding_alias(),
                'endpoint':'http://127.0.0.1:%d/v1'%self.port,'events':list(reversed(self.events[-100:])),
                'catalog_date':self.config['catalog_date'],'source':SOURCE}

    def update_provider(self,data):
        with self.lock:
            p=self.provider(data.get('id'))
            if not p: raise ValueError('Unknown provider.')
            base=str(data.get('base_url',p['base_url'])).strip()
            account=str(data.get('account_id',p.get('account_id',''))).strip()
            # Permit saving an unconfigured Cloudflare placeholder, never using it.
            if '{account_id}' not in base or account: endpoint(base,account)
            elif base!=OVERRIDES.get('Cloudflare Workers AI'): raise ValueError('Invalid account URL.')
            model=str(data.get('model','')).strip()
            if len(model)>256 or any(ord(c)<32 for c in model): raise ValueError('Invalid model ID.')
            key=str(data.get('api_key','')).strip()
            if '\r' in key or '\n' in key: raise ValueError('Invalid API key.')
            if data.get('clear_key'): p['key']=''
            if urlsplit(base).netloc!=urlsplit(p['base_url']).netloc: p['key']=''
            if key: p['key']=protect(key)
            p.update(base_url=base,account_id=account,model=model,enabled=bool(data.get('enabled')))
            self.cooldowns.pop(p['id'],None); self.save()
        return self.state()

    def update_routing(self,data):
        with self.lock:
            order=data.get('order',self.config['order'])
            known={p['id'] for p in self.config['providers']}
            if set(order)!=known or len(order)!=len(known): raise ValueError('Routing must contain each connection once.')
            embedding=data.get('embedding',self.config['embedding'])
            if embedding.get('provider') not in known or not str(embedding.get('model','')).strip():
                raise ValueError('Choose an embedding provider and model.')
            self.config.update(order=order,fallback=bool(data.get('fallback',True)),
                               embedding={'provider':embedding['provider'],'model':str(embedding['model']).strip()})
            self.save()
        return self.state()

    def record(self,p,model,path,status,elapsed,reason='',error_kind=''):
        with self.lock:
            self.events.append({'time':time.time(),'provider':p['name'],'model':model,'operation':path,
                'status':status,'latency_ms':round(elapsed*1000),'message':reason,'error_kind':error_kind})
            self.events=self.events[-200:]

    def request(self,p,path,payload=None):
        base=endpoint(p['base_url'],p.get('account_id',''))
        url=base+'/'+path; shape='openai'
        if path=='models' and p['name']=='Cohere':
            url='https://api.cohere.com/v1/models?endpoint=chat&page_size=1000'; shape='cohere'
        elif path=='models' and p['name']=='Cloudflare Workers AI':
            url=base.rsplit('/v1',1)[0]+'/models/search'; shape='cloudflare'
        # Identify this application explicitly: library-default urllib headers can
        # trigger a provider's Cloudflare Browser Integrity Check before API auth.
        headers={'Content-Type':'application/json','Accept':'application/json','Accept-Encoding':'identity',
                 'User-Agent':CLIENT_USER_AGENT}
        if p.get('key'): headers['Authorization']='Bearer '+protect(p['key'],True)
        raw=None if payload is None else json.dumps(payload,ensure_ascii=False).encode('utf-8')
        started=time.monotonic()
        try:
            with self.opener.open(Request(url,raw,headers),timeout=120) as response:
                content=response.read(16*1024*1024+1)
                if len(content)>16*1024*1024: raise UpstreamError(502,'Provider response exceeded the response limit.')
                value=json.loads(content.decode('utf-8'))
            if isinstance(value,dict) and value.get('error'):
                code=(value['error'].get('code',502) if isinstance(value['error'],dict) else 502)
                raise UpstreamError(int(code) if str(code).isdigit() else 502,'Provider returned an API error.')
            if path=='models':
                rows=value.get('models',[]) if shape=='cohere' else value.get('result',[]) if shape=='cloudflare' else value.get('data',[])
                if isinstance(rows,dict): rows=rows.get('models',[])
                value={'data':[{'id':r.get('id') or r.get('name'),'object':'model'} for r in rows if isinstance(r,dict) and (r.get('id') or r.get('name'))]}
            self.record(p,(payload or {}).get('model',''),path,200,time.monotonic()-started)
            return value
        except HTTPError as exc:
            status=exc.code
            body=exc.read(8000).decode('utf-8','replace').lower(); retry=exc.headers.get('Retry-After','0')
            kind,reason=upstream_reason(status,body,exc.headers)
            message=p['name']+': '+reason
            self.record(p,(payload or {}).get('model',''),path,status,time.monotonic()-started,message,kind)
            raise UpstreamError(status,message,min(3600,int(retry)) if str(retry).isdigit() else 60,kind) from None
        except UpstreamError: raise
        except (TimeoutError,socket.timeout):
            raise UpstreamError(504,'Provider timed out. The request was not replayed automatically.') from None
        except Exception:
            raise UpstreamError(502,'Provider connection or response failed. Check this connection.') from None

    def models(self,pid):
        p=self.provider(pid)
        if not p: raise ValueError('Unknown provider.')
        return self.transport(p,'models',None)

    def chat(self,payload):
        if payload.get('model')!='hub-chat': raise UpstreamError(404,'Select the hub-chat routing model.')
        attempted=[]
        with self.lock:
            connections=[dict(self.provider(pid)) for pid in self.config['order']]
            fallback=self.config['fallback']
        for p in connections:
            if not p['enabled'] or not p['model'] or (not p.get('key') and not p['optional_key']): continue
            if self.cooldowns.get(p['id'],0)>time.time(): continue
            if '{account_id}' in p['base_url'] and not p.get('account_id'): continue
            # The free-only gateways must never silently choose a paid model.
            if p['name'] in ('OpenRouter','Kilo Code') and not (p['model'].endswith(':free') or p['model'] in ('openrouter/free','kilo-auto/free')):
                raise UpstreamError(400,'Choose a free model for '+p['name']+'.')
            request=dict(payload,model=p['model'],stream=False)
            try:
                response=self.transport(p,'chat/completions',request)
                if not response.get('choices'): raise UpstreamError(502,'Provider returned no chat choices.')
                response['burpai_hub']={'provider':p['name'],'model':p['model'],'attempts':attempted+[p['name']]}
                return response
            except UpstreamError as exc:
                attempted.append(p['name'])
                if not fallback or exc.status not in (402,429,503): raise
                self.cooldowns[p['id']]=time.time()+(exc.retry_after or (3600 if exc.status==402 else 60))
        raise UpstreamError(503,'No enabled connection is available. Configure keys/models or wait for provider cooldowns.')

    def embed(self,payload):
        with self.lock:
            if payload.get('model')!=self.embedding_alias():
                raise UpstreamError(409,'Embedding route changed. Reconnect Burp and rebuild this embedding index.')
            selection=dict(self.config['embedding']); p=dict(self.provider(selection['provider']))
        if not p.get('key') and not p['optional_key']: raise UpstreamError(401,'Configure an API key for the embedding provider.')
        response=self.transport(p,'embeddings',dict(payload,model=selection['model']))
        if not isinstance(response.get('data'),list): raise UpstreamError(502,'Provider returned no embedding vectors.')
        return response

    def connect_burp(self,embeddings=False):
        with self.lock:
            old=json.loads(self.profile.read_text(encoding='utf-8-sig')) if self.profile.exists() else {}
            if self.profile.exists():
                backup=self.profile.with_name(self.profile.name+'.hub-backup-'+str(time.time_ns()))
                backup.write_bytes(self.profile.read_bytes())
            old.update(provider='hub',hub_base_url='http://127.0.0.1:%d/v1'%self.port,
                       hub_api_key=self.token,hub_model='hub-chat')
            if embeddings:
                old.update(embedding_base_url=old['hub_base_url'],embedding_api_key=self.token,embedding_model=self.embedding_alias())
            atomic(self.profile,old)
        return {'ok':True,'message':'Connection saved. Reload the Burp extension.'+(' Run Index Files for the hub embedding route.' if embeddings else '')}

    def test(self,pid):
        p=self.provider(pid)
        if not p: raise ValueError('Unknown provider.')
        if p['name'] in ('OpenRouter','Kilo Code') and not (p['model'].endswith(':free') or p['model'] in ('openrouter/free','kilo-auto/free')):
            raise UpstreamError(400,'Choose a free model before testing this gateway.')
        payload={'model':p['model'],'messages':[{'role':'user','content':'Reply with OK.'}],
                 'max_tokens':256,'stream':False}
        # Only the fixed connection probe is replayed; ordinary chat is unchanged.
        for attempt in range(3):
            try:
                response=self.transport(p,'chat/completions',payload)
                break
            except UpstreamError as exc:
                if exc.status!=503 or attempt==2 or exc.retry_after>5: raise
                time.sleep(max(2**attempt,exc.retry_after))
        return {'ok':bool(response.get('choices')),'message':'Provider returned a chat response.'}

def server(hub):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*args): pass
        def reply(self,status,value,kind='application/json'):
            raw=json.dumps(value,ensure_ascii=False).encode('utf-8') if kind=='application/json' else value
            self.send_response(status); self.send_header('Content-Type',kind+'; charset=utf-8')
            self.send_header('Content-Length',str(len(raw))); self.send_header('Cache-Control','no-store')
            self.send_header('X-Content-Type-Options','nosniff'); self.send_header('X-Frame-Options','DENY')
            self.send_header('Content-Security-Policy',"default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'")
            self.end_headers(); self.wfile.write(raw)
        def allowed(self,auth=False):
            origins={'http://127.0.0.1:%d'%hub.port,'http://localhost:%d'%hub.port}
            if 'http://'+self.headers.get('Host','') not in origins or self.headers.get('Origin') not in (None,*origins):
                self.reply(403,{'error':{'message':'The Hub rejected the page origin. Open the dashboard using Launch Hub.','code':'hub_origin_required','source':'hub'}}); return False
            token=self.headers.get('Authorization','').removeprefix('Bearer ') or self.headers.get('X-Hub-Token','')
            if auth and not secrets.compare_digest(token.encode('utf-8'),hub.token.encode('utf-8')):
                self.reply(401,{'error':{'message':'Open the dashboard from Launch Hub or provide the hub API key.','code':'hub_auth_required'}}); return False
            return True
        def do_GET(self):
            if not self.allowed(): return
            path=urlsplit(self.path).path
            if path=='/health': self.reply(200,{'ok':True,'service':'BurpAI Connection Hub','client_user_agent':CLIENT_USER_AGENT}); return
            if path.startswith(('/api/','/v1/')):
                if not self.allowed(True): return
                if path=='/api/state': self.reply(200,hub.state()); return
                if path=='/v1/models':
                    self.reply(200,{'object':'list','data':[{'id':'hub-chat','object':'model'},
                        {'id':hub.embedding_alias(),'object':'model'}]}); return
                self.reply(404,{'error':{'message':'Not found.'}}); return
            assets={'/':'index.html','/app.js':'app.js','/style.css':'style.css'}
            if path not in assets: self.reply(404,{'error':{'message':'Not found.'}}); return
            target=ROOT/'dist'/assets[path]
            mime='text/html' if path=='/' else 'text/javascript' if path.endswith('.js') else 'text/css'
            self.reply(200,target.read_bytes(),mime)
        def do_POST(self):
            if not self.allowed(True): return
            try:
                size=int(self.headers.get('Content-Length','0'))
                if size<1 or size>16*1024*1024: raise ValueError('Invalid request size.')
                data=json.loads(self.rfile.read(size))
                if not isinstance(data,dict): raise ValueError('JSON object required.')
                path=urlsplit(self.path).path
                if path=='/api/provider': result=hub.update_provider(data)
                elif path=='/api/routing': result=hub.update_routing(data)
                elif path=='/api/connect': result=hub.connect_burp(bool(data.get('embeddings')))
                elif path=='/api/models': result=hub.models(data.get('id'))
                elif path=='/api/test': result=hub.test(data.get('id'))
                elif path=='/v1/chat/completions':
                    if data.get('stream'): raise ValueError('Use stream=false; routing buffers a complete response before returning it.')
                    result=hub.chat(data)
                elif path=='/v1/embeddings': result=hub.embed(data)
                else: self.reply(404,{'error':{'message':'Not found.'}}); return
                self.reply(200,result)
            except UpstreamError as exc: self.reply(exc.status,{'error':{'message':exc.message,'code':exc.status,'kind':exc.kind,'source':'provider'}})
            except (ValueError,KeyError): self.reply(400,{'error':{'message':'Invalid settings or request. Check the selected provider, URL, account and model.'}})
            except Exception: self.reply(500,{'error':{'message':'Hub operation failed. Check the connection settings.'}})
    return ThreadingHTTPServer(('127.0.0.1',hub.port),Handler)

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port',type=int,default=8765)
    parser.add_argument('--open',action='store_true')
    parser.add_argument('--connect-burp',action='store_true')
    args=parser.parse_args(); hub=Hub(port=args.port)
    if args.connect_burp: hub.connect_burp()
    service=server(hub)
    if args.open:
        import webbrowser
        webbrowser.open('http://127.0.0.1:%d/#token=%s'%(args.port,hub.token))
    print('BurpAI Connection Hub: http://127.0.0.1:%d'%args.port,flush=True)
    service.serve_forever()

if __name__=='__main__': main()

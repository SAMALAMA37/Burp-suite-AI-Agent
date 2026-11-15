"""Hub integration checks use temporary settings and local synthetic upstreams only."""
import base64
import json
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
from io import BytesIO
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.request import Request, build_opener, ProxyHandler

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'provider_hub'))
from llm_hub import Hub, UpstreamError, protect, endpoint, server, CLIENT_USER_AGENT


class CredentialFormatTests(unittest.TestCase):
    def test_linux_diagnoses_windows_credentials_before_decoding(self):
        windows_blob = 'dpapi:' + base64.b64encode(b'123456\x9d').decode('ascii')
        with patch('llm_hub.os.name', 'posix'):
            with self.assertRaisesRegex(RuntimeError, 'Start the Hub with Windows Python'):
                protect(windows_blob, decrypt=True)


class HubTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.profile=Path(self.tmp.name)/'profile.json'
        self.profile.write_text(json.dumps({'provider':'openrouter','openrouter_api_key':'secret-cloud',
            'model_name':'example:free','local_model':'local-test','embedding_model':'embeddinggemma','untouched':'keep'}))
        self.calls=[]
        def transport(p,path,body):
            self.calls.append((p['id'],path,body))
            return {'choices':[{'message':{'role':'assistant','content':'OK'}}]}
        self.hub=Hub(Path(self.tmp.name)/'state',self.profile,transport=transport)

    def test_catalog_all_connections_and_native_overrides(self):
        self.assertEqual(16,len(self.hub.state()['providers']))
        self.assertEqual('https://api.cohere.ai/compatibility/v1',self.hub.provider('cohere')['base_url'])
        self.assertTrue(self.hub.provider('google-gemini')['base_url'].endswith('/openai'))
        self.assertIn('{account_id}',self.hub.provider('cloudflare-workers-ai')['base_url'])

    def test_keys_encrypted_and_never_in_state(self):
        self.assertNotIn('secret-cloud',self.hub.path.read_text())
        self.assertNotIn('secret-cloud',json.dumps(self.hub.state()))
        self.assertNotIn(self.hub.token,json.dumps(self.hub.state()))
        self.assertEqual('secret-cloud',protect(self.hub.provider('openrouter')['key'],True))

    def test_saved_key_survives_restart_blank_save_and_failed_probe(self):
        settings={'id':'google-gemini','api_key':'synthetic-gemini-key',
                  'model':'synthetic-model','enabled':True}
        self.hub.update_provider(settings)
        restored=Hub(self.hub.path.parent,self.profile)
        self.assertEqual('synthetic-gemini-key',protect(restored.provider('google-gemini')['key'],True))
        settings['api_key']=''
        state=restored.update_provider(settings)
        self.assertTrue(next(p for p in state['providers'] if p['id']=='google-gemini')['has_key'])
        restored.transport=lambda *a: (_ for _ in ()).throw(UpstreamError(401,'Rejected'))
        with self.assertRaises(UpstreamError): restored.test('google-gemini')
        restarted=Hub(self.hub.path.parent,self.profile)
        self.assertEqual('synthetic-gemini-key',protect(restarted.provider('google-gemini')['key'],True))
        self.assertNotIn('synthetic-gemini-key',json.dumps(restarted.state()))

    def test_explicit_key_removal_persists(self):
        self.hub.update_provider({'id':'google-gemini','api_key':'synthetic-key','model':'test'})
        self.hub.update_provider({'id':'google-gemini','clear_key':True,'model':'test'})
        restored=Hub(self.hub.path.parent,self.profile)
        self.assertFalse(restored.provider('google-gemini')['key'])

    def test_quota_falls_back_without_changing_messages_or_tools(self):
        original=self.hub.transport
        def transport(p,path,body):
            if p['id']=='openrouter': raise UpstreamError(429,'Quota reached',17)
            return original(p,path,body)
        self.hub.transport=transport
        payload={'model':'hub-chat','messages':[{'role':'user','content':'synthetic'}],'tools':[{'type':'function'}]}
        response=self.hub.chat(payload)
        self.assertEqual('Local',response['burpai_hub']['provider'])
        self.assertEqual(['OpenRouter','Local'],response['burpai_hub']['attempts'])
        self.assertEqual(payload['messages'],self.calls[-1][2]['messages'])
        self.assertEqual(payload['tools'],self.calls[-1][2]['tools'])
        self.assertEqual('hub-chat',payload['model'])
        self.assertGreater(self.hub.cooldowns['openrouter'],0)

    def test_auth_context_and_ambiguous_errors_do_not_switch_provider(self):
        for status in (400,401,403,422,502,504):
            calls=[]
            def transport(p,path,body):
                calls.append(p['id']); raise UpstreamError(status,'test')
            self.hub.transport=transport
            with self.assertRaises(UpstreamError): self.hub.chat({'model':'hub-chat'})
            self.assertEqual(['openrouter'],calls)

    def test_fallback_can_be_disabled(self):
        self.hub.config['fallback']=False
        self.hub.transport=lambda *a: (_ for _ in ()).throw(UpstreamError(429,'limit'))
        with self.assertRaises(UpstreamError) as caught: self.hub.chat({'model':'hub-chat'})
        self.assertEqual(429,caught.exception.status)

    def test_embedding_route_change_rejects_old_alias(self):
        alias=self.hub.embedding_alias()
        self.hub.config['embedding']['model']='different'
        with self.assertRaises(UpstreamError) as caught: self.hub.embed({'model':alias,'input':['test']})
        self.assertEqual(409,caught.exception.status); self.assertEqual([],self.calls)

    def test_embedding_no_provider_fallback(self):
        calls=[]
        def transport(p,path,body):
            calls.append(p['id']); raise UpstreamError(429,'limit')
        self.hub.transport=transport
        with self.assertRaises(UpstreamError): self.hub.embed({'model':self.hub.embedding_alias(),'input':['test']})
        self.assertEqual(['local'],calls)

    def test_connect_preserves_local_cloud_and_embedding_settings(self):
        self.hub.connect_burp()
        data=json.loads(self.profile.read_text())
        self.assertEqual('hub',data['provider']); self.assertEqual('keep',data['untouched'])
        self.assertEqual('secret-cloud',data['openrouter_api_key']); self.assertEqual('local-test',data['local_model'])
        self.assertEqual('embeddinggemma',data['embedding_model']); self.assertNotIn('embedding_api_key',data)
        self.assertEqual(1,len(list(self.profile.parent.glob('profile.json.hub-backup-*'))))
        self.hub.connect_burp(True)
        self.assertEqual(self.hub.embedding_alias(),json.loads(self.profile.read_text())['embedding_model'])

    def test_host_change_clears_key_and_paid_gateway_models_are_blocked(self):
        self.hub.update_provider({'id':'openrouter','base_url':'https://example.invalid/v1','model':'paid-model','enabled':True})
        self.assertFalse(self.hub.provider('openrouter')['key'])
        self.hub.provider('openrouter')['key']=protect('new-secret')
        with self.assertRaises(UpstreamError): self.hub.chat({'model':'hub-chat'})
        with self.assertRaises(UpstreamError): self.hub.test('openrouter')
        self.assertEqual([],self.calls)

    def test_endpoint_validation(self):
        for url in ('http://public.example/v1','https://key@example.com/v1','https://example.com/v1?key=test'):
            with self.assertRaises(ValueError): endpoint(url)
        self.assertEqual('http://127.0.0.1:1234/v1',endpoint('http://127.0.0.1:1234/v1'))

    def test_unavailable_message_does_not_expose_upstream_body(self):
        error=HTTPError('https://example.invalid',503,'Unavailable',{},BytesIO(b'secret-key'))
        with patch.object(self.hub.opener,'open',side_effect=error):
            with self.assertRaises(UpstreamError) as caught:
                self.hub.request(self.hub.provider('google-gemini'),'chat/completions',{})
        self.assertEqual(503,caught.exception.status)
        self.assertIn('temporarily unavailable or overloaded',caught.exception.message)
        self.assertNotIn('secret-key',caught.exception.message)

    def test_transport_identifies_app_without_changing_auth_or_payload(self):
        captured=[]
        class Upstream(BaseHTTPRequestHandler):
            def log_message(self,*args): pass
            def do_POST(self):
                captured.append((dict(self.headers),json.loads(self.rfile.read(int(self.headers['Content-Length'])))))
                self.send_response(200); self.end_headers()
                self.wfile.write(b'{"choices":[{"message":{"content":"OK"}}]}')
        service=ThreadingHTTPServer(('127.0.0.1',0),Upstream)
        worker=threading.Thread(target=service.serve_forever,daemon=True); worker.start()
        def close(): service.shutdown(); service.server_close(); worker.join()
        self.addCleanup(close)
        p=dict(self.hub.provider('openrouter'),base_url='http://127.0.0.1:%d/v1'%service.server_port)
        payload={'model':'synthetic-model','messages':[{'role':'user','content':'Synthetic test'}]}
        self.assertTrue(self.hub.request(p,'chat/completions',payload)['choices'])
        headers,body=captured[0]
        self.assertEqual(CLIENT_USER_AGENT,headers['User-Agent'])
        self.assertEqual('Bearer secret-cloud',headers['Authorization'])
        self.assertEqual(payload,body)

    def test_http_errors_distinguish_gateway_auth_permissions_and_quota(self):
        cases=[
            (403,{'Server':'cloudflare','Content-Type':'application/json'},
             {'type':'https://developers.cloudflare.com/error-1010/','detail':"blocked based on your browser's signature"},'client_signature_blocked'),
            (403,{'Server':'cloudflare','Content-Type':'text/html'},'<html>Blocked secret-cloud</html>','gateway_blocked'),
            (403,{'Server':'cloudflare','Content-Type':'application/json'},
             {'error':{'message':'Model permission denied secret-cloud'}},'access_denied'),
            (401,{}, {'error':{'message':'Invalid key secret-cloud'}},'authentication_failed'),
            (429,{}, {'message':'Rate limit exceeded','code':'1300'},'rate_or_quota_limit'),
            (404,{}, {'error':{'message':'Model retired'}},'resource_unavailable'),
        ]
        for status,headers,body,kind in cases:
            with self.subTest(kind=kind):
                raw=body.encode() if isinstance(body,str) else json.dumps(body).encode()
                error=HTTPError('https://example.invalid',status,'test',headers,BytesIO(raw))
                with patch.object(self.hub.opener,'open',side_effect=error):
                    with self.assertRaises(UpstreamError) as caught:
                        self.hub.request(self.hub.provider('openrouter'),'chat/completions',{})
                self.assertEqual(kind,caught.exception.kind)
                self.assertEqual(status,caught.exception.status)
                self.assertEqual(kind,self.hub.events[-1]['error_kind'])
                self.assertNotIn('secret-cloud',json.dumps(self.hub.events))
                self.assertNotIn('secret-cloud',caught.exception.message)

    def test_connection_probe_recovers_from_temporary_unavailability(self):
        with patch.object(self.hub,'transport',side_effect=[UpstreamError(503,'busy'),
                UpstreamError(503,'busy',3),{'choices':[{}]}]) as transport:
            with patch('llm_hub.time.sleep') as sleep:
                self.assertTrue(self.hub.test('google-gemini')['ok'])
        self.assertEqual(3,transport.call_count)
        self.assertEqual([((1,),{}),((3,),{})],sleep.call_args_list)

    def test_probe_retries_are_bounded_and_respect_long_cooldowns(self):
        for status,retry,count in ((503,0,3),(503,60,1),(401,0,1),(429,0,1)):
            with self.subTest(status=status,retry=retry):
                with patch.object(self.hub,'transport',side_effect=UpstreamError(status,'busy',retry)) as transport:
                    with patch('llm_hub.time.sleep'):
                        with self.assertRaises(UpstreamError): self.hub.test('google-gemini')
                self.assertEqual(count,transport.call_count)

    def test_http_auth_origin_and_openai_routes(self):
        self.hub.port=0
        service=server(self.hub); self.hub.port=service.server_port
        worker=threading.Thread(target=service.serve_forever,daemon=True); worker.start()
        def close(): service.shutdown(); service.server_close(); worker.join()
        self.addCleanup(close)
        opener=build_opener(ProxyHandler({})); base='http://127.0.0.1:%d'%self.hub.port
        def call(path,body=None,headers=None):
            values={'X-Hub-Token':self.hub.token}; values.update(headers or {})
            req=Request(base+path,json.dumps(body).encode() if body else None,values)
            return opener.open(req,timeout=3)
        for headers,status in (({'X-Hub-Token':'bad'},401),({'Origin':'https://evil.invalid'},403),({'Host':'evil.invalid'},403)):
            with self.assertRaises(HTTPError) as caught: call('/api/state',headers=headers)
            self.assertEqual(status,caught.exception.code)
            error=json.load(caught.exception)['error']
            self.assertEqual('hub_auth_required' if status==401 else 'hub_origin_required',error['code'])
        with call('/v1/chat/completions',{'model':'hub-chat','messages':[]}) as response:
            self.assertEqual('OK',json.load(response)['choices'][0]['message']['content'])
        with call('/') as response: self.assertIn(b'Connection Hub',response.read())
        with call('/v1/models') as response: self.assertEqual('hub-chat',json.load(response)['data'][0]['id'])
        self.hub.transport=lambda *a: (_ for _ in ()).throw(UpstreamError(403,'Gateway blocked',kind='gateway_blocked'))
        with self.assertRaises(HTTPError) as caught: call('/api/test',{'id':'openrouter'})
        error=json.load(caught.exception)['error']
        self.assertEqual('provider',error['source'])
        self.assertEqual('gateway_blocked',error['kind'])
        self.assertEqual(403,error['code'])

if __name__=='__main__': unittest.main()

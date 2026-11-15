from __future__ import unicode_literals
import os
import sys
import unittest
import json
import uuid
import io
import copy
try:
    from urllib.error import HTTPError
except ImportError:
    from urllib2 import HTTPError
sys.path.insert(0,os.path.dirname(os.path.abspath(__file__)))
from test_burpai_website_integration import extension_namespace,load_function
from BurpAI_v4_Semantic import embedding_config

class ProviderFallbackTests(unittest.TestCase):
    def setUp(self):
        self.ns=extension_namespace()
        self.calls=[]
        method=load_function('chat',self.ns,'LLMClient')
        self.client=type('Client',(object,),{'chat':method})()
        self.config={'enabled':True,'model':'local-chat','base_url':'http://127.0.0.1:11434/v1',
                     'api_key':'local-secret','timeout':600}
        self.client.local_fallback=lambda: self.config
        self.client._cancelled_result=lambda: {'ok':False,'cancelled':True}
        self.notices=[]
        self.client.on_local_fallback=self.notices.append
        self.cloud={'ok':False,'status':429,'error':'limit'}
        self.local={'ok':True,'content':'local answer','status':200}
        def call(**kwargs):
            self.calls.append(kwargs)
            return self.cloud if kwargs['provider']=='openrouter' else self.local
        self.client._chat_provider=call
        self.messages=[{'role':'user','content':'Inspect saved source.'}]
        self.tools=[{'type':'function','function':{'name':'read_source'}}]

    def chat(self,**kwargs):
        return self.client.chat('cloud-secret','cloud-model',self.messages,tools=self.tools,**kwargs)

    def test_rate_or_credit_limit_uses_only_local_credentials_preserving_context(self):
        for status in (429,402):
            self.client._local_fallback_active=False; self.calls[:]=[]
            self.cloud['status']=status
            result=self.chat()
            self.assertEqual('local',result['effective_provider'])
            local=self.calls[-1]
            self.assertEqual('local-secret',local['api_key'])
            self.assertEqual(self.messages,local['messages'])
            self.assertEqual(self.tools,local['tools'])
            self.assertEqual(600,local['request_timeout'])
            self.assertEqual('local-chat',local['model'])
            self.assertEqual(status,result['fallback_status'])

    def test_following_turns_stay_local_until_new_run_reset(self):
        self.chat(); self.chat()
        self.assertEqual(['openrouter','local','local'],[c['provider'] for c in self.calls])
        self.assertEqual(['local-chat'],self.notices)
        self.client._local_fallback_active=False
        self.chat()
        self.assertEqual('openrouter',self.calls[-2]['provider'])

    def test_auth_network_timeout_and_context_failures_do_not_trigger_failover(self):
        for result in ({'ok':False,'status':401},{'ok':False,'status':500},
                       {'ok':False,'status':0,'timed_out':True},
                       {'ok':False,'status':400},{'ok':False,'status':429,'cancelled':True}):
            self.cloud=result; self.calls[:]=[]
            self.assertEqual(result,self.chat())
            self.assertEqual(1,len(self.calls))

    def test_cancel_between_limit_and_local_request_prevents_new_request(self):
        def call(**kwargs):
            self.calls.append(kwargs)
            return self.cloud
        self.client._chat_provider=call
        result=self.chat(cancel_check=lambda:bool(self.calls))
        self.assertTrue(result['cancelled'])
        self.assertEqual(1,len(self.calls))

    def test_disabled_and_explicit_local_mode_never_cross_providers(self):
        self.config['enabled']=False
        self.chat()
        self.assertEqual(1,len(self.calls))
        self.calls[:]=[]
        self.chat(provider='local')
        self.assertEqual(['local'],[c['provider'] for c in self.calls])

    def test_local_failure_is_reported_without_returning_to_cloud(self):
        self.local={'ok':False,'status':404,'error':'model not found'}
        result=self.chat()
        self.assertIn('local fallback failed',result['error'])
        self.assertEqual(['openrouter','local'],[c['provider'] for c in self.calls])

    def test_cloud_limit_returns_before_cloud_backoff_when_fallback_enabled(self):
        load_function('_bounded_int',self.ns); load_function('_bounded_float',self.ns)
        method=load_function('_chat_provider',self.ns,'LLMClient')
        client=type('Provider',(object,),{'_chat_provider':method})()
        client.url='https://openrouter.ai/api/v1/chat/completions'
        client._no_native_tools=set()
        client._do_call=lambda *a,**kw: {'ok':False,'status':429}
        client._log=lambda *a: None
        def forbidden(*a): raise AssertionError('Cloud backoff before local fallback')
        client._wait_delay=forbidden
        result=client._chat_provider('secret','cloud',[],stop_on_limit=True)
        self.assertEqual(429,result['status'])

    def test_provider_prompt_block_is_an_error_with_its_explanation(self):
        self.ns.update(json=json, uuid=uuid, _json_text=json.dumps)
        methods = dict((name, load_function(name, self.ns, 'LLMClient'))
                       for name in ('_parse_completion', '_content_to_text'))
        client = type('Parser', (object,), methods)()
        for response in ({'promptFeedback': {'blockReason': 'OTHER', 'blockReasonMessage': 'Prompt rejected'}},
                         {'response': {'promptFeedback': {'blockReason': 'OTHER', 'blockReasonMessage': 'Prompt rejected'}}}):
            result = client._parse_completion(response, json.dumps(response))
            self.assertFalse(result['ok'])
            self.assertEqual(403, result['status'])
            self.assertIn('Prompt rejected', result['error'])
        result = client._parse_completion({'response': {'metadata': {}}}, '')
        self.assertFalse(result['ok'])
        result = client._parse_completion({'response': 'Ollama answer'}, '')
        self.assertEqual('Ollama answer', result['content'])

    def test_http_provider_rejection_preserves_detail_without_auth_or_retry(self):
        self.ns.update(json=json, HTTPError=HTTPError,
                       Request=lambda url: object(),
                       _json_bytes=lambda value: json.dumps(value).encode('utf-8'),
                       _extract_error_detail=lambda result: result.get('error', ''))
        load_function('_bounded_int', self.ns)
        methods = dict((name, load_function(name, self.ns, 'LLMClient'))
                       for name in ('_do_call', 'classify_error', '_is_transient'))
        client = type('Transport', (object,), methods)()
        client._add_headers = lambda *args: None
        client._log = lambda *args: None
        body = json.dumps({'error': {'code': 'provider_prompt_blocked',
                                    'message': 'Provider rejected this request: OTHER'}}).encode('utf-8')
        def reject(*args, **kwargs):
            raise HTTPError('http://localhost/test', 403, 'Forbidden', {}, io.BytesIO(body))
        client._read_all = reject
        result = client._do_call('test-key', {'model': 'hub-chat'},
                                 provider='hub', endpoint='http://localhost/test')
        self.assertEqual(403, result['status'])
        self.assertIn('Provider rejected this request: OTHER', result['error'])
        self.assertEqual('provider_rejection', client.classify_error(result))
        self.assertFalse(client._is_transient(result))
        self.assertEqual('authentication', client.classify_error({'status': 403}))

class EmbeddingSettingsTests(unittest.TestCase):
    def test_openrouter_key_is_reused_only_for_the_official_endpoint(self):
        ns=extension_namespace()
        method=load_function('get_embedding_config',ns,'SettingsStore')
        store=type('Store',(object,),{'get_embedding_config':method})()
        values={}
        store._g=lambda key,default: values.get(key,default)
        store.get_api_key=lambda:'cloud-secret'
        for url in ('https://openrouter.ai','https://openrouter.ai/api/v1','https://openrouter.ai/api/v1/embeddings'):
            values['embedding_base_url']=url
            self.assertEqual('cloud-secret',store.get_embedding_config()['api_key'])
        for url in ('http://127.0.0.1:11434','https://openrouter.ai.evil.test/api/v1','https://custom.test/v1'):
            values['embedding_base_url']=url
            self.assertEqual('',store.get_embedding_config()['api_key'])

    def test_openrouter_endpoint_model_and_cache_identity(self):
        remote=embedding_config({'base_url':'https://openrouter.ai','model':'nvidia/nemotron-3.5-embed-8b:free'})
        self.assertEqual('https://openrouter.ai/api/v1/embeddings',remote['endpoint'])
        self.assertEqual('openai',remote['protocol'])
        local=embedding_config({'base_url':'http://127.0.0.1:11434','model':'embeddinggemma'})
        self.assertNotEqual(remote['identity'],local['identity'])


class CloudContextTests(unittest.TestCase):
    def test_captured_credentials_are_masked_in_outbound_copies(self):
        redact = load_function('_v3_redact_cloud_messages', extension_namespace())
        captured = {'req_headers': ['GET /admin HTTP/1.1',
                                    'Authorization: Bearer captured-token',
                                    'Cookie: session=captured-session'],
                    'resp_headers': ['Set-Cookie: session=renewed-session; HttpOnly',
                                     'Content-Type: application/json']}
        arguments = {'headers': {'Proxy-Authorization': 'Basic proxy-token'}}
        messages = [
            {'role': 'assistant', 'tool_calls': [{'id': 'call-1',
                'function': {'name': 'get_http_entry', 'arguments': json.dumps(arguments)}}]},
            {'role': 'tool', 'tool_call_id': 'call-1', 'content': json.dumps(captured)},
        ]
        originals = copy.deepcopy(messages)
        outbound = redact(messages)
        masked = json.loads(outbound[1]['content'])
        self.assertEqual(['GET /admin HTTP/1.1', 'Authorization: [REDACTED]',
                          'Cookie: [REDACTED]'], masked['req_headers'])
        self.assertEqual(['Set-Cookie: [REDACTED]', 'Content-Type: application/json'],
                         masked['resp_headers'])
        sent_call = outbound[0]['tool_calls'][0]
        self.assertEqual(outbound[1]['tool_call_id'], sent_call['id'])
        self.assertEqual('[REDACTED]', json.loads(sent_call['function']['arguments'])
                         ['headers']['Proxy-Authorization'])
        self.assertEqual(originals, messages)


if __name__=='__main__': unittest.main()

"""Synthetic-only checks; never uploads captured traffic or saved website code."""
import os
import sys
import types
import tempfile
import shutil
import json
sys.path.insert(0,os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
burp=types.ModuleType('burp')
burp.IBurpExtender=type('IBurpExtender',(object,),{})
burp.ITab=type('ITab',(object,),{})
burp.IExtensionStateListener=type('IExtensionStateListener',(object,),{})
sys.modules['burp']=burp
import BurpAI_v4_Extension as extension
from BurpAI_v4_Semantic import SemanticCodeIndex,embedding_config,EmbeddingError
class Callbacks(object):
    def getHelpers(self): return object()
store=extension.SettingsStore()
client=extension.LLMClient(Callbacks())
original=client._do_call
def limited_cloud(api_key,payload,provider='openrouter',*args,**kwargs):
    if provider=='openrouter': return {'ok':False,'status':429,'error':'synthetic rate limit'}
    return original(api_key,payload,provider,*args,**kwargs)
client._do_call=limited_cloud
client.local_fallback=lambda:{'enabled':True,'model':store.get_local_model(),
    'base_url':store.get_local_base_url(),'api_key':store.get_local_api_key(),'timeout':120}
result=client.chat('synthetic-cloud-key','synthetic-cloud-model',
    [{'role':'user','content':'Reply with OK.'}],max_tokens=512,max_retries=1)
print(json.dumps({'local_chat_ok':bool(result.get('ok') and result.get('content')),
    'effective_provider':result.get('effective_provider'),'fallback_status':result.get('fallback_status')}))
assert result.get('ok') and result.get('content') and result.get('effective_provider')=='local'
folder=tempfile.mkdtemp(prefix='embedding-live-')
try:
    config=embedding_config({'base_url':'https://openrouter.ai/api/v1',
        'model':'nvidia/nemotron-3.5-embed-8b:free','api_key':store.get_api_key()})
    if config['api_key']:
        try:
            vectors=SemanticCodeIndex(folder)._embed(['Synthetic semantic search setup check.'],config)
            print(json.dumps({'openrouter_embedding_ok':True,'dimensions':len(vectors[0])}))
        except EmbeddingError as exc:
            print(json.dumps({'openrouter_embedding_ok':False,'error':str(exc)}))
    else: print(json.dumps({'openrouter_embedding_ok':False,'error':'missing_openrouter_key'}))
finally: os.rmdir(folder)

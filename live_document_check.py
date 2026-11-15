# -*- coding: utf-8 -*-
"""Opt-in live check with synthetic text and an isolated document library only."""
import json
import os
import sys
import types

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
fake_burp = types.ModuleType('burp')
fake_burp.IBurpExtender = type('IBurpExtender', (object,), {})
fake_burp.ITab = type('ITab', (object,), {})
fake_burp.IExtensionStateListener = type('IExtensionStateListener', (object,), {})
sys.modules['burp'] = fake_burp
import BurpAI_v4_Extension as extension

class Callbacks(object):
    def getHelpers(self): return object()

with open(os.path.join(ROOT, 'nine_router', '.state', 'burp-connection.json'), 'rb') as handle:
    connection = json.loads(handle.read().decode('utf-8'))
agent = extension.BurpExtender()
agent.ui = None
agent.documents = extension.DocumentLibrary(os.path.join(ROOT, 'test-tmp', 'live-document-check'))
agent.tool_registry = extension.ToolRegistry()
agent._register_tools()
tools = [schema for schema in agent.tool_registry.get_schemas()
         if schema['function']['name'] in ('document_save', 'documents_list', 'document_read')]
client = extension.LLMClient(Callbacks())
messages = [{'role':'system','content':'You are a helpful writing assistant. Use the provided tools to save requested documents.' + extension.DOCUMENT_PROMPT},
    {'role':'user','content':'Save two short example documents about planning a picnic: one Markdown note with headings and a checklist, and one visual mind map with three branches and two children per branch. Use made-up general examples, no personal data. Save both now; do not open them.'}]
saved = []
trace = []
for turn in range(3):
    response = client.chat(api_key=connection['key'], model=connection['model'], provider='hub',
        base_url='http://127.0.0.1:20128/v1', messages=messages, tools=tools,
        max_retries=1, request_timeout=50, max_tokens=1800, temperature=0.2)
    if not response.get('ok'):
        raise RuntimeError('Live model check failed with status ' + str(response.get('status')))
    calls = response.get('tool_calls') or []
    trace.append({'turn':turn, 'content':response.get('content'), 'finish_reason':response.get('finish_reason'),
                  'calls':calls})
    if not calls: break
    messages.append({'role':'assistant','content':response.get('content') or '', 'tool_calls':calls})
    for call in calls:
        name = call['function']['name']
        assert name in ('document_save', 'documents_list', 'document_read')
        args = json.loads(call['function']['arguments'])
        result = agent.tool_registry.execute(name, args)
        trace.append({'tool':name,'result':result})
        messages.append({'role':'tool','tool_call_id':call['id'],'content':json.dumps(result)})
        if name == 'document_save' and result.get('ok') and result['result'].get('ok'):
            saved.append(result['result'])
    if set(row['kind'] for row in saved) == set(('note','mind_map')): break
if set(row['kind'] for row in saved) != set(('note','mind_map')):
    with open(os.path.join(ROOT,'test-tmp','live-document-check-trace.json'),'wb') as handle:
        handle.write(json.dumps(trace,ensure_ascii=True,indent=2).encode('ascii'))
    raise AssertionError('Model did not save both requested document types. See the synthetic test trace.')
assert all(os.path.isfile(row['markdown_path']) and os.path.isfile(row['viewer_path']) for row in saved)
print(json.dumps({'ok':True,'model':connection['model'],'saved':[{'title':row['title'],'kind':row['kind']} for row in saved]}))

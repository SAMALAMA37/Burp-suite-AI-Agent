# -*- coding: utf-8 -*-
"""Exercise real orchestration with deterministic models and no target traffic."""
from __future__ import unicode_literals
import copy
import hashlib
import json
import os
import sys
import threading
import time
import traceback
import unittest
import uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_burpai_website_integration import extension_namespace, load_function
from BurpAI_v4_Investigation import Investigation, plan_metadata, compare_http


class Box(object):
    def __init__(self, **values): self.__dict__.update(values)


class Field(object):
    def __init__(self, text=''): self.text = text
    def getText(self): return self.text
    def setText(self, text): self.text = text


class Store(object):
    values = {'active_api_key':'', 'active_model':'fixture', 'provider':'local',
        'active_base_url':'http://localhost', 'temperature':0, 'max_tokens':1000,
        'use_native_tools':True, 'max_iters':2, 'auto_mode':True, 'system_prompt':'Test policy',
        'auto_send_requests':False, 'context_window':32000, 'working_context':16000,
        'unattended_choices':False, 'persist_conversation':True}
    def __getattr__(self, name):
        if name == 'get_request_timeout': return lambda provider: 30
        if name.startswith('get_'): return lambda: self.values[name[4:]]
        raise AttributeError(name)


def call(name, args=None):
    return {'id':'call_' + uuid.uuid4().hex, 'type':'function',
            'function':{'name':name,'arguments':json.dumps(args or {})}}


def response(*calls, **kwargs):
    return dict(ok=True, content=kwargs.get('content',''), tool_calls=list(calls))


class AutonomyTests(unittest.TestCase):
    def setUp(self):
        ns = extension_namespace()
        ns.update(json=json, hashlib=hashlib, uuid=uuid, threading=threading,
                  time=time, traceback=traceback, _json_text=json.dumps, DOCUMENT_PROMPT='',
                  _full_js_request_target=lambda text:None)
        ns.update(plan_metadata=plan_metadata, compare_http=compare_http)
        ns['_bounded_int'] = load_function('_bounded_int', ns)
        names = ('_run_agent_loop','_agent_run_summary','_agent_tool_activity',
            '_agent_tool_outcome','_call_signature','_has_agent_guidance','_drain_agent_guidance',
            '_send_chat','_stop_agent','_tool_update_test_plan','_ask_user_choice',
            '_tool_ask_user_decision','_parse_prose_response','_investigation_event',
            '_refresh_investigation','_wait_if_paused','_toggle_agent_pause','_summarize_agent',
            '_agent_command','_tool_compare_evidence','_tool_report_progress','_investigation_next')
        self.ns = ns
        self.agent = a = type('Agent',(object,),dict((name,load_function(name,ns,'BurpExtender'))
                                                   for name in names))()
        conv_names = ('__init__','_append','add_user','add_assistant','add_tool_result',
                      'update_system_prompt','clear','get_messages')
        conv_methods = dict((name,load_function(name,ns,'ConversationState')) for name in conv_names)
        conv_methods['_maybe_compact'] = lambda self:None
        a.conversation = type('Conversation',(object,),conv_methods)()
        a.conversation.add_user('Investigate the captured traffic.')
        a.store = Store()
        a.store.values = dict(Store.values)
        a.agent_lock = threading.Lock()
        a.agent_running = False
        a._pending_agent_messages = []
        a.stop_agent_flag = a.kill_switch = False
        self.chat = []
        self.statuses = []
        self.executed = []
        self.requests = []
        self.responses = []
        self.hook = None
        a._append_chat = lambda role,text:self.chat.append((role,text))
        a._safe_ui = lambda fn:fn()
        a._log_debug = lambda text:None
        a._record_tool_display = lambda *args:None
        a._website_agent_prompt = lambda:''
        a._with_js_coverage = lambda value:value
        def extract(value):
            try: return json.loads(value)
            except ValueError: return None
        a.json = Box(extract_json_any=extract)
        a.ui = Box(input_field=Field(), modelio_area=Field(),
            set_status=lambda state,**kwargs:self.statuses.append(state),
            hide_decision_prompt=lambda:None, show_decision_prompt=lambda *args:None)
        def remember(text): a.ledger.data['goals'].append(text)
        a.ledger = Box(data={'mission_id':'m1','goals':[]}, lock=threading.RLock(),
            remember_user=remember, observe=lambda *args:None, _persist=lambda:None)
        self.records = []
        def capture(name,args,payload):
            record = {'id':'EV%07d' % (len(self.records)+1),'mission_id':'m1',
                      'tool':name,'summary':name}
            self.records.append(record)
            return record
        a.evidence = Box(capture=capture, tool_projection=lambda record,payload:payload,
                         lock=threading.RLock(), index={'items':self.records})
        a.context_engine = Box(prepare=lambda prompt,conv,*args,**kwargs:copy.deepcopy(conv.get_messages()),
            last_report={},calibrate=lambda *args:None)
        def chat(**kwargs):
            self.requests.append(kwargs)
            result = self.responses.pop(0)
            return result() if callable(result) else result
        a.client = Box(chat=chat,classify_error=lambda result:'error')
        def execute(name,args):
            self.executed.append(name)
            if self.hook: return self.hook(name,args)
            return {'ok':True,'result':{'ok':True,'value':'fixture'}}
        a.tool_registry = Box(execute=execute, get_schemas=lambda:[{'fixture':True}],
                              describe_for_prompt=lambda:'tools')

    def assert_paired(self):
        calls = [tc['id'] for msg in self.agent.conversation.messages
                 for tc in msg.get('tool_calls',[])]
        replies = [msg['tool_call_id'] for msg in self.agent.conversation.messages if msg['role']=='tool']
        self.assertEqual(calls,replies)

    def test_budget_adds_one_tool_free_evidence_summary(self):
        self.responses = [response(call('read',{'page':1})),response(call('read',{'page':2})),
                          response(content='Inconclusive; no live check was run.')]
        self.agent._run_agent_loop()
        self.assertEqual(['read','read'],self.executed)
        self.assertEqual(3,len(self.requests))
        self.assertIsNone(self.requests[-1]['tools'])
        self.assertIn('Summarize existing evidence', self.requests[-1]['messages'][0]['content'])
        self.assert_paired()

    def test_single_step_mode_still_explains_result(self):
        self.agent.store.values['auto_mode'] = False
        self.responses = [response(call('read')),response(content='Read completed; needs validation.')]
        self.agent._run_agent_loop()
        self.assertEqual(2,len(self.requests))
        self.assertIsNone(self.requests[-1]['tools'])

    def test_summary_cannot_execute_native_or_prose_tool_calls(self):
        for native in (True,False):
            self.setUp()
            self.agent.store.values.update(max_iters=1,use_native_tools=native)
            forbidden = call('send_request',{'url':'https://example.test/'})
            summary = response(forbidden) if native else response(content=json.dumps({
                'tool_calls':[{'name':'send_request','arguments':{'url':'https://example.test/'}}]}))
            self.responses = [response(call('read')),summary]
            self.agent._run_agent_loop()
            self.assertEqual(['read'],self.executed)
            self.assertTrue(any('budget ended' in text for role,text in self.chat))

    def test_final_answer_stops_remaining_batch_with_paired_replies(self):
        self.hook = lambda name,args:{'ok':True,'result':{'summary':'Findings with gaps.'}}
        self.responses = [response(call('final_answer'),call('send_request'))]
        self.agent._run_agent_loop()
        self.assertEqual(['final_answer'],self.executed)
        self.assert_paired()

    def test_request_dedup_ignores_rationale_header_case_and_tool_alias(self):
        a = self.agent
        first = {'method':'get','url':'https://example.test/','headers':{'Accept':'text/plain'},'rationale':'one'}
        second = dict(first,method='GET',headers={'accept':'text/plain'},rationale='two',confidence=.9)
        self.assertEqual(a._call_signature('propose_request',first),a._call_signature('send_request',second))
        self.responses = [response(call('propose_request',first),call('send_request',second)),response(content='Done')]
        a._run_agent_loop()
        self.assertEqual(['propose_request'],self.executed)
        self.assert_paired()

    def test_nested_tool_failures_trigger_early_summary(self):
        self.agent.store.values['max_iters'] = 10
        self.hook = lambda *args:{'ok':True,'result':{'ok':False,'error':'fixture_error'}}
        self.responses = [response(call('read',{'page':i})) for i in range(3)] + [response(content='Blocked.')]
        self.agent._run_agent_loop()
        self.assertEqual(4,len(self.requests))
        self.assertIsNone(self.requests[-1]['tools'])
        self.assertEqual(3,self.agent._agent_stats['errors'])

    def test_guidance_during_first_tool_skips_rest_and_preserves_protocol(self):
        def execute(*args):
            self.agent._pending_agent_messages.append('Focus on login instead.')
            return {'ok':True,'result':{'ok':True}}
        self.hook = execute
        self.responses = [response(call('read'),call('send_request'))]
        self.agent._run_agent_loop()
        self.assertEqual(['read'],self.executed)
        self.assert_paired()
        self.agent._drain_agent_guidance()
        self.assertEqual('Focus on login instead.',self.agent.conversation.messages[-1]['content'])

    def test_stop_mid_batch_skips_remaining_actions(self):
        def execute(*args):
            self.agent.stop_agent_flag = True
            return {'ok':True,'result':{'ok':True}}
        self.hook = execute
        self.responses = [response(call('read'),call('send_request'))]
        self.agent._run_agent_loop()
        self.assertEqual(['read'],self.executed)
        self.assert_paired()
        self.assertTrue(any('incomplete' in text for role,text in self.chat))

    def test_send_while_running_queues_in_order_without_mutating_history(self):
        self.agent.agent_running = True
        before = copy.deepcopy(self.agent.conversation.messages)
        for text in ('First correction','Second correction'):
            self.agent.ui.input_field.setText(text)
            self.agent._send_chat()
        self.assertEqual(before,self.agent.conversation.messages)
        self.assertEqual(['First correction','Second correction'],self.agent._pending_agent_messages)
        self.agent._drain_agent_guidance()
        self.assertEqual(['First correction','Second correction'],self.agent.ledger.data['goals'])

    def test_worker_processes_followup_arriving_during_completion(self):
        def first_response():
            self.agent.ui.input_field.setText('Now check the baseline.')
            self.agent._send_chat()
            return response(content='First response.')
        self.responses = [first_response,response(content='Baseline reviewed.')]
        self.agent.ui.input_field.setText('Start review.')
        worker = self.agent._send_chat()
        worker.join(5)
        self.assertFalse(worker.is_alive())
        self.assertFalse(self.agent.agent_running)
        self.assertEqual(2,len(self.requests))
        self.assertEqual('Now check the baseline.', self.requests[-1]['messages'][-1]['content'])

    def test_stop_preserves_accepted_unprocessed_followup(self):
        def first_response():
            self.agent.ui.input_field.setText('Remember this followup.')
            self.agent._send_chat()
            self.agent._stop_agent()
            return response(content='Old response.')
        self.responses = [first_response]
        self.agent.ui.input_field.setText('Start review.')
        worker = self.agent._send_chat()
        worker.join(5)
        self.assertFalse(worker.is_alive())
        self.assertEqual('Remember this followup.',self.agent.conversation.messages[-1]['content'])
        self.assertEqual('stopped',self.statuses[-1])

    def test_stopping_preserves_unsent_draft(self):
        self.agent.agent_running = self.agent.stop_agent_flag = True
        self.agent.ui.input_field.setText('Keep draft')
        self.agent._send_chat()
        self.assertEqual('Keep draft',self.agent.ui.input_field.getText())
        self.assertEqual([],self.agent._pending_agent_messages)

    def test_empty_model_output_returns_failure(self):
        self.responses = [response()]
        self.assertIs(False,self.agent._run_agent_loop())
        self.assertEqual('error',self.statuses[-1])

    def test_queue_outcome_does_not_claim_request_was_sent(self):
        self.agent._agent_stats = {'tools':0,'errors':0}
        self.agent._agent_tool_outcome('propose_request',{'ok':True,'result':{'queued':True}},'EV0000001')
        self.assertIn('has not been sent',self.chat[-1][1])
        self.assertIn('EV0000001',self.chat[-1][1])

    def test_unanswered_decision_does_not_choose_first_option(self):
        ticks = iter((0,301))
        self.ns['time'] = Box(time=lambda:next(ticks))
        choice = self.agent._ask_user_choice('Choose','', [{'id':'first'}],default_id='first')
        self.assertIsNone(choice)
        self.assertTrue(self.agent.stop_agent_flag)
        self.assertIn('no option was selected',self.chat[-1][1])

    def test_guidance_dismisses_decision_without_selecting(self):
        self.agent._pending_agent_messages.append('Use a different approach.')
        choice = self.agent._ask_user_choice('Choose','', [{'id':'first'}],default_id='first')
        self.assertIsNone(choice)
        self.assertFalse(self.agent.stop_agent_flag)

    def test_test_plan_requires_real_current_mission_evidence_for_supported(self):
        a = self.agent
        result = a._tool_update_test_plan({'title':'Access check','hypothesis':'A role check may be missing.'})
        test_id = result['test']['id']
        update = {'id':test_id,'status':'supported','baseline':'Allowed role',
                  'check':'Different role','result':'Observed different access','evidence_ids':['bad','bad2']}
        self.assertFalse(a._tool_update_test_plan(update)['ok'])
        self.records.extend([{'id':'E1','mission_id':'m1','tool':'get_http_entry'},
                             {'id':'E2','mission_id':'m2','tool':'get_http_entry'}])
        update['evidence_ids'] = ['E1','E2']
        self.assertFalse(a._tool_update_test_plan(update)['ok'])
        self.records[-1]['mission_id'] = 'm1'
        self.assertTrue(a._tool_update_test_plan(update)['ok'])
        self.assertEqual('model_authored',a._tool_update_test_plan({})['tests'][0]['assessment'])
        self.assertEqual(1,len(a.ledger.data['test_plan']))

    def test_test_plan_rejects_duplicates_as_two_evidence_records(self):
        self.records.append({'id':'E1','mission_id':'m1','tool':'get_http_entry'})
        result = self.agent._tool_update_test_plan({'title':'Test','hypothesis':'Hypothesis',
            'status':'supported','baseline':'base','check':'check','result':'result','evidence_ids':['E1','E1']})
        self.assertFalse(result['ok'])
        self.assertNotIn('test_plan',self.agent.ledger.data)

    def test_test_plan_rejects_self_referential_assessment_as_evidence(self):
        self.records.extend([{'id':'E1','mission_id':'m1','tool':'update_test_plan'},
                             {'id':'E2','mission_id':'m1','tool':'final_answer'}])
        result = self.agent._tool_update_test_plan({'title':'Test','hypothesis':'Hypothesis',
            'status':'supported','baseline':'base','check':'check','result':'result','evidence_ids':['E1','E2']})
        self.assertFalse(result['ok'])

    def test_test_plan_rejects_outcome_without_explanation_and_unknown_ids(self):
        for args in ({'id':'unknown','title':'Test','hypothesis':'Hypothesis'},
                     {'title':'Test','hypothesis':'Hypothesis','status':'blocked'}):
            self.assertFalse(self.agent._tool_update_test_plan(args)['ok'])


if __name__ == '__main__': unittest.main()

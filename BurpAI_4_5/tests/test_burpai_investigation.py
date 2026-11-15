# -*- coding: utf-8 -*-
from __future__ import unicode_literals
import copy
import hashlib
import json
import os
import sys
import threading
import time
import unittest
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import test_burpai_autonomy as autonomy
from test_burpai_autonomy import Box, Field, call, response
from BurpAI_v4_Investigation import Investigation, compare_http, plan_metadata, plan_snapshot
from test_burpai_website_integration import extension_namespace, load_function, FakeHelpers, response as raw_response
from test_burpai_workbench import Item, Helpers, Callbacks


def http(body='{"allowed":false}', status=200, **kwargs):
    value = {'url':'https://example.test/resource', 'method':'GET', 'status':status,
             'body':body, 'body_complete':True, 'headers':['Content-Type: application/json']}
    value.update(kwargs)
    return value


class ComparisonTests(unittest.TestCase):
    def test_json_changes_are_bounded_paths_without_response_values(self):
        result = compare_http(http(),http('{"allowed":true,"secret":"private-token"}', 403))
        self.assertEqual(['/allowed','/secret'],result['changed_json_paths'])
        self.assertTrue(result['status_changed'])
        self.assertNotIn('private-token',json.dumps(result))
        self.assertEqual('observation_only',result['assessment'])

    def test_json_order_does_not_count_as_semantic_change(self):
        result = compare_http(http('{"a":1,"b":2}'),http('{"b":2,"a":1}'))
        self.assertFalse(result['body_equal'])
        self.assertTrue(result['json_equal'])

    def test_boolean_and_integer_are_not_equal_json_values(self):
        result = compare_http(http('{"a":true}'),http('{"a":1}'))
        self.assertEqual(['/a'], result['changed_json_paths'])

    def test_incomplete_queued_failed_and_missing_status_are_rejected(self):
        for value in (http(body_complete=False), http(queued=True), http(ok=False), http(status=0)):
            with self.assertRaises(ValueError): compare_http(http(),value)

    def test_baseline_repeat_flags_drift_and_rejects_wrong_target(self):
        self.assertEqual('unstable_observed',compare_http(http(),http(),http('{"allowed":true}'))['baseline_stability'])
        with self.assertRaises(ValueError): compare_http(http(),http(),http(url='https://other.test/'))
        with self.assertRaises(ValueError):
            compare_http(http(request_sha256='a'),http(),http(request_sha256='different-role'))

    def test_sensitive_header_values_not_exposed_and_security_headers_cannot_be_hidden(self):
        result = compare_http(http(headers=['Date: a','Set-Cookie: token=a']),
                              http(headers=['Date: b','Set-Cookie: token=b']))
        self.assertEqual(['set-cookie'], result['changed_headers'])
        self.assertNotIn('token=',json.dumps(result))
        with self.assertRaises(ValueError): compare_http(http(),http(),ignore_headers=['set-cookie'])

    def test_diff_is_bounded_for_large_json_arrays(self):
        result = compare_http(http('[]'),http(json.dumps(list(range(1000)))))
        self.assertEqual(60,len(result['changed_json_paths']))
        self.assertTrue(result['json_paths_truncated'])

    def test_non_json_and_identical_responses_remain_observations(self):
        result = compare_http(http('hello'),http('hello'))
        self.assertFalse(result['json_compared'])
        self.assertTrue(result['body_equal'])
        self.assertEqual('not_checked',result['baseline_stability'])


class PlanningTests(unittest.TestCase):
    def row(self, ref, **kwargs):
        row = {'id':ref,'title':ref,'status':'planned','priority':3,'depends_on':[]}
        row.update(kwargs); return row

    def test_priority_dependency_and_resumption_order(self):
        rows = [self.row('A',priority=2),self.row('B',priority=1,depends_on=['A']),
                self.row('C',priority=2,status='testing'),self.row('D',priority=1,status='blocked')]
        result = plan_snapshot(rows)
        self.assertEqual(['C','A'],[r['id'] for r in result['ready']])
        self.assertEqual(['A'],result['waiting'][0]['waiting_for'])
        rows[0]['status']='not_reproduced'
        self.assertEqual('B',plan_snapshot(rows)['next_test']['id'])

    def test_cycles_missing_and_self_dependencies_rejected_without_mutation(self):
        rows = [self.row('A'), self.row('B',depends_on=['A'])]
        before = copy.deepcopy(rows)
        for dep in ('B','A','unknown'):
            with self.assertRaises(ValueError): plan_metadata(rows[0],{'depends_on':[dep]},rows)
        self.assertEqual(before,rows)

    def test_coverage_is_per_planned_target_and_category(self):
        rows = [self.row('A',status='supported',target='one',category='auth'),
                self.row('B',status='inconclusive',target='one',category='auth')]
        result = plan_snapshot(rows)
        self.assertEqual(1,result['coverage'][0]['resolved'])
        self.assertEqual(2,result['coverage'][0]['total'])

    def test_request_budget_and_pause_are_atomic(self):
        ledger = Box(lock=threading.RLock(),data={},_persist=lambda:None)
        investigation = Investigation(ledger)
        investigation.start(2)
        investigation.state('paused')
        self.assertEqual('investigation_paused',investigation.reserve_request()['error'])
        investigation.state('running')
        results = []
        threads = [threading.Thread(target=lambda:results.append(investigation.reserve_request())) for i in range(8)]
        for worker in threads: worker.start()
        for worker in threads: worker.join(2)
        self.assertEqual(2,sum(1 for value in results if value['ok']))
        investigation.state('finished')
        self.assertTrue(investigation.reserve_request()['ok'])

    def test_reload_marks_run_interrupted_without_starting_requests(self):
        ledger = Box(lock=threading.RLock(),data={'investigation_run':{'state':'running'}},_persist=lambda:None)
        investigation = Investigation(ledger)
        self.assertFalse(investigation.active)
        self.assertEqual('interrupted',investigation.snapshot()['run']['state'])


class HttpIntegrationTests(unittest.TestCase):
    def setUp(self):
        ns = extension_namespace()
        ns['hashlib'] = hashlib
        methods = dict((name,load_function(name,ns,'BurpExtender')) for name in
                       ('_tool_capture_http_evidence','_dispatch_request'))
        self.agent = a = type('HttpAgent',(object,),methods)()
        self.item = Item('https://example.test/resource',status=403)
        class AllHelpers(Helpers,FakeHelpers): pass
        a.helpers = AllHelpers()
        a.callbacks = Callbacks([self.item])
        a._v3_read_scope = lambda url:{'ok':url.startswith('https://example.test/')}
        a._safe_ui = lambda fn:None
        a._refresh_investigation = lambda:None
        a.kill_switch = a.stop_agent_flag = False
        a.store = Box(get_auto_send_requests=lambda:True,get_rpm_limit=lambda:100)
        a.policy = Box(check=lambda *args,**kwargs:{'ok':True})
        a.send_times = []
        a.investigation = Investigation(Box(lock=threading.RLock(),data={},_persist=lambda:None))

    def capture(self):
        return self.agent._tool_capture_http_evidence({'index':0,'expected_url':self.item.url,
            'expected_request_sha256':hashlib.sha256(self.item.raw).hexdigest()})

    def test_complete_non_200_capture_does_not_send_traffic(self):
        result = self.capture()
        self.assertTrue(result['ok'],result)
        self.assertEqual(403,result['status'])
        self.assertTrue(result['body_complete'])
        self.assertEqual([],self.agent.callbacks.sent)

    def test_capture_rejects_changed_same_url_request_scope_and_partial_response(self):
        self.assertEqual('history_request_changed',self.agent._tool_capture_http_evidence({
            'index':0,'expected_url':self.item.url,'expected_request_sha256':'stale'})['error'])
        self.agent._v3_read_scope = lambda url:{'ok':False,'error':'outside_scope'}
        self.assertEqual('outside_scope',self.capture()['error'])
        self.agent._v3_read_scope = lambda url:{'ok':True}
        for raw in (raw_response('fragment',status=206), raw_response('short',headers=['Content-Length: 1000'])):
            self.item.resp = raw
            self.assertFalse(self.capture()['ok'])

    def test_request_cap_prevents_transport_and_counts_ambiguous_failure(self):
        a = self.agent
        a.investigation.start(1)
        request = {'method':'GET','url':self.item.url,'approved_by_automation':True}
        first = a._dispatch_request(request)
        self.assertFalse(first['ok'])  # Fixture deliberately fails after attempted transport.
        second = a._dispatch_request(request)
        self.assertEqual('investigation_request_budget_exhausted',second['error'])
        self.assertEqual(1,len(a.callbacks.sent))
        self.assertEqual(1,a.investigation.snapshot()['run']['requests'])

    def test_zero_budget_and_pause_reject_before_transport(self):
        a = self.agent
        a.investigation.start(0)
        request = {'method':'GET','url':self.item.url}
        self.assertEqual('investigation_request_budget_exhausted',a._dispatch_request(request)['error'])
        a.investigation.start(2); a._pause_requested = True
        self.assertEqual('investigation_paused',a._dispatch_request(request)['error'])
        self.assertEqual([],a.callbacks.sent)


class InvestigationLoopTests(autonomy.AutonomyTests):
    # Only new tests here; inherited regression tests also run with durable state.
    def setUp(self):
        super(InvestigationLoopTests,self).setUp()
        self.agent.investigation = Investigation(self.agent.ledger)
        self.agent.ui.refresh_investigation = lambda snapshot:None
        self.agent.ui.investigation_budget = Field('2')

    def test_summary_mid_batch_skips_network_and_pairs_every_call(self):
        self.agent.agent_running = True
        def execute(*args):
            self.agent._summarize_agent()
            return {'ok':True,'result':{'ok':True}}
        self.hook = execute
        self.responses = [response(call('read'),call('send_request')),response(content='Summary with remaining gaps.')]
        self.agent._run_agent_loop()
        self.assertEqual(['read'],self.executed)
        self.assertIsNone(self.requests[-1]['tools'])
        self.assert_paired()

    def test_paused_tool_batch_waits_and_stop_pairs_pending_calls(self):
        self.agent.agent_running = True
        self.responses = [response(call('read'),call('send_request'))]
        def execute(*args):
            self.agent._toggle_agent_pause()
            return {'ok':True,'result':{'ok':True}}
        self.hook = execute
        worker = threading.Thread(target=self.agent._run_agent_loop)
        worker.start()
        deadline = time.time() + 3
        while 'paused' not in self.statuses and time.time() < deadline: time.sleep(.02)
        try:
            self.assertIn('paused',self.statuses)
            self.assertEqual(['read'],self.executed)
        finally:
            self.agent._stop_agent(); worker.join(3)
        self.assertFalse(worker.is_alive())
        self.assert_paired()

    def test_pause_resume_applies_guidance_before_remaining_tools(self):
        self.agent.agent_running = True
        self.responses = [response(call('read'),call('send_request'))]
        def execute(*args):
            self.agent._toggle_agent_pause()
            return {'ok':True,'result':{'ok':True}}
        self.hook = execute
        worker = threading.Thread(target=self.agent._run_agent_loop)
        worker.start()
        deadline = time.time() + 3
        while 'paused' not in self.statuses and time.time() < deadline: time.sleep(.02)
        self.agent.ui.input_field.setText('Review saved evidence only.')
        self.agent._send_chat()
        self.agent._toggle_agent_pause(); worker.join(3)
        self.assertFalse(worker.is_alive())
        self.assertEqual(['read'],self.executed)
        self.assert_paired()

    def test_local_commands_do_not_call_model_or_become_guidance(self):
        self.agent.agent_running = True
        for command in ('/help','/status','/plan','/pause','/resume'):
            self.agent.ui.input_field.setText(command)
            self.agent._send_chat()
        self.assertEqual([],self.requests)
        self.assertEqual([],self.agent._pending_agent_messages)
        self.assertFalse(self.agent._pause_requested)

    def test_progress_cannot_be_used_as_finding_evidence(self):
        self.records.extend([{'id':'E1','mission_id':'m1','tool':'report_progress'},
                             {'id':'E2','mission_id':'m1','tool':'next_test'}])
        result = self.agent._tool_update_test_plan({'title':'Test','hypothesis':'Hypothesis',
            'status':'supported','baseline':'base','check':'check','result':'result','evidence_ids':['E1','E2']})
        self.assertFalse(result['ok'])

    def test_evidence_comparison_enforces_mission_and_original_capture(self):
        records = {'E1':{'mission_id':'m1','tool':'capture_http_evidence'},
                   'E2':{'mission_id':'m2','tool':'capture_http_evidence'}}
        self.agent.evidence._get_record = records.get
        self.agent.evidence._load_text = lambda ref:json.dumps(http())
        args = {'baseline_id':'E1','candidate_id':'E2'}
        self.assertFalse(self.agent._tool_compare_evidence(args)['ok'])
        records['E2']['mission_id']='m1'
        self.assertTrue(self.agent._tool_compare_evidence(args)['ok'])
        records['E2']['tool']='compare_evidence'
        self.assertFalse(self.agent._tool_compare_evidence(args)['ok'])

    def test_summary_dismisses_pending_choice_without_choosing_or_stopping(self):
        self.agent._summary_requested = True
        choice = self.agent._ask_user_choice('Choose','',[{'id':'first'}],default_id='first')
        self.assertIsNone(choice)
        self.assertFalse(self.agent.stop_agent_flag)

    def test_guidance_replans_without_replenishing_request_budget(self):
        self.agent.ui.investigation_budget.setText('1')
        reservations = []
        def execute(name, args):
            outcome = self.agent.investigation.reserve_request()
            reservations.append(outcome)
            if len(reservations) == 1:
                self.agent.ui.input_field.setText('Check the other captured role next.')
                self.agent._send_chat()
            return {'ok':True,'result':outcome}
        self.hook = execute
        self.responses = [response(call('propose_request',{'url':'https://example.test/a'})),
                          response(call('propose_request',{'url':'https://example.test/b'})),
                          response(content='Budget reached. Review the captured evidence.')]
        self.agent.ui.input_field.setText('Investigate.')
        worker = self.agent._send_chat(); worker.join(5)
        self.assertFalse(worker.is_alive())
        self.assertEqual(2,len(reservations))
        self.assertTrue(reservations[0]['ok'])
        self.assertEqual('investigation_request_budget_exhausted',reservations[1]['error'])
        self.assertEqual(1,self.agent.investigation.snapshot()['run']['requests'])
        self.assert_paired()

    def test_testing_cannot_skip_unresolved_prerequisite(self):
        first = self.agent._tool_update_test_plan({'title':'Baseline','hypothesis':'Check baseline'})['test']
        result = self.agent._tool_update_test_plan({'title':'Compare','hypothesis':'Compare roles',
            'status':'testing','depends_on':[first['id']]})
        self.assertEqual('unresolved_test_dependencies',result['error'])

    def test_same_capture_is_not_independent_comparison_evidence(self):
        self.agent.evidence._get_record = lambda ref:{'mission_id':'m1','tool':'capture_http_evidence'}
        self.agent.evidence._load_text = lambda ref:json.dumps(http(history_index=1,
            response_sha256='response',request_sha256='request'))
        result = self.agent._tool_compare_evidence({'baseline_id':'E1','candidate_id':'E2'})
        self.assertEqual('same_captured_exchange_is_not_independent_evidence',result['error'])


if __name__ == '__main__': unittest.main()

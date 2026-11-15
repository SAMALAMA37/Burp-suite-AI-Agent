# -*- coding: utf-8 -*-
from __future__ import unicode_literals
import copy
import hashlib
import json
import os
import sys
import threading
import unittest
sys.path.insert(0,os.path.dirname(os.path.abspath(__file__)))
import test_burpai_autonomy as autonomy
from test_burpai_autonomy import Box, Field
from test_burpai_website_integration import extension_namespace, load_function, response as raw_response
from test_burpai_workbench import Item, Helpers, Callbacks
from BurpAI_v4_Lab import LabEngine, origin, observe, discover, digest, parameter_variant, shape, route_path


def ledger(): return Box(lock=threading.RLock(),data={'mission_id':'fixture'},_persist=lambda:None)
def request(url='https://example.test/items/42?page=2&sort=a%2Bb', **kwargs):
    value={'url':url,'method':'GET','body':'','headers':{'Cookie':'baseline-secret','Authorization':'Bearer baseline-token','Accept':'application/json'}}
    value.update(kwargs); return value
def response(body='{"items":[{"id":42}]}',status=200,**kwargs):
    value={'ok':True,'url':'https://example.test/items/42','method':'GET','status':status,'body':body,
           'body_complete':True,'headers':['Content-Type: application/json']}
    value.update(kwargs); return value
def selection(req=None,index=1):
    req=req or request()
    return {'history_index':index,'request_sha256':digest(json.dumps(req,sort_keys=True)),'url_sha256':digest(req['url'])}


class DiscoveryTests(unittest.TestCase):
    def test_real_observations_generate_distinct_falsifiable_leads(self):
        req=request()
        samples=[observe(req,response(),selection(req,1)),
                 observe(req,response('{"error":"internal"}',500),selection(req,2)),
                 observe(req,response('{"page":2,"items":[]}'),selection(req,3))]
        mapped=discover(samples,origin(req['url']))
        kinds=set(l['kind'] for l in mapped['leads'])
        self.assertTrue({'parameter_contract','object_boundary','server_error','contract_drift'}.issubset(kinds))
        self.assertTrue(all(l['falsifier'] and l['state']=='unverified' for l in mapped['leads']))
        self.assertEqual(1,len(mapped['routes']))

    def test_mapping_does_not_persist_query_values_cookies_or_response_values(self):
        req=request('https://example.test/api?password=private-password&q=private-search')
        obs=observe(req,response('{"name":"private-name","token":"private-token"}'),selection(req))
        serialized=json.dumps(discover([obs],origin(req['url'])))
        for secret in ('baseline-secret','baseline-token','private-password','private-search','private-name','private-token'):
            self.assertNotIn(secret,serialized)
        self.assertFalse(any(l['parameter']=='password' for l in discover([obs],origin(req['url']))['leads']))

    def test_origin_matching_distinguishes_scheme_host_and_port(self):
        samples=[]
        for url in ('https://example.test/items/1','http://example.test/items/1','https://example.test:8443/items/1','https://example.test.evil/items/1'):
            req=request(url); samples.append(observe(req,response(),selection(req)))
        result=discover(samples,'https://example.test:443')
        self.assertEqual(1,result['routes'][0]['count'])

    def test_anonymous_equivalence_is_hypothesis_not_authentication_verdict(self):
        samples=[observe(request(),response(),selection(index=1)),
                 observe(request(headers={}),response(),selection(index=2))]
        leads=discover(samples,origin(request()['url']))['leads']
        lead=next(l for l in leads if l['kind']=='anonymous_equivalence')
        self.assertIn('public',lead['falsifier'])
        self.assertEqual('unverified',lead['state'])

    def test_incomplete_bodies_cannot_trigger_equivalence_or_contract_claim(self):
        samples=[observe(request(),response(body_complete=False),selection(index=1)),
                 observe(request(headers={}),response(body_complete=False),selection(index=2))]
        kinds=[l['kind'] for l in discover(samples,origin(request()['url']))['leads']]
        self.assertNotIn('anonymous_equivalence',kinds)
        self.assertNotIn('contract_drift',kinds)

    def test_shape_and_path_are_bounded_and_suppress_dynamic_values(self):
        self.assertEqual('/users/{value}/{number}',route_path('https://example.test/users/a@example.test/12'))
        value=shape(json.dumps({'private@example.test':'private-value','rows':[{'id':n} for n in range(100)]}))
        self.assertNotIn('private',json.dumps(value))
        self.assertLessEqual(len(value),80)

    def test_challenge_retrieves_actual_denials_and_controls(self):
        samples=[observe(request(),response(),selection(index=1)),
                 observe(request(headers={}),response('Denied',403),selection(index=2))]
        lab=LabEngine(ledger()); mapped=discover(samples,origin(request()['url']))
        lab.ingest(mapped,'EV-map')
        lead=next(l for l in mapped['leads'] if l['kind']=='object_boundary')
        challenge=lab.challenge(lead['id'])
        self.assertEqual(403,challenge['counter_observations'][0]['status'])
        self.assertEqual(1,len(challenge['successful_controls']))
        self.assertEqual(['EV-map'],challenge['evidence_ids'])

    def test_custom_hypothesis_requires_observed_route_and_keeps_falsifier(self):
        req=request(); lab=LabEngine(ledger())
        mapped=discover([observe(req,response(),selection(req))],origin(req['url']))
        lab.ingest(mapped,'EV-map')
        lead=lab.create_hypothesis(origin(req['url']),'GET /items/{number}','Potential paging invariant',
            'Removing paging could change the visibility rule.','Visibility remains bounded independently of paging.',
            ['EV-map'],'page')
        self.assertEqual('custom_hypothesis',lead['kind'])
        self.assertEqual('page',lead['parameter'])
        with self.assertRaises(ValueError):
            lab.create_hypothesis(origin(req['url']),'POST /invented','Title','Claim','Counterexample',['EV-map'])
        self.assertEqual(1,len(lab.snapshot(include_routes=True)['routes']))


class ExperimentTests(unittest.TestCase):
    def setUp(self):
        self.ledger=ledger(); self.lab=LabEngine(self.ledger); self.sent=[]; self.captured=[]
        self.req=request()
        self.exp=self.lab.prepare(self.req,selection(self.req),'parameter_boundaries','page')
    def send(self,req):
        self.sent.append(copy.deepcopy(req))
        return response('{"items":[]}' if len(self.sent)==2 else '{"items":[{"id":42}]}')
    def capture(self,exp,label,payload):
        self.captured.append((label,payload)); return 'EV'+str(len(self.captured))
    def run_exp(self,**kwargs):
        return self.lab.run(self.exp['id'],self.send,self.capture,lambda:True,**kwargs)

    def test_single_parameter_mutation_preserves_other_raw_encoding_and_order(self):
        url='https://example.test/path?x=a%2Bb&x=two+words&page=2&last=%2f'
        self.assertEqual('https://example.test/path?x=a%2Bb&x=two+words&last=%2f',parameter_variant(url,'page','omit'))
        self.assertEqual(url+'&page=2',parameter_variant(url,'page','duplicate'))
        self.assertIn('x=a%2Bb&x=two+words&page=&last=%2f',parameter_variant(url,'page','empty'))
        self.assertEqual('https://example.test/?other=a%2Bb',parameter_variant(
            'https://example.test/?%C5%BC=one&other=a%2Bb','\u017c','omit'))

    def test_preparation_contains_no_credentials_and_does_not_send(self):
        self.assertEqual(5,self.exp['request_count'])
        self.assertEqual('draft',self.exp['state'])
        for secret in ('baseline-secret','baseline-token','a%2Bb'):
            self.assertNotIn(secret,json.dumps(self.lab.snapshot()))
            self.assertNotIn(secret,json.dumps(self.ledger.data))
        self.assertEqual([],self.sent)

    def test_all_cases_share_full_response_transport_normalization(self):
        req=request(headers={'Cookie':'secret','Accept-Encoding':'br','If-None-Match':'etag','Range':'bytes=0-99'})
        exp=self.lab.prepare(req,selection(req),'parameter_boundaries','page')
        self.lab.run(exp['id'],self.send,self.capture,lambda:True,approved=True)
        for req in self.sent:
            self.assertEqual('identity',req['headers']['Accept-Encoding'])
            self.assertNotIn('If-None-Match',req['headers']); self.assertNotIn('Range',req['headers'])

    def test_approval_and_whole_experiment_budget_required_before_first_send(self):
        self.assertEqual('experiment_approval_required',self.run_exp(approved=False)['error'])
        self.assertEqual('insufficient_run_request_budget',self.run_exp(approved=True,available_requests=4)['error'])
        self.assertEqual([],self.sent)
        self.assertEqual('draft',self.lab.get_experiment(self.exp['id'])['state'])

    def test_baseline_three_variants_and_repeat_are_archived_and_compared(self):
        result=self.run_exp(approved=True)['experiment']
        self.assertEqual(5,len(self.sent)); self.assertEqual(5,len(self.captured))
        self.assertEqual(self.sent[0],self.sent[-1])
        self.assertNotIn('page=',self.sent[1]['url'])
        self.assertIn('page=&',self.sent[2]['url'])
        self.assertTrue(self.sent[3]['url'].endswith('&page=2'))
        self.assertEqual('differences_observed',result['assessment'])
        self.assertEqual(3,len(result['comparisons']))
        self.assertEqual('EV5',result['comparisons'][0]['repeat_baseline_id'])
        self.assertEqual('stable_observed',result['comparisons'][0]['baseline_stability'])

    def test_dynamic_baseline_marks_comparisons_inconclusive(self):
        def send(req):
            self.sent.append(req); return response(json.dumps({'clock':len(self.sent)}))
        result=self.lab.run(self.exp['id'],send,self.capture,lambda:True,approved=True)
        self.assertEqual('unstable_baseline',result['experiment']['assessment'])

    def test_failed_send_is_not_replayed_even_after_prepare_again(self):
        def failed(req): self.sent.append(req); return {'ok':False,'error':'timeout'}
        result=self.lab.run(self.exp['id'],failed,self.capture,lambda:True,approved=True)
        self.assertEqual('incomplete',result['experiment']['state'])
        rebuilt=self.lab.prepare(self.req,selection(self.req),'parameter_boundaries','page')
        self.assertEqual('incomplete',rebuilt['state'])
        self.assertEqual('experiment_already_attempted_no_automatic_replay',self.run_exp(approved=True)['error'])
        self.assertEqual(1,len(self.sent))
        rebuilt=self.lab.prepare(self.req,selection(self.req,index=99),'parameter_boundaries','page')
        self.assertEqual(self.exp['id'],rebuilt['id'])

    def test_stop_or_guidance_prevents_remaining_cases(self):
        result=self.lab.run(self.exp['id'],self.send,self.capture,lambda:len(self.sent)<2,approved=True)
        self.assertEqual(2,len(self.sent))
        self.assertEqual('interrupted',result['experiment']['state'])
        self.assertEqual('planned',result['experiment']['cases'][2]['state'])

    def test_archive_failure_leaves_interrupted_state_and_no_replay(self):
        def broken(*args): raise IOError('disk full')
        with self.assertRaises(IOError): self.lab.run(self.exp['id'],self.send,broken,lambda:True,approved=True)
        self.assertEqual('interrupted',self.lab.get_experiment(self.exp['id'])['state'])
        self.assertEqual('experiment_already_attempted_no_automatic_replay',self.run_exp(approved=True)['error'])

    def test_reload_keeps_metadata_but_requires_rehydrating_draft_request(self):
        loaded=LabEngine(self.ledger)
        result=loaded.run(self.exp['id'],self.send,self.capture,lambda:True,approved=True)
        self.assertEqual('request_template_missing_prepare_again',result['error'])
        loaded.prepare(self.req,selection(self.req),'parameter_boundaries','page')
        self.assertTrue(loaded.run(self.exp['id'],self.send,self.capture,lambda:True,approved=True)['ok'])

    def test_mutating_requests_bodies_action_routes_and_secret_parameters_are_rejected(self):
        for req,param in ((request(method='POST'),'page'),(request(body='value'),'page'),
                          (request('https://example.test/delete?page=1'),'page'),
                          (request('https://example.test/?token=x'),'token')):
            with self.assertRaises(ValueError): self.lab.prepare(req,selection(req),'parameter_boundaries',param)

    def test_concurrent_execution_cannot_start_second_copy(self):
        entered=threading.Event(); release=threading.Event()
        def send(req): entered.set(); release.wait(3); return response()
        worker=threading.Thread(target=lambda:self.lab.run(self.exp['id'],send,self.capture,lambda:True,approved=True))
        worker.start(); self.assertTrue(entered.wait(2))
        try: self.assertEqual('experiment_already_attempted_no_automatic_replay',self.run_exp(approved=True)['error'])
        finally: release.set(); worker.join(4)
        self.assertFalse(worker.is_alive())


class SessionTests(unittest.TestCase):
    def setUp(self): self.ledger=ledger(); self.lab=LabEngine(self.ledger)
    def profile(self,url='https://example.test/profile'):
        return self.lab.add_profile('Test account B',request(url,headers={'Cookie':'other-cookie','Authorization':'Bearer other-token'}))

    def test_session_substitution_removes_original_credentials_and_binds_origin(self):
        profile=self.profile(); req=request()
        exp=self.lab.prepare(req,selection(req),'session_matrix',profile_ids=['anonymous',profile['id']])
        sent=[]
        def send(value): sent.append(value); return response()
        self.lab.run(exp['id'],send,lambda *args:'EV',lambda:True,approved=True)
        self.assertEqual({},dict((k,v) for k,v in sent[1]['headers'].items() if k.lower() in ('cookie','authorization')))
        self.assertEqual('other-cookie',sent[2]['headers']['Cookie'])
        self.assertNotIn('baseline-token',json.dumps(sent[2]))
        self.assertEqual(sent[0],sent[-1])

    def test_profiles_never_cross_scheme_or_port_and_do_not_persist(self):
        profile=self.profile('http://example.test/profile'); req=request()
        with self.assertRaises(ValueError): self.lab.prepare(req,selection(req),'session_matrix',profile_ids=[profile['id']])
        for secret in ('other-cookie','other-token'):
            self.assertNotIn(secret,json.dumps(self.ledger.data)); self.assertNotIn(secret,json.dumps(self.lab.snapshot()))
        self.assertEqual([],LabEngine(self.ledger).snapshot()['session_profiles'])

    def test_forgetting_sessions_stops_active_matrix_after_current_request(self):
        profile=self.profile(); req=request()
        exp=self.lab.prepare(req,selection(req),'session_matrix',profile_ids=[profile['id']])
        sent=[]
        def send(value):
            sent.append(value); self.lab.forget_profiles(); return response()
        result=self.lab.run(exp['id'],send,lambda *args:'EV',lambda:True,approved=True)
        self.assertEqual(1,len(sent)); self.assertEqual('interrupted',result['experiment']['state'])

    def test_new_mission_forgets_profiles_and_experiment_templates(self):
        self.profile(); self.ledger.data={'mission_id':'new'}
        snapshot=self.lab.snapshot()
        self.assertEqual([],snapshot['session_profiles']); self.assertEqual([],snapshot['experiments'])

    def test_query_bound_authentication_cannot_masquerade_as_anonymous_matrix(self):
        req=request('https://example.test/api?access_token=token')
        with self.assertRaises(ValueError): self.lab.prepare(req,selection(req),'session_matrix')

    def test_irrelevant_parameter_cannot_bypass_experiment_identity(self):
        req=request()
        one=self.lab.prepare(req,selection(req),'session_matrix',parameter='one')
        two=self.lab.prepare(req,selection(req,index=99),'session_matrix',parameter='two')
        self.assertEqual(one['id'],two['id'])

    def test_failed_session_baseline_stops_before_cross_session_variants(self):
        req=request(); exp=self.lab.prepare(req,selection(req),'session_matrix'); sent=[]
        def send(value): sent.append(value); return response('Sign in',401)
        result=self.lab.run(exp['id'],send,lambda *args:'EV',lambda:True,approved=True)
        self.assertEqual(1,len(sent)); self.assertEqual('baseline_not_successful',result['experiment']['assessment'])


class AdapterTests(unittest.TestCase):
    def setUp(self):
        ns=extension_namespace(); ns.update(hashlib=hashlib,json=json,threading=threading,
            lab_origin=origin,lab_observe=observe,discover_app=discover,lab_digest=digest)
        ns['_bounded_int']=load_function('_bounded_int',ns)
        names=('_lab_request','_tool_lab_map','_tool_lab_prepare','_tool_lab_run','_tool_lab_assessment','_tool_lab_create')
        self.agent=a=type('Agent',(object,),dict((name,load_function(name,ns,'BurpExtender')) for name in names))()
        self.item=Item('https://example.test/items/42?page=1')
        a.callbacks=Callbacks([self.item]); a.helpers=Helpers(); a.ledger=ledger(); a.lab=LabEngine(a.ledger)
        a._v3_read_scope=lambda url:{'ok':url.startswith('https://example.test/')}
        a._has_agent_guidance=lambda:False; a._wait_if_paused=lambda:True
        a.stop_agent_flag=a.kill_switch=False; a._summary_requested=False
        a._refresh_lab=lambda:None; self.cards=[]; a._append_lab_card=self.cards.append
        a._append_chat=lambda *args:None; a._investigation_event=lambda *args:None
        self.records=[]
        def capture(name,args,payload):
            self.records.append({'id':'EV'+str(len(self.records)+1),'tool':name,'mission_id':'fixture'})
            return self.records[-1]
        a.evidence=Box(capture=capture,lock=threading.RLock(),index={'items':self.records})
        a.ledger.observe=lambda *args:None
        a.agent_lock=threading.Lock(); a._lab_approvals=set()
        a.store=Box(get_auto_send_requests=lambda:False)
        a.investigation=Box(snapshot=lambda:{'run':{'request_limit':10,'requests':0}},active=True)
        self.sent=[]
        def dispatch(req,**kwargs): self.sent.append((req,kwargs)); return response()
        a._dispatch_request=dispatch

    def mapped_lead(self):
        result=self.agent._tool_lab_map({'url':'https://example.test/'})
        return next(l for l in result['leads'] if l['kind']=='parameter_contract')

    def test_discovery_and_preparation_are_passive_then_run_requires_real_approval(self):
        a=self.agent; lead=self.mapped_lead()
        exp=a._tool_lab_prepare({'lead_id':lead['id'],'mode':'parameter_boundaries'})['experiment']
        self.assertEqual([],self.sent); self.assertTrue(self.cards)
        result=a._tool_lab_run({'experiment_id':exp['id'],'approved':True})
        self.assertEqual('experiment_approval_required',result['error']); self.assertEqual([],self.sent)
        a._lab_approvals.add(exp['id'])
        result=a._tool_lab_run({'experiment_id':exp['id']})
        self.assertEqual('completed',result['experiment']['state'])
        self.assertEqual(5,len(self.sent))
        self.assertTrue(all(kwargs['experiment_response'] for req,kwargs in self.sent))
        self.assertTrue(all(req['approved_by_user'] for req,kwargs in self.sent))
        self.assertNotIn(exp['id'],a._lab_approvals)

    def test_changed_history_identity_is_rejected_before_preparation(self):
        lead=self.mapped_lead(); self.item.raw=self.item.raw.replace(b'one',b'changed')
        with self.assertRaises(ValueError): self.agent._tool_lab_prepare({'lead_id':lead['id'],'mode':'parameter_boundaries'})
        self.assertEqual([],self.sent)

    def test_auto_send_toggle_interrupts_remaining_cases(self):
        enabled=[True]; self.agent.store.get_auto_send_requests=lambda:enabled[0]
        lead=self.mapped_lead(); exp=self.agent._tool_lab_prepare({'lead_id':lead['id'],'mode':'parameter_boundaries'})['experiment']
        def send(req,**kwargs): self.sent.append(req); enabled[0]=False; return response()
        self.agent._dispatch_request=send
        result=self.agent._tool_lab_run({'experiment_id':exp['id']})
        self.assertEqual(1,len(self.sent)); self.assertEqual('interrupted',result['experiment']['state'])

    def test_assessment_cannot_cite_self_authored_claims_as_observations(self):
        lead=self.mapped_lead(); self.records.append({'id':'fiction','mission_id':'fixture','tool':'lab_record_assessment'})
        args={'lead_id':lead['id'],'state':'ready_for_review','assessment':'Observed behavior','evidence_ids':['fiction']}
        self.assertFalse(self.agent._tool_lab_assessment(args)['ok'])
        args['evidence_ids']=['EV1']
        self.assertTrue(self.agent._tool_lab_assessment(args)['ok'])

    def test_agent_can_create_grounded_custom_hypothesis(self):
        lead=self.mapped_lead()
        args={'origin':lead['origin'],'route_key':lead['route_key'],'title':'Application-specific invariant',
              'hypothesis':'The source suggests paging should not affect access.','falsifier':'Access checks remain consistent.',
              'evidence_ids':['unknown'],'parameter':'page'}
        self.assertFalse(self.agent._tool_lab_create(args)['ok'])
        args['evidence_ids']=['EV1']
        result=self.agent._tool_lab_create(args)
        self.assertTrue(result['ok']); self.assertEqual('custom_hypothesis',result['lead']['kind'])


class ChatIntegrationTests(autonomy.AutonomyTests):
    def test_card_action_prompt_preserves_unsent_draft_and_retains_referenced_mission(self):
        self.agent.ui.input_field.setText('My unfinished message')
        self.agent.store.values['persist_conversation']=False
        self.responses=[autonomy.response(content='I will inspect that exact discovery.')]
        worker=self.agent._send_chat('Explain discovery L1234567890abcd',retain_mission=True)
        worker.join(3)
        self.assertFalse(worker.is_alive())
        self.assertEqual('My unfinished message',self.agent.ui.input_field.getText())
        self.assertEqual('fixture',self.requests[0]['model'])

    def test_card_action_queues_guidance_without_overwriting_draft(self):
        self.agent.agent_running=True
        self.agent.ui.input_field.setText('Draft')
        self.agent._send_chat('Challenge discovery L1234567890abcd',retain_mission=True)
        self.assertEqual(['Challenge discovery L1234567890abcd'],self.agent._pending_agent_messages)
        self.assertEqual('Draft',self.agent.ui.input_field.getText())


if __name__=='__main__': unittest.main()

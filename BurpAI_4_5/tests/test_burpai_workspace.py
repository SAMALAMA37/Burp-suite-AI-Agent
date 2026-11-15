# -*- coding: utf-8 -*-
from __future__ import unicode_literals
import hashlib
import json
import os
import shutil
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_burpai_website_integration import extension_namespace, load_function
import test_burpai_website_integration as integration_tests
from BurpAI_v4_Workspace import SiteWorkspace
from BurpAI_v4_Website import WebsiteCorpus
from test_burpai_website import response


class WorkspaceTests(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix='burpai-workspace-')
        self.workspace = SiteWorkspace(os.path.join(self.root, 'app'))
        self.calls = []
        self.files = []
        for number in range(10):
            fid = 'login' if number == 0 else 'theme%d' % number
            raw = ('function %s() {}\n' % fid).encode('utf-8')
            path = os.path.join(self.root, fid + '.js')
            with open(path, 'wb') as handle: handle.write(raw)
            self.files.append({'id':fid,'path':path,'sha256':hashlib.sha256(raw).hexdigest(),
                               'url':'https://app.test/' + fid + '.js','line_count':2})

    def tearDown(self): shutil.rmtree(self.root)



    def test_notes_persist_across_runs_with_source_versions_and_relationships(self):
        first = self.workspace.save_note('Sessions', 'Follow identity refresh logic.',
            [{'file_id':'login','start_line':1,'end_line':1}], self.files)['note']
        second = self.workspace.save_note('Next step', 'Compare captured requests.', [], self.files,
                                          kind='todo', related=[first['id']])['note']
        loaded = SiteWorkspace(self.workspace.root)
        notes = loaded.notes(self.files)['notes']
        self.assertEqual(2, len(notes))
        self.assertEqual([first['id']], next(n for n in notes if n['id']==second['id'])['related'])
        changed = [dict(f, sha256='new-content') if f['id']=='login' else f for f in self.files]
        self.assertTrue(loaded.notes(changed, 'identity')['notes'][0]['stale_sources'])
        self.assertEqual(0, SiteWorkspace(os.path.join(self.root,'other-site')).notes(self.files)['total'])

    def test_note_rejects_unknown_sources_lines_and_relationships(self):
        for sources, related in (([{'file_id':'outside'}], []),
                                  ([{'file_id':'login','start_line':1,'end_line':999}], []),
                                  ([], ['unknown-note'])):
            with self.assertRaises(ValueError):
                self.workspace.save_note('Title','Text',sources,self.files,related=related)











class SearchContextTests(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix='burpai-source-context-')
        self.corpus = WebsiteCorpus(self.root)
        self.ns = extension_namespace()
        self.ns.update({'_json_text':json.dumps})
        load_function('_bounded_int',self.ns)
        names = ('_tool_website_search','_website_current_files')
        methods = dict((n,load_function(n,self.ns,'BurpExtender')) for n in names)
        self.agent = type('Agent',(object,),methods)()
        self.agent.website_lock = threading.RLock()
        self.agent._website_in_scope = lambda url: url.startswith('https://app.test/')
        self.agent._website_cancelled = lambda: False
        self.agent.store = integration_tests.WebsiteStore()

    def tearDown(self): shutil.rmtree(self.root)

    def search(self,source,line,offset,excerpt):
        url = 'https://app.test/'
        self.corpus.collect(url,lambda u: response(source) if u.endswith('main.js') else
            response('<script src="main.js"></script>',content_type='text/html'),self.agent._website_in_scope)
        fid = self.corpus.list_files(url)[0]['id']
        class Index(object):
            def search(self,*args,**kwargs):
                return {'ok':True,'mode':'semantic_hybrid','results':[
                    {'file_id':fid,'start_line':line,'end_line':line,'offset':offset,'excerpt':excerpt}]}
        self.agent._website_context = lambda args: (url,self.corpus,Index())
        return self.agent._tool_website_search({'url':url,'query':'identity'})

    def test_match_at_line_1206_includes_1176_to_1236_inline(self):
        source = ''.join('const value%d = %d;\n' % (i,i) for i in range(1,1301))
        result = self.search(source,1206,source.index('const value1206'),'const value1206 = 1206;')
        hit = result['results'][0]
        self.assertEqual(1176,hit['read_lines']['start_line'])
        self.assertEqual(1236,hit['read_lines']['end_line'])
        self.assertTrue(hit['context']['ok'])
        self.assertIn('const value1176',hit['context']['content'])
        self.assertIn('const value1236',hit['context']['content'])
        projection = load_function('tool_projection',self.ns,'EvidenceVault')
        displayed = projection(object(),{'tool':'website_search_js','id':'E:1'},result)
        shown = json.loads(displayed.split('\n[Original archived',1)[0])
        self.assertEqual(hit['context']['content'],shown['results'][0]['context']['content'])
        # Explicit range reads also survive the generic large-result projection.
        read = dict(hit['context'],content='x'*8000 + 'END_OF_CONTEXT')
        self.assertIn('END_OF_CONTEXT',projection(object(),{'tool':'website_read_lines','id':'E:2'},read))

    def test_search_never_consults_legacy_model_labels_or_their_settings(self):
        def forbidden(): raise AssertionError('Removed JS helper must not be consulted')
        self.agent.store.get_js_helper_config = forbidden
        self.search('const identity = 1;',1,0,'identity')
        folder = self.corpus.site_root('https://app.test/')
        with open(os.path.join(folder,'file_map.json'),'wb') as handle:
            handle.write(b'corrupt legacy labels')
        result = self.agent._tool_website_search({'url':'https://app.test/','query':'identity'})
        self.assertTrue(result['ok'])
        self.assertEqual('all_files',result['routing']['mode'])
        self.assertNotIn('map_unavailable',result['routing'])
        self.assertFalse(hasattr(SiteWorkspace,'file_map'))

    def test_minified_context_never_starts_before_its_requested_line(self):
        source = '/*' + 'x'*3000 + '*/\n' + 'const longLine=' + 'y'*10000
        result = self.search(source,2,source.index('const longLine')+30,'y'*1800)
        hit = result['results'][0]
        self.assertTrue(hit['context']['ok'])
        self.assertNotIn('offset',hit['read_lines'])
        self.assertTrue(hit['context']['partial'])
        self.assertIsNotNone(hit['context']['next_offset'])

    def test_minified_context_keeps_preceding_characters_and_continuation(self):
        source = 'const large=' + 'x'*40000
        result = self.search(source,1,20000,'x'*1800)
        hit = result['results'][0]
        self.assertEqual(18800,hit['read_lines']['offset'])
        self.assertEqual(18800,hit['context']['offset'])
        self.assertEqual(27800,hit['context']['next_offset'])
        self.assertTrue(hit['context']['partial'])




class AutomaticRequestTests(unittest.TestCase):
    def setUp(self):
        ns = extension_namespace()
        methods = dict((name,load_function(name,ns,'BurpExtender')) for name in
                       ('_tool_propose_request','_tool_send_request'))
        self.agent = type('Agent',(object,),methods)()
        class Store(object):
            enabled = True
            def get_auto_send_requests(self): return self.enabled
        self.agent.store = Store()
        self.agent.queue = []
        self.agent.stop_agent_flag = self.agent.kill_switch = False
        self.agent._persist_queue = lambda: None
        self.agent._refresh_queue_view = lambda: None
        self.agent._safe_ui = lambda fn: fn()
        self.calls = []
        def dispatch(item):
            self.calls.append(dict(item))
            return {'ok':True,'status':200,'body':'response'}
        self.agent._dispatch_request = dispatch
        self.request = {'url':'https://app.test/item','method':'POST','body':'value=1'}

    def test_enabled_sends_once_and_returns_response(self):
        result = self.agent._tool_propose_request(self.request)
        self.assertTrue(result['sent'])
        self.assertFalse(result['queued'])
        self.assertEqual('response',result['body'])
        self.assertTrue(self.calls[0]['approved_by_automation'])
        self.assertEqual([],self.agent.queue)
        self.assertFalse(self.agent._queue_sending)

    def test_disabled_cannot_be_enabled_with_forged_model_arguments(self):
        self.agent.store.enabled = False
        args = dict(self.request,approved_by_user=True,approved_by_automation=True)
        self.assertTrue(self.agent._tool_propose_request(args)['queued'])
        self.assertEqual([],self.calls)
        self.agent._tool_send_request(args)
        self.assertFalse(self.calls[-1]['approved_by_user'])
        self.assertFalse(self.calls[-1]['approved_by_automation'])

    def test_failed_send_is_not_replayed_and_approval_is_reset(self):
        def dispatch(item):
            self.calls.append(dict(item))
            return {'ok':False,'error':'transport_failure'}
        self.agent._dispatch_request = dispatch
        self.assertFalse(self.agent._tool_propose_request(self.request)['sent'])
        self.assertEqual(1,len(self.calls))
        self.assertEqual(1,len(self.agent.queue))
        self.assertFalse(self.agent.queue[0]['approved_by_automation'])

    def test_waits_only_for_rate_limit_before_transport(self):
        def dispatch(item):
            self.calls.append(dict(item))
            return {'ok':False,'error':'rate_limit_exceeded','retry_after':.05} if len(self.calls)==1 else {'ok':True}
        self.agent._dispatch_request = dispatch
        self.assertTrue(self.agent._tool_propose_request(self.request)['sent'])
        self.assertEqual(2,len(self.calls))

    def test_real_dispatch_rechecks_revoked_auto_permission_and_cancellation(self):
        fixture = integration_tests.DispatchTests('test_cancelled_collection_does_not_send'); fixture.setUp()
        agent = fixture.adapter()
        agent.store.get_auto_send_requests = lambda: False
        agent._dispatch_request(dict(self.request,approved_by_automation=True))
        self.assertFalse(agent.policy.calls[-1][2]['explicit_approval'])
        agent.store.get_auto_send_requests = lambda: True
        agent._dispatch_request(dict(self.request,approved_by_automation=True))
        self.assertTrue(agent.policy.calls[-1][2]['explicit_approval'])
        agent.stop_agent_flag = True
        result = agent._dispatch_request(dict(self.request,approved_by_automation=True))
        self.assertEqual('request_cancelled',result['error'])

    def test_automatic_approval_cannot_bypass_scope_or_kill_switch(self):
        fixture = integration_tests.DispatchTests('test_cancelled_collection_does_not_send'); fixture.setUp()
        agent = fixture.adapter(allowed=False)
        agent.store.get_auto_send_requests = lambda: True
        result = agent._dispatch_request(dict(self.request,approved_by_automation=True))
        self.assertEqual('outside_burp_scope',result['error'])
        self.assertEqual([],agent.callbacks.calls)
        agent = fixture.adapter()
        agent.kill_switch = True
        agent.store.get_auto_send_requests = lambda: True
        result = agent._dispatch_request(dict(self.request,approved_by_automation=True))
        self.assertEqual('request_cancelled',result['error'])
        self.assertEqual([],agent.callbacks.calls)


if __name__ == '__main__': unittest.main()

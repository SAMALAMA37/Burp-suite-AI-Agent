# -*- coding: utf-8 -*-
"""Agent receives saved source inventory without network or UI chat history."""
from __future__ import unicode_literals
import json
import os
import shutil
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_burpai_website_integration import extension_namespace, load_function
from test_burpai_website import response
from BurpAI_v4_Website import WebsiteCorpus
from BurpAI_v4_Workspace import SiteWorkspace


class AgentSearchContextTests(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix='burpai-agent-context-')
        self.url = 'https://app.test/'
        self.corpus = WebsiteCorpus(self.root)
        root = self.root
        class Store(object):
            selected_url = 'https://app.test/'
            def _g(self, key, default): return self.selected_url if key == 'website_last_url' else default
            def get_website_root(self): return root
        ns = extension_namespace()
        ns.update({'WebsiteCorpus': WebsiteCorpus, 'SiteWorkspace':SiteWorkspace, '_json_text': json.dumps})
        methods = dict((name, load_function(name, ns, 'BurpExtender')) for name in
                       ('_website_agent_prompt', '_website_current_files'))
        self.agent = type('Agent', (object,), methods)()
        self.agent.store = Store()
        self.agent.logger = None
        self.agent.website_lock = threading.RLock()
        self.agent._website_in_scope = lambda url: url.startswith(self.url)

    def tearDown(self):
        shutil.rmtree(self.root)

    def inventory(self):
        prompt = self.agent._website_agent_prompt()
        return json.loads(prompt.rsplit('scope is rechecked by tools): ', 1)[1])

    def collect(self):
        routes = {self.url: response('<script src="/main.js"></script>', content_type='text/html'),
                  self.url + 'main.js': response('const adminRoute = "/admin";')}
        result = self.corpus.collect(self.url, fetch=lambda url: routes[url],
                                     in_scope=self.agent._website_in_scope)
        self.assertTrue(result['ok'])

    def test_disk_inventory_reaches_agent_without_ui_collection_message(self):
        self.collect()
        data = self.inventory()
        self.assertEqual(self.url, data['url'])
        self.assertEqual(1, data['saved_files'])
        self.assertIn('complete_discovery', data['collection'])
        self.assertNotIn('mode', data)  # Actual search reports current embedding mode.

    def test_inventory_refreshes_after_collection_and_file_removal(self):
        self.assertEqual(0, self.inventory()['saved_files'])
        self.collect()
        self.assertEqual(1, self.inventory()['saved_files'])
        os.remove(self.corpus.list_files(self.url)[0]['path'])
        self.assertEqual(0, self.inventory()['saved_files'])

    def test_scope_change_does_not_expose_saved_library(self):
        self.collect()
        self.agent._website_in_scope = lambda url: False
        data = self.inventory()
        self.assertEqual('outside_burp_scope', data['error'])
        self.assertNotIn('saved_files', data)

    def test_missing_selection_and_other_site_do_not_reuse_previous_counts(self):
        self.collect()
        self.agent.store.selected_url = ''
        self.assertEqual({}, self.inventory())
        self.agent.store.selected_url = 'https://other.test/'
        self.agent._website_in_scope = lambda url: True
        self.assertEqual(0, self.inventory()['saved_files'])

    def test_corrupt_manifest_is_reported_as_unknown_not_empty(self):
        self.collect()
        with open(os.path.join(self.corpus.site_root(self.url), 'manifest.json'), 'wb') as handle:
            handle.write(b'broken')
        data = self.inventory()
        self.assertEqual('local_inventory_unavailable', data['error'])
        self.assertNotIn('saved_files', data)


if __name__ == '__main__':
    unittest.main()

# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import hashlib
import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from BurpAI_v4_Website import WebsiteCorpus, canonical_url


def response(body='', status=200, content_type='application/javascript', **kwargs):
    result = {'ok': True, 'status': status, 'body': body, 'body_complete': True,
              'headers': ['Content-Type: ' + content_type]}
    result.update(kwargs)
    return result


class WebsiteCorpusTests(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix='burpai-website-test-')
        self.corpus = WebsiteCorpus(self.root)
        self.calls = []

    def tearDown(self):
        shutil.rmtree(self.root)

    def collect(self, routes, **kwargs):
        def fetch(url):
            self.calls.append(url)
            return routes.get(url, response(status=404))
        kwargs.setdefault('in_scope', lambda url: url.startswith('https://app.test/') or url.startswith('https://cdn.test/'))
        return self.corpus.collect('https://app.test/', fetch=fetch, **kwargs)

    def test_crawl_html_inline_modules_chunks_base_and_scoped_cdn(self):
        routes = {
            'https://app.test/': response('''<html><head><base href="/assets/">
                <link rel="modulepreload" href="preload.mjs"></head><body>
                <script src="app.js?v=1"></script><script src="//cdn.test/lib.js"></script>
                <script type="module">import './inline-dep.js'; const x = "\u017b\u00f3\u0142w";</script>
                <script type="application/ld+json">{"fake": "no.js"}</script>
                <a href="/next">next</a></body></html>''', content_type='text/html'),
            'https://app.test/assets/app.js?v=1': response("import {x} from './dep'; import('./chunk.js'); const s='bundle.js';"),
            'https://app.test/assets/dep': response('export const x = 1;'),
            'https://app.test/assets/chunk.js': response('export default 2;'),
            'https://app.test/assets/bundle.js': response('const bundle=3;'),
            'https://app.test/assets/inline-dep.js': response('export const inline=4;'),
            'https://app.test/assets/preload.mjs': response('export const pre=5;'),
            'https://cdn.test/lib.js': response('const lib=6;'),
            'https://app.test/next': response('<script src="/next.js"></script>', content_type='text/html'),
            'https://app.test/next.js': response('const next=7;')}
        result = self.collect(routes)
        self.assertEqual(result['files_count'], 9)
        self.assertEqual(result['failures'], [])
        self.assertTrue(result['discovery_exhausted'])
        self.assertFalse(result['complete_discovery'])
        rows = self.corpus.list_files('https://app.test/elsewhere')
        inline = next(row for row in rows if row['kind'] == 'inline')
        self.assertIn('\u017b\u00f3\u0142w', self.corpus.read_file('https://app.test/', inline['id'])['content'])
        self.assertFalse(any('no.js' in call for call in self.calls))

    def test_redirect_scope_and_same_origin_page_boundary(self):
        routes = {'https://app.test/': response(status=302, headers=['Location: https://cdn.test/'])}
        result = self.collect(routes)
        self.assertEqual(self.calls, ['https://app.test/'])
        self.assertEqual(result['failures'][0]['error'], 'page_redirect_outside_origin')
        self.calls = []
        routes = {'https://app.test/': response('<script src="/start.js"></script>', content_type='text/html'),
                  'https://app.test/start.js': response(status=302, headers=['Location: https://evil.test/trap.js'])}
        result = self.collect(routes)
        self.assertNotIn('https://evil.test/trap.js', self.calls)
        self.assertEqual(result['failures'][0]['error'], 'redirect_outside_burp_scope')

    def test_script_redirect_resolves_relative_import_from_final_url(self):
        routes = {'https://app.test/': response('<script src="/start.js"></script>', content_type='text/html'),
                  'https://app.test/start.js': response(status=302, headers=['Location: /v2/main.js']),
                  'https://app.test/v2/main.js': response("import './dep.js'"),
                  'https://app.test/v2/dep.js': response('var dep=1;')}
        result = self.collect(routes)
        self.assertEqual(result['files_count'], 2)
        self.assertIn('https://app.test/v2/dep.js', self.calls)

    def test_query_collisions_and_hostile_file_names_are_contained(self):
        urls = ['https://app.test/../../CON.js?q=1', 'https://app.test/../../CON.js?q=2',
                'https://app.test/%2e%2e%2fescape.js?x=%00', 'https://app.test/C:%5cevil.js']
        result = self.collect({'https://app.test/': response('<html></html>', content_type='text/html')},
                              cached_sources=[{'url': url, 'body': 'const x=%d;' % i, 'complete': True} for i, url in enumerate(urls)])
        self.assertEqual(result['files_count'], 4)
        rows = self.corpus.list_files('https://app.test/')
        self.assertEqual(len(set(row['path'] for row in rows)), 4)
        for row in rows:
            self.assertTrue(os.path.realpath(row['path']).startswith(self.root + os.sep))
            self.assertTrue(row['path'].endswith('.js'))

    def test_partial_responses_html_and_json_never_become_source_files(self):
        routes = {'https://app.test/': response('<script src="/short.js"></script><script src="/login.js"></script><script src="/data.js"></script>', content_type='text/html'),
                  'https://app.test/short.js': response('var incomplete=', body_complete=False),
                  'https://app.test/login.js': response('<html>Login</html>', content_type='text/html'),
                  'https://app.test/data.js': response('{"data": 1}', content_type='application/json')}
        result = self.collect(routes)
        self.assertEqual(result['files_count'], 0)
        self.assertEqual(len(result['failures']), 3)
        self.assertFalse(result['discovery_exhausted'])

    def test_limit_and_cancel_retain_completed_files(self):
        routes = {'https://app.test/': response('<script src="/a.js"></script><script src="/b.js"></script>', content_type='text/html'),
                  'https://app.test/a.js': response('var a=1;'), 'https://app.test/b.js': response('var b=2;')}
        result = self.collect(routes, max_files=1)
        self.assertEqual(result['files_count'], 1)
        self.assertIn('max_files', result['limits_reached'])
        self.calls = []
        stop = [False]
        def progress(message):
            if message.startswith('Saved '):
                stop[0] = True
        result = self.collect(routes, cancel_check=lambda: stop[0], progress=progress)
        self.assertTrue(result['stopped'])
        self.assertEqual(result['files_count'], 1)
        self.assertNotIn('https://app.test/b.js', self.calls)

    def test_size_and_page_limits_are_explicit(self):
        routes = {'https://app.test/': response('<a href="/second">next</a><script src="/a.js"></script>', content_type='text/html'),
                  'https://app.test/a.js': response('1234567890')}
        result = self.collect(routes, max_pages=1, max_bytes=5)
        self.assertEqual(result['files_count'], 0)
        self.assertEqual(set(result['limits_reached']), set(['max_pages', 'max_bytes']))
        self.assertNotIn('https://app.test/second', self.calls)

    def test_rerun_preserves_versions_but_removes_stale_membership(self):
        routes = {'https://app.test/': response('<script src="/a.js"></script><script src="/old.js"></script>', content_type='text/html'),
                  'https://app.test/a.js': response('var a=1;'), 'https://app.test/old.js': response('var old=1;')}
        self.collect(routes)
        previous = self.corpus.list_files('https://app.test/')
        routes['https://app.test/']['body'] = '<script src="/a.js"></script>'
        routes['https://app.test/a.js']['body'] = 'var a=2;'
        self.collect(routes)
        fresh = self.corpus.list_files('https://app.test/')
        self.assertEqual(len(fresh), 1)
        self.assertTrue(all(os.path.isfile(row['path']) for row in previous))
        self.assertNotIn(fresh[0]['id'], [row['id'] for row in previous])
        self.assertEqual(self.corpus.read_file('https://app.test/', previous[0]['id'])['error'], 'unknown_file_id')

    def test_source_read_is_verified_and_paginated(self):
        self.collect({'https://app.test/': response('<html></html>', content_type='text/html')},
                     cached_sources=[{'url': 'https://app.test/a.js', 'body': 'one\ntwo\nthree\n', 'complete': True}])
        row = self.corpus.list_files('https://app.test/')[0]
        result = self.corpus.read_file('https://app.test/', row['id'], offset=4, limit=3)
        self.assertEqual(result['content'], 'two')
        self.assertEqual(result['line_start'], 2)
        self.assertEqual(result['next_offset'], 7)
        with open(row['path'], 'wb') as handle:
            handle.write(b'corrupted')
        self.assertEqual(self.corpus.read_file('https://app.test/', row['id'])['error'], 'source_integrity_mismatch')

    def test_initial_scope_and_cached_origin_are_enforced(self):
        result = self.collect({}, in_scope=lambda url: False)
        self.assertFalse(result['ok'])
        self.assertEqual(self.calls, [])
        result = self.collect({'https://app.test/': response('<html></html>', content_type='text/html')},
                              cached_sources=[{'url': 'https://cdn.test/a.js', 'body': 'var no=1;', 'complete': True},
                                              {'url': 'https://app.test/short.js', 'body': 'broken', 'complete': False}])
        self.assertEqual(result['files_count'], 0)
        self.assertEqual(result['failures'][0]['error'], 'incomplete_cached_source')

    def test_url_validation(self):
        self.assertEqual(canonical_url('HTTPS://APP.TEST:443/a.js?q=1#fragment'), 'https://app.test/a.js?q=1')
        for value in ('file:///tmp/a.js', 'http://user:pass@app.test/a.js', 'https://app.test/\r\nx', 'https://app.test:xyz/a', 'https://app.test\\@evil.test/a', 'https://app.test:0/a', 'https://app.test:70000/a', 'https://app.test/a b.js', 'https://app. test/a'):
            self.assertRaises(ValueError, canonical_url, value)

    def test_tampered_manifest_cannot_read_outside_site(self):
        result = self.collect({'https://app.test/': response('<html></html>', content_type='text/html')},
                              cached_sources=[{'url': 'https://app.test/a.js', 'body': 'var a=1;', 'complete': True}])
        with open(result['manifest_path'], 'rb') as handle:
            manifest = json.loads(handle.read().decode('utf-8'))
        manifest['files'][0]['path'] = os.path.join(self.root, 'outside.js')
        with open(result['manifest_path'], 'wb') as handle:
            handle.write(json.dumps(manifest).encode('utf-8'))
        self.assertRaises(ValueError, self.corpus.list_files, 'https://app.test/')

    def test_page_limit_counts_failures_and_non_html_responses(self):
        routes = {'https://app.test/': response('<a href="/missing">missing</a><a href="/json">json</a><a href="/more">more</a>', content_type='text/html'),
                  'https://app.test/json': response('{}', content_type='application/json')}
        result = self.collect(routes, max_pages=3)
        self.assertEqual(result['pages'], 3)
        self.assertEqual(result['html_pages'], 1)
        self.assertEqual(len(self.calls), 3)
        self.assertNotIn('https://app.test/more', self.calls)
        self.assertIn('max_pages', result['limits_reached'])

    def test_cached_sources_require_explicit_completeness_and_reject_html_fragments(self):
        result = self.collect({'https://app.test/': response('<html></html>', content_type='text/html')},
                              cached_sources=[{'url': 'https://app.test/missing.js', 'body': 'var no=1;'},
                                              {'url': 'https://app.test/head.js', 'body': '<head>login</head>', 'complete': True},
                                              {'url': 'https://app.test/body.js', 'body': '<body>login</body>', 'complete': True},
                                              {'url': 'https://app.test/empty.js', 'body': '', 'complete': True}])
        self.assertEqual(result['files_count'], 1)
        self.assertEqual(result['failure_count'], 3)
        self.assertEqual(self.corpus.list_files('https://app.test/')[0]['size'], 0)

    def test_diagnostic_lists_are_bounded_but_counts_are_exact(self):
        html = '<html>' + ''.join('<script src="https://evil.test/%d.js"></script>' % i for i in range(250)) + '</html>'
        result = self.collect({'https://app.test/': response(html, content_type='text/html')})
        self.assertEqual(result['skipped_count'], 250)
        self.assertEqual(len(result['skipped']), 100)
        self.assertTrue(result['diagnostics_truncated'])


if __name__ == '__main__':
    unittest.main()

# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from BurpAI_v4_Website import WebsiteCorpus

SITE = 'https://app.test/'


class NavigationTests(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix='burpai-navigation-')
        self.corpus = WebsiteCorpus(self.root)

    def tearDown(self):
        shutil.rmtree(self.root)

    def save(self, sources):
        def fetch(url):
            return {'ok': True, 'status': 200 if url == SITE else 404,
                    'body': '<html></html>', 'body_complete': True,
                    'headers': ['Content-Type: text/html']}
        rows = [{'url': SITE + name, 'body': source, 'complete': True}
                for name, source in sources.items()]
        self.corpus.collect(SITE, fetch, lambda url: url.startswith(SITE), cached_sources=rows)
        return dict((row['url'][len(SITE):], row) for row in self.corpus.list_files(SITE))

    def test_inclusive_lines_50_to_150_keep_unicode_crlf(self):
        lines = ['const n%d = "\u017b\u00f3\u0142w";\r\n' % i for i in range(1, 201)]
        row = self.save({'a.js': ''.join(lines)})['a.js']
        result = self.corpus.read_lines(SITE, row['id'], 50, 150)
        self.assertTrue(result['ok'])
        self.assertEqual(''.join(lines[49:150]), result['content'])
        self.assertEqual((50, 150), (result['line_start'], result['line_end']))
        self.assertFalse(result['partial'])
        self.assertEqual(len(''.join(lines[:49])), result['offset'])

    def test_short_file_clamps_end_and_invalid_ranges_fail(self):
        row = self.save({'a.js': 'a();\nb();'})['a.js']
        result = self.corpus.read_lines(SITE, row['id'], 1, 150)
        self.assertTrue(result['range_clamped'])
        self.assertEqual(2, result['line_end'])
        for start, end in ((0, 5), (2, 1), (-1, 2), (3, 4), ('x', 5)):
            self.assertFalse(self.corpus.read_lines(SITE, row['id'], start, end)['ok'])
        self.assertFalse(self.corpus.read_lines(SITE, 'missing', 1, 2)['ok'])

    def test_huge_minified_line_continuation_is_exact_and_bounded(self):
        source = 'x();\n' + 'a' * 35000 + ';\nend();'
        row = self.save({'a.js': source})['a.js']
        parts, offset = [], None
        while True:
            result = self.corpus.read_lines(SITE, row['id'], 2, 2, max_chars=5000, offset=offset)
            self.assertTrue(result['ok'])
            self.assertLessEqual(len(result['content']), 5000)
            self.assertEqual((2, 2), (result['line_start'], result['line_end']))
            parts.append(result['content'])
            if not result['more']:
                break
            self.assertTrue(result['partial_end_line'])
            offset = result['next_offset']
        self.assertEqual('a' * 35000 + ';\n', ''.join(parts))
        self.assertFalse(self.corpus.read_lines(SITE,row['id'],2,2,offset=0)['ok'])
        self.assertFalse(self.corpus.read_lines(SITE,row['id'],2,2,offset=len(source)-len('end();'))['ok'])
        self.assertFalse(self.corpus.read_lines(SITE,row['id'],2,2,offset=len(source))['ok'])

    def test_single_cr_newlines_and_empty_source(self):
        rows = self.save({'cr.js': 'first\rsecond\rthird', 'empty.js': ''})
        result = self.corpus.read_lines(SITE,rows['cr.js']['id'],2,2)
        self.assertEqual('second\r', result['content'])
        result = self.corpus.read_lines(SITE,rows['empty.js']['id'],1,1)
        self.assertTrue(result['ok'])
        self.assertEqual('', result['content'])

    def test_tampered_sources_never_return_navigation_content(self):
        row = self.save({'a.js': 'function login() {}'})['a.js']
        with open(row['path'],'wb') as handle:
            handle.write(b'changed();')
        self.assertEqual('source_integrity_mismatch', self.corpus.read_lines(SITE,row['id'])['error'])
        self.assertFalse(self.corpus.outline(SITE,row['id'])['ok'])
        self.assertEqual([], self.corpus.find_references(SITE,'changed')['results'])

    def test_outline_finds_definitions_not_comments_or_string_examples(self):
        source = ('// function fake() {}\nconst text="class Fake {}";\n'
                  'export async function login(user) {}\nclass Session {}\n'
                  'const refresh = async (token) => token;\nlet old = function() {};\n'
                  'const simple = x => x;')
        row = self.save({'a.js':source})['a.js']
        result = self.corpus.outline(SITE,row['id'],limit=2)
        self.assertEqual(['login','Session'],[r['name'] for r in result['symbols']])
        self.assertTrue(result['more'])
        rest = self.corpus.outline(SITE,row['id'],offset=result['next_offset'])
        self.assertEqual(['refresh','old','simple'],[r['name'] for r in rest['symbols']])
        for item in result['symbols'] + rest['symbols']:
            self.assertTrue(source[item['offset']:].startswith(item['name']))

    def test_related_imports_have_bidirectional_current_ids_and_missing_targets(self):
        rows = self.save({'main.js':"import {login} from './auth.js?v=2'; import('./missing.js'); import lib from 'pkg';",
                          'auth.js?v=2':'export function login() {}',
                          'auth.js?v=1':'export function oldLogin() {}'})
        result = self.corpus.related_files(SITE,rows['main.js']['id'])
        auth = next(r for r in result['outgoing'] if r['target_url'] and 'auth.js' in r['target_url'])
        self.assertEqual(rows['auth.js?v=2']['id'],auth['target_file_id'])
        self.assertEqual(2,len([r for r in result['outgoing'] if r['missing']]))
        incoming = self.corpus.related_files(SITE,rows['auth.js?v=2']['id'])['incoming']
        self.assertEqual(rows['main.js']['id'],incoming[0]['source_file_id'])
        self.assertEqual([],self.corpus.related_files(SITE,rows['auth.js?v=1']['id'])['incoming'])

    def test_related_comment_imports_are_ignored(self):
        rows = self.save({'a.js':"// import './b.js';\n/* import('./b.js'); */\nconst x=1;",'b.js':'b();'})
        self.assertEqual([],self.corpus.related_files(SITE,rows['a.js']['id'])['outgoing'])

    def test_reference_boundaries_pagination_and_source_lines(self):
        rows = self.save({'a.js':'function login() {}\nlogin(); logins(); $login();\n',
                          'b.js':'login(); login();'})
        result = self.corpus.find_references(SITE,'login',limit=2)
        self.assertEqual(4,result['total'])
        self.assertEqual([1,2],[r['line'] for r in result['results']])
        self.assertTrue(result['more'])
        rest = self.corpus.find_references(SITE,'login',offset=result['next_offset'],limit=2)
        self.assertEqual([rows['b.js']['id']]*2,[r['file_id'] for r in rest['results']])
        self.assertFalse(rest['more'])
        self.assertFalse(self.corpus.find_references(SITE,'login()')['ok'])

    def test_scope_allowlist_is_applied_before_file_read(self):
        rows = self.save({'a.js':"import './b.js'; login();", 'b.js':'login();'})
        original = self.corpus._navigation_source
        calls=[]
        def checked(row):
            calls.append(row['id'])
            self.assertNotEqual(rows['b.js']['id'],row['id'])
            return original(row)
        self.corpus._navigation_source=checked
        allowed=[rows['a.js']['id']]
        result=self.corpus.find_references(SITE,'login',allowed_ids=allowed)
        self.assertEqual(1,result['total'])
        related=self.corpus.related_files(SITE,rows['a.js']['id'],allowed_ids=allowed)
        self.assertTrue(related['outgoing'][0]['missing'])
        self.assertEqual([rows['a.js']['id']]*2,calls)

    def test_navigation_cancellation_reports_stopped(self):
        row=self.save({'a.js':'function login() {}\nlogin();'})['a.js']
        cancel=lambda:True
        self.assertTrue(self.corpus.outline(SITE,row['id'],cancel_check=cancel)['stopped'])
        self.assertTrue(self.corpus.related_files(SITE,row['id'],cancel_check=cancel)['stopped'])
        self.assertTrue(self.corpus.find_references(SITE,'login',cancel_check=cancel)['stopped'])


if __name__ == '__main__':
    unittest.main()

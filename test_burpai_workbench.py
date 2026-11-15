# -*- coding: utf-8 -*-
"""Verify evidence navigation and Repeater handoff without sending requests."""
from __future__ import unicode_literals
import hashlib
import os
import sys
import threading
import tempfile
import shutil
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_burpai_website_integration import (extension_namespace, load_function,
                                            FakeURL, FakeInfo, response)
from BurpAI_v4_Website import WebsiteCorpus


class Service(object):
    def __init__(self, url): self.url = FakeURL(url)
    def getHost(self): return self.url.getHost()
    def getPort(self): return self.url.getPort() if self.url.getPort() != -1 else (443 if self.getProtocol() == 'https' else 80)
    def getProtocol(self): return self.url.getProtocol()


class Item(object):
    def __init__(self, url, method='GET', marker='one', status=200):
        self.url, self.method = url, method
        parsed = FakeURL(url)
        self.raw = ('%s %s HTTP/1.1\r\nHost: %s\r\nX-Fixture: %s\r\n\r\n' % (
            method, parsed.getPath() or '/', parsed.getHost(), marker)).encode('latin-1')
        self.resp = response('fixture', status=status)
    def getRequest(self): return self.raw
    def getResponse(self): return self.resp
    def getHttpService(self): return Service(self.url)


class RequestInfo(object):
    def __init__(self, item): self.item = item
    def getUrl(self): return FakeURL(self.item.url)
    def getMethod(self): return self.item.method


class Helpers(object):
    def analyzeRequest(self, item): return RequestInfo(item)
    def analyzeResponse(self, raw): return FakeInfo(raw)
    def bytesToString(self, raw): return raw.decode('latin-1')


class Callbacks(object):
    def __init__(self, items): self.items, self.repeater, self.sent = items, [], []
    def getProxyHistory(self): return list(self.items)
    def isInScope(self, url): return url.getHost() in ('example.test', 'cdn.test')
    def getSiteMap(self, prefix): return []
    def sendToRepeater(self, *args): self.repeater.append(args)
    def makeHttpRequest(self, *args):
        self.sent.append(args)
        raise AssertionError('Navigation must not send a network request')


class WorkbenchTrafficTests(unittest.TestCase):
    def setUp(self):
        self.ns = extension_namespace()
        self.ns.update({'hashlib': hashlib, 'threading': threading})
        load_function('_bounded_int', self.ns)
        names = ('_website_origin', '_burp_request_hash', '_tool_burp_find_traffic', '_tool_burp_open_repeater')
        methods = dict((name, load_function(name, self.ns, 'BurpExtender')) for name in names)
        self.obj = type('WorkbenchAdapter', (object,), methods)()
        self.obj.helpers = Helpers()
        self.items = [Item('https://example.test/api/session', marker='old'),
                      Item('https://example.test.evil/api/session'),
                      Item('http://example.test/api/session'),
                      Item('https://example.test:8443/api/session'),
                      Item('https://example.test/api/profile'),
                      Item('https://example.test/api/session', marker='new')]
        self.obj.callbacks = Callbacks(self.items)
        self.obj.kill_switch = self.obj.stop_agent_flag = False
        self.obj._website_cancelled = lambda: self.obj.kill_switch or self.obj.stop_agent_flag
        self.obj._website_in_scope = lambda url: self.obj.callbacks.isInScope(FakeURL(url))
        self.obj._safe_ui = lambda fn: fn()
        self.obj._log_debug = lambda message: None

    def args(self, index=5):
        item = self.obj.callbacks.items[index]
        return {'history_index': index, 'expected_url': item.url,
                'expected_request_sha256': hashlib.sha256(item.raw).hexdigest()}

    def test_traffic_matches_exact_origin_and_retains_history_indices(self):
        result = self.obj._tool_burp_find_traffic({'url': 'https://example.test/', 'limit': 50})
        self.assertTrue(result['ok'])
        self.assertEqual([5, 4, 0], [row['history_index'] for row in result['items']])
        for row in result['items']:
            item = self.items[row['history_index']]
            self.assertEqual(hashlib.sha256(item.raw).hexdigest(), row['request_sha256'])
        self.assertEqual([], self.obj.callbacks.sent)

    def test_traffic_pagination_uses_exclusive_history_cursor(self):
        first = self.obj._tool_burp_find_traffic({'url': 'https://example.test/', 'limit': 1})
        self.assertTrue(first['more'])
        second = self.obj._tool_burp_find_traffic({'url': 'https://example.test/', 'limit': 1,
                                                'before_index': first['next_before_index']})
        self.assertEqual(5, first['items'][0]['history_index'])
        self.assertEqual(4, second['items'][0]['history_index'])

    def test_traffic_query_filters_url_without_searching_secret_headers(self):
        result = self.obj._tool_burp_find_traffic({'url': 'https://example.test/', 'query': '/api/session'})
        self.assertEqual([5, 0], [row['history_index'] for row in result['items']])
        result = self.obj._tool_burp_find_traffic({'url': 'https://example.test/', 'query': 'X-Fixture'})
        self.assertEqual([], result['items'])

    def test_out_of_scope_origin_is_rejected(self):
        result = self.obj._tool_burp_find_traffic({'url': 'https://unrelated.test/'})
        self.assertFalse(result['ok'])

    def test_repeater_copies_exact_captured_request_without_sending(self):
        result = self.obj._tool_burp_open_repeater(self.args())
        self.assertTrue(result['ok'])
        self.assertEqual(1, len(self.obj.callbacks.repeater))
        host, port, tls, raw, label = self.obj.callbacks.repeater[0]
        self.assertEqual(('example.test', 443, True), (host, port, tls))
        self.assertEqual(self.items[5].raw, raw)
        self.assertEqual([], self.obj.callbacks.sent)

    def test_repeater_rejects_same_url_with_changed_request(self):
        args = self.args()
        self.obj.callbacks.items[5] = Item(args['expected_url'], marker='replacement')
        result = self.obj._tool_burp_open_repeater(args)
        self.assertFalse(result['ok'])
        self.assertEqual([], self.obj.callbacks.repeater)

    def test_repeater_rejects_url_mismatch_missing_hash_and_bad_index(self):
        args = self.args()
        for changes in ({'expected_url': 'https://example.test/other'},
                        {'expected_request_sha256': ''}, {'history_index': -1},
                        {'history_index': 999}):
            request = dict(args); request.update(changes)
            self.assertFalse(self.obj._tool_burp_open_repeater(request)['ok'])
        self.assertEqual([], self.obj.callbacks.repeater)

    def test_repeater_rechecks_scope_and_cancellation(self):
        args = self.args()
        self.obj.callbacks.isInScope = lambda url: False
        self.assertFalse(self.obj._tool_burp_open_repeater(args)['ok'])
        self.obj.callbacks.isInScope = lambda url: True
        self.obj.kill_switch = True
        self.assertFalse(self.obj._tool_burp_open_repeater(args)['ok'])
        self.assertEqual([], self.obj.callbacks.repeater)


class Field(object):
    def __init__(self, value=''): self.value = value
    def setText(self, value): self.value = value
    def getText(self): return self.value
    def setCaretPosition(self, unused): pass
    def setSelectedIndex(self, value): self.selected = value


class Table(object):
    def __init__(self): self.rows, self.selected = [], -1
    def getModel(self): return self
    def setRowCount(self, count): self.rows = self.rows[:count]
    def addRow(self, values): self.rows.append(values)
    def getSelectedRow(self): return self.selected
    def convertRowIndexToModel(self, row): return row


class SourceWorkbenchTests(unittest.TestCase):
    def setUp(self):
        ns = extension_namespace(); ns['os'] = os
        names = ('_website_navigation', '_tool_website_read_lines', '_website_selected_row',
                 '_website_open_selected', '_website_nav_history', '_website_continue_source', '_website_present')
        methods = dict((name, load_function(name, ns, 'BurpExtender')) for name in names)
        self.obj = type('SourceAdapter', (object,), methods)()
        self.obj.ui = type('Ui', (object,), {})()
        for name in ('website_area', 'website_status', 'website_reader_tabs', 'website_workspace_tabs',
                     'website_source', 'website_source_title', 'website_url', 'website_file',
                     'website_start_line', 'website_end_line', 'website_offset'):
            setattr(self.obj.ui, name, Field())
        self.obj.ui.website_results = Table()
        self.calls = []
        self.obj._website_ui_run = lambda *args, **kw: self.calls.append((args, kw))
        self.obj.website_lock = threading.RLock()
        self.obj._website_in_scope = lambda url: FakeURL(url).getHost() == 'example.test'
        self.obj._website_cancelled = lambda: False
        self.obj._website_highlight_source = lambda *args: None

    def test_semantic_selection_uses_saved_site_and_exact_read_arguments(self):
        args = {'url': 'https://example.test/'}
        jump = {'url': args['url'], 'file_id': 'session', 'start_line': 50, 'end_line': 150, 'offset': 960}
        result = {'ok': True, 'results': [{'file_id': 'session', 'url': args['url'] + 'session.js',
                  'start_line': 50, 'offset': 960, 'read_lines': jump}]}
        self.obj._website_present('search', args, result, '')
        self.assertEqual(1, len(self.obj.ui.website_results.rows))
        self.obj.ui.website_results.selected = 0
        self.obj.ui.website_url.setText('https://other.test/')
        self.obj._website_open_selected()
        self.assertEqual(('read_lines', jump), self.calls[-1][0])

    def test_symbol_and_reference_selection_jumps_to_exact_location(self):
        for action, key in (('outline', 'symbols'), ('references', 'results')):
            result = {'ok': True, key: [{'file_id': 'session', 'url': 'https://example.test/session.js',
                                        'line': 83, 'offset': 1650, 'name': 'refreshSession'}]}
            self.obj._website_present(action, {'url': 'https://example.test/'}, result, '')
            self.obj.ui.website_results.selected = 0
            self.obj._website_open_selected()
            args = self.calls[-1][0][1]
            self.assertEqual(83, args['start_line'])
            self.assertEqual(1650, args['offset'])

    def test_read_range_presentation_history_and_continuation(self):
        first = {'url': 'https://example.test/', 'file_id': 'one', 'start_line': 50, 'end_line': 150}
        result = {'ok': True, 'content': 'one\ntwo\n', 'line_start': 50, 'line_end': 51,
                  'offset': 900, 'end_offset': 908, 'next_offset': None, 'path': 'session.js'}
        self.obj._website_present('read_lines', first, result, '')
        lines = self.obj.ui.website_source.value.splitlines()
        self.assertEqual(2, len(lines))
        self.assertTrue(lines[0].lstrip().startswith('50'))
        self.assertTrue(lines[1].lstrip().startswith('51'))
        second = dict(first, file_id='two', start_line=10, end_line=20)
        partial = dict(result, content='const value =', line_start=10, line_end=10, next_offset=150, partial=True)
        self.obj._website_present('read_lines', second, partial, '')
        self.obj._website_continue_source()
        self.assertEqual(dict(second, offset=150), self.calls[-1][0][1])
        self.obj._website_nav_history(-1)
        self.assertEqual(('read_lines', first), self.calls[-1][0])
        self.assertEqual({'history_index': 0}, self.calls[-1][1])
        self.obj._website_present('read_lines', first, result, '', history_index=0)
        self.obj._website_nav_history(1)
        self.assertEqual(('read_lines', second), self.calls[-1][0])
        self.assertEqual(2, len(self.obj._website_navigation_history))

    def test_real_corpus_line_50_to_150_through_extension_tool(self):
        folder = tempfile.mkdtemp(prefix='burpai-workbench-lines-')
        try:
            corpus = WebsiteCorpus(folder)
            source = ''.join('const n%d = %d;\n' % (n, n) for n in range(1, 201))
            corpus.collect('https://example.test/app.js',
                lambda url: {'ok': True, 'status': 200, 'body_complete': True, 'body': source,
                             'headers': ['Content-Type: application/javascript']}, lambda url: True)
            files = corpus.list_files('https://example.test/')
            self.obj._website_context = lambda args: ('https://example.test/', corpus, None)
            self.obj._website_current_files = lambda c, url: files
            result = self.obj._tool_website_read_lines({'file_id': files[0]['id'], 'start_line': 50, 'end_line': 150})
            self.assertTrue(result['ok'])
            self.assertEqual(101, len(result['content'].splitlines()))
            self.assertTrue(result['content'].startswith('const n50 = 50;'))
            self.assertTrue(result['content'].endswith('const n150 = 150;\n'))
        finally:
            shutil.rmtree(folder)


if __name__ == '__main__':
    unittest.main()

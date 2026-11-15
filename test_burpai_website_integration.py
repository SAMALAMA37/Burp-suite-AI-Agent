# -*- coding: utf-8 -*-
"""Exercise the real Burp adapters without a Burp installation or network.

The portable extraction harness also runs on the shipped Jython 2.7 runtime.
It uses actual extension function bodies; only Java/Burp I/O is replaced.
"""
from __future__ import unicode_literals
import ast
import gzip
import math
import io
import os
import re
import shutil
import sys
import tempfile
import textwrap
import threading
import unittest
import zlib
try:
    from urllib.parse import urlparse
except ImportError:
    from urlparse import urlparse


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path: sys.path.insert(0, ROOT)
with io.open(os.path.join(ROOT, 'BurpAI_v4_Extension.py'), encoding='utf-8') as handle:
    SOURCE = handle.read()
TREE = ast.parse(SOURCE.encode('utf-8'))
LINES = SOURCE.splitlines(True)


def load_function(name, namespace, owner=None):
    nodes = TREE.body
    owner_end = len(LINES)
    if owner:
        position, container = next((i,node) for i,node in enumerate(nodes)
                                  if isinstance(node,ast.ClassDef) and node.name == owner)
        if position + 1 < len(nodes): owner_end = nodes[position + 1].lineno - 1
        nodes = container.body
    for i, node in enumerate(nodes):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            end = nodes[i + 1].lineno - 1 if i + 1 < len(nodes) else owner_end
            # End at the next method/module declaration, including its comments.
            selected = list(LINES[node.lineno - 1:end])
            while selected and (not selected[-1].strip() or selected[-1].lstrip().startswith('#')):
                selected.pop()
            code = textwrap.dedent(''.join(selected))
            eval(compile(code, '<extension:%s>' % name, 'exec'), namespace)
            return namespace[name]
    raise AssertionError('Extension function missing: %s' % name)


class FakeURL(object):
    def __init__(self, url):
        self.url = url
        self.parsed = urlparse(url)
    def getProtocol(self): return self.parsed.scheme
    def getHost(self): return self.parsed.hostname
    def getPort(self): return self.parsed.port or -1
    def getPath(self): return self.parsed.path
    def getQuery(self): return self.parsed.query
    def getUserInfo(self): return self.parsed.username
    def __str__(self): return self.url


class FakeInfo(object):
    def __init__(self, raw):
        self.offset = raw.index(b'\r\n\r\n') + 4
        self.headers = raw[:self.offset - 4].decode('latin-1').split('\r\n')
    def getBodyOffset(self): return self.offset
    def getHeaders(self): return self.headers
    def getStatusCode(self): return int(self.headers[0].split()[1])


class FakeHelpers(object):
    def analyzeResponse(self, raw): return FakeInfo(raw)
    def bytesToString(self, raw): return raw.decode('latin-1')
    def stringToBytes(self, value): return value.encode('latin-1')
    def buildHttpService(self, host, port, tls): return (host, port, tls)


def response(body=b'const x = 1;', headers=None, status=200, add_length=True):
    if not isinstance(body, bytes): body = body.encode('utf-8')
    headers = list(headers or ['Content-Type: application/javascript'])
    if add_length and not any(h.lower().startswith('content-length:') for h in headers):
        headers.append('Content-Length: %d' % len(body))
    return ('HTTP/1.1 %d Test\r\n%s\r\n\r\n' % (status, '\r\n'.join(headers))).encode('latin-1') + body


class Clock(object):
    def __init__(self): self.now = 123456.0
    def time(self): return self.now
    def sleep(self, seconds): self.now += seconds


def extension_namespace():
    try:
        text_type, string_types = unicode, basestring
    except NameError:
        text_type, string_types = str, str
    namespace = {'re': re, 'gzip': gzip, 'zlib': zlib, 'BytesIO': io.BytesIO,
                 '_text_type': text_type, '_string_types': string_types,
                 '_JS_SOURCE_LIMIT': 32 * 1024 * 1024, 'URL': FakeURL,
                 'time': Clock(), 'math': math}
    for name in ('_safe_text', '_validate_js_text', '_decode_full_js_response', '_decode_burp_body'):
        load_function(name, namespace)
    return namespace


class DecodeTests(unittest.TestCase):
    def setUp(self):
        self.ns = extension_namespace()
        self.decode = self.ns['_decode_full_js_response']
        self.helpers = FakeHelpers()

    def test_preserves_complete_unicode_source(self):
        source = 'const name = "za\u017c\u00f3\u0142\u0107 \U0001f600";\n'
        result = self.decode(self.helpers, response(source))
        self.assertEqual(source, result['body'])
        self.assertTrue(result['body_complete'])
        self.assertEqual(len(source.encode('utf-8')), result['decoded_bytes'])

    def test_html_is_only_allowed_for_website_decoder(self):
        raw = response('<html><script src="/app.js"></script></html>', ['Content-Type: text/html'])
        with self.assertRaises(ValueError): self.decode(self.helpers, raw)
        result = self.decode(self.helpers, raw, validate_js=False)
        self.assertIn('<script', result['body'])
        self.assertTrue(result['body_complete'])

    def test_partial_status_and_content_range_are_rejected(self):
        for raw in (response(status=206), response(status=304),
                    response(headers=['Content-Range: bytes 0-11/90']),
                    response(headers=['Content-Length: 999'])):
            with self.assertRaises(ValueError): self.decode(self.helpers, raw, validate_js=False)

    def test_invalid_utf8_and_unsupported_compression_are_rejected(self):
        for raw in (response(b'\xff\xfe'), response(headers=['Content-Encoding: br'])):
            with self.assertRaises((ValueError, UnicodeError)):
                self.decode(self.helpers, raw, validate_js=False)

    def test_chunked_source_is_reconstructed_and_partial_chunk_rejected(self):
        body = b'const x = 1;'
        encoded = b'%x\r\n' % len(body) + body + b'\r\n0\r\n\r\n'
        raw = response(encoded, ['Transfer-Encoding: chunked'], add_length=False)
        self.assertEqual(body.decode('utf-8'), self.decode(self.helpers, raw)['body'])
        with self.assertRaises(ValueError):
            self.decode(self.helpers, response(encoded[:-3], ['Transfer-Encoding: chunked'], add_length=False))

    def test_gzip_and_deflate_decode_without_preview_truncation(self):
        body = b'const x = 1;' * 3000
        zipped = io.BytesIO()
        with gzip.GzipFile(fileobj=zipped, mode='wb') as stream: stream.write(body)
        for coding, encoded in (('gzip', zipped.getvalue()), ('deflate', zlib.compress(body))):
            raw = response(encoded, ['Content-Encoding: ' + coding])
            self.assertEqual(body.decode('utf-8'), self.decode(self.helpers, raw)['body'])

    def test_decoded_limit_rejects_compression_bomb(self):
        self.ns['_JS_SOURCE_LIMIT'] = 128
        raw = response(zlib.compress(b'x' * 5000), ['Content-Encoding: deflate'])
        with self.assertRaises(ValueError): self.decode(self.helpers, raw, validate_js=False)


class Callbacks(object):
    def __init__(self, raw): self.raw, self.calls = raw, []
    def makeHttpRequest(self, service, request):
        self.calls.append((service, request))
        raw = self.raw
        class Message(object):
            def getResponse(self): return raw
        return Message()


class Policy(object):
    def __init__(self, allowed=True): self.allowed, self.calls = allowed, []
    def check(self, url, method, **kwargs):
        self.calls.append((url, method, kwargs))
        if kwargs.get('cancelled'): return {'ok': False, 'error': 'request_cancelled'}
        return {'ok': True} if self.allowed else {'ok': False, 'error': 'outside_burp_scope'}


class Store(object):
    def get_rpm_limit(self): return 120


class DispatchTests(unittest.TestCase):
    def setUp(self):
        self.ns = extension_namespace()
        dispatch = load_function('_dispatch_request', self.ns, 'BurpExtender')
        self.adapter_type = type('Adapter', (object,), {'_dispatch_request': dispatch,
                        '_safe_ui': lambda self, fn: None})

    def adapter(self, raw=None, allowed=True):
        obj = self.adapter_type()
        obj.helpers, obj.callbacks = FakeHelpers(), Callbacks(raw or response())
        obj.store, obj.policy = Store(), Policy(allowed)
        obj.kill_switch, obj.stop_agent_flag, obj.send_times = False, False, []
        return obj

    def test_collection_is_evenly_paced_without_consuming_budget_on_wait(self):
        obj = self.adapter()
        first = obj._dispatch_request({'url':'https://example.test/a.js'},website_source=True)
        self.assertTrue(first['ok'])
        second = obj._dispatch_request({'url':'https://example.test/b.js'},website_source=True)
        self.assertEqual('collection_pacing',second['reason'])
        self.assertAlmostEqual(0.5,second['retry_after'])
        self.assertEqual(1,len(obj.callbacks.calls))
        self.assertEqual(1,len(obj.send_times))
        self.ns['time'].sleep(second['retry_after'])
        self.assertTrue(obj._dispatch_request({'url':'https://example.test/b.js'},website_source=True)['ok'])
        self.assertEqual(2,len(obj.callbacks.calls))

    def test_exhausted_shared_budget_returns_exact_countdown_without_sleep(self):
        obj = self.adapter()
        now = self.ns['time'].time()
        obj.send_times = [now-12] * 120
        result = obj._dispatch_request({'url':'https://example.test/a.js'},website_source=True)
        self.assertEqual('request_budget',result['reason'])
        self.assertEqual(48,result['retry_after'])
        self.assertEqual(120,result['requests_in_window'])
        self.assertEqual(now,self.ns['time'].time())
        self.assertEqual([],obj.callbacks.calls)
        self.ns['time'].sleep(48)
        self.assertTrue(obj._dispatch_request({'url':'https://example.test/a.js'},website_source=True)['ok'])

    def test_every_website_request_passes_scope_policy_before_network(self):
        obj = self.adapter(allowed=False)
        result = obj._dispatch_request({'url': 'https://example.test/app.js'}, website_source=True)
        self.assertEqual('outside_burp_scope', result['error'])
        self.assertEqual([], obj.callbacks.calls)
        self.assertEqual(1, len(obj.policy.calls))

    def test_cancelled_collection_does_not_send(self):
        obj = self.adapter()
        obj.stop_agent_flag = True
        result = obj._dispatch_request({'url': 'https://example.test/'}, website_source=True)
        self.assertEqual('request_cancelled', result['error'])
        self.assertEqual([], obj.callbacks.calls)

    def test_website_html_get_is_complete_and_requests_identity_encoding(self):
        source = '<html><script src="app.js"></script></html>'
        obj = self.adapter(response(source, ['Content-Type: text/html']))
        result = obj._dispatch_request({'url': 'https://example.test/'}, body_limit=32000, website_source=True)
        self.assertTrue(result['ok'], result)
        self.assertTrue(result['body_complete'])
        self.assertEqual(source, result['body'])
        self.assertTrue(any('text/html' in h for h in result['headers']))
        request = obj.callbacks.calls[0][1].decode('latin-1')
        self.assertIn('Accept-Encoding: identity', request)
        self.assertTrue(request.startswith('GET / HTTP/1.1\r\n'))

    def test_redirect_headers_reach_collector_without_implicit_follow(self):
        obj = self.adapter(response('', ['Location: https://cdn.test/app.js'], status=302))
        result = obj._dispatch_request({'url': 'https://example.test/'}, website_source=True)
        self.assertTrue(result['ok'], result)
        self.assertEqual(302, result['status'])
        self.assertIn('Location: https://cdn.test/app.js', result['headers'])
        self.assertEqual(1, len(obj.callbacks.calls))

    def test_website_dispatch_rejects_truncated_payload(self):
        obj = self.adapter(response('<html>', ['Content-Type: text/html', 'Content-Length: 999']))
        result = obj._dispatch_request({'url': 'https://example.test/'}, website_source=True)
        self.assertFalse(result['ok'])
        self.assertIn('content_length', result['error'])

    def test_existing_strict_js_mode_still_rejects_html(self):
        obj = self.adapter(response('<html>', ['Content-Type: text/html']))
        result = obj._dispatch_request({'url': 'https://example.test/app.js'}, strict_js=True)
        self.assertFalse(result['ok'])
        self.assertIn('html_response', result['error'])


class CorpusStub(object):
    def __init__(self):
        self.files = [{'id': 'yes', 'url': 'https://example.test/app.js', 'path': 'one.js'},
                      {'id': 'no', 'url': 'https://removed.test/lib.js', 'path': 'two.js'}]
        self.reads, self.collections = [], []
    def list_files(self, url): return self.files
    def site_root(self, url): return 'test-library'
    def read_file(self, *args):
        self.reads.append(args)
        return {'ok': True, 'content': 'const valid = true;'}
    def collect(self, *args, **kwargs):
        self.collections.append((args, kwargs))
        return {'ok': True, 'files_count': 1}


class IndexStub(object):
    def __init__(self): self.index_calls, self.search_calls = [], []
    def index(self, files, **kwargs):
        self.index_calls.append((files, kwargs))
        return {'ok': True, 'mode': 'semantic_hybrid'}
    def search(self, query, files, **kwargs):
        self.search_calls.append((query, files, kwargs))
        return {'ok': True, 'mode': 'semantic_hybrid', 'results': []}


class WebsiteStore(object):
    def _g(self, key, default): return default
    def get_embedding_config(self):
        return {'base_url': 'http://127.0.0.1:11434', 'model': 'embeddinggemma', 'api_key': ''}
    def get_active_model(self): return 'test-chat-model'
    def get_rpm_limit(self): return 120


class WebsiteAdapterTests(unittest.TestCase):
    def setUp(self):
        self.ns = extension_namespace()
        self.ns['threading'] = threading
        load_function('_bounded_int', self.ns)
        names = ('_website_cancelled', '_website_fetch', '_website_cached_sources',
                 '_website_current_files', '_tool_website_collect', '_tool_website_index',
                 '_tool_website_search', '_tool_website_files', '_tool_website_read',
                 '_website_ui_run')
        methods = dict((name, load_function(name, self.ns, 'BurpExtender')) for name in names)
        self.obj = type('WebsiteAdapter', (object,), methods)()
        self.obj.website_lock = threading.RLock()
        self.obj.agent_lock = threading.Lock()
        self.obj.agent_running = False
        self.obj.stop_agent_flag = self.obj.kill_switch = False
        self.obj.store = WebsiteStore()
        self.corpus, self.index = CorpusStub(), IndexStub()
        self.obj._website_context = lambda args: ('https://example.test/', self.corpus, self.index)
        self.obj._website_in_scope = lambda url: urlparse(url).hostname == 'example.test'
        self.obj._website_progress = lambda message: None

    def test_search_uses_only_currently_scoped_saved_files(self):
        result = self.obj._tool_website_search({'query': 'login', 'limit': 999})
        self.assertTrue(result['ok'])
        query, files, kwargs = self.index.search_calls[0]
        self.assertEqual('login', query)
        self.assertEqual(['yes'], [f['id'] for f in files])
        self.assertEqual(20, kwargs['limit'])
        self.assertEqual('http://127.0.0.1:11434', kwargs['config']['base_url'])

    def test_saved_file_cannot_bypass_scope_after_scope_changes(self):
        result = self.obj._tool_website_read({'file_id': 'no'})
        self.assertFalse(result['ok'])
        self.assertEqual([], self.corpus.reads)
        self.assertTrue(self.obj._tool_website_read({'file_id': 'yes'})['ok'])

    def test_file_inventory_pagination_does_not_include_removed_scope(self):
        result = self.obj._tool_website_files({'offset': 0, 'limit': 1})
        self.assertEqual(1, result['total'])
        self.assertEqual('yes', result['files'][0]['id'])
        self.assertFalse(result['more'])

    def test_collect_indexes_saved_files_and_respects_bounds(self):
        self.obj._website_cached_sources = lambda url: []
        result = self.obj._tool_website_collect({'max_pages': -1, 'max_files': 99999})
        self.assertEqual('semantic_hybrid', result['index']['mode'])
        args, kwargs = self.corpus.collections[0]
        self.assertEqual(1, kwargs['max_pages'])
        self.assertEqual(10000, kwargs['max_files'])
        self.assertEqual(['yes'], [f['id'] for f in self.index.index_calls[0][0]])

    def test_only_complete_successful_history_responses_are_collected(self):
        calls = []
        class History(object):
            def iter_js_sources(self, **kwargs):
                calls.append(kwargs)
                return iter([{'ok': True, 'body_complete': True, 'url': 'https://example.test/a.js', 'body': 'a();'},
                             {'ok': True, 'body_complete': False, 'url': 'https://example.test/b.js'},
                             {'ok': False, 'body_complete': True, 'url': 'https://example.test/c.js'}])
        self.obj.history = History()
        sources = list(self.obj._website_cached_sources('https://example.test/'))
        self.assertEqual(1, len(sources))
        self.assertEqual('a();', sources[0]['body'])
        self.assertTrue(sources[0]['complete'])
        self.assertTrue(calls[0]['exact_host'])

    def test_rate_limited_fetch_retries_via_dispatch(self):
        calls = []
        def dispatch(item, **kwargs):
            calls.append((item, kwargs))
            return {'error': 'rate_limit_exceeded'} if len(calls) == 1 else {'ok': True}
        self.obj._dispatch_request = dispatch
        result = self.obj._website_fetch('https://example.test/a.js')
        self.assertTrue(result['ok'])
        self.assertEqual(2, len(calls))
        self.assertTrue(calls[0][1]['website_source'])
        self.assertEqual(32 * 1024 * 1024, calls[0][1]['body_limit'])

    def test_rate_limit_wait_can_be_cancelled(self):
        calls = []
        def dispatch(item, **kwargs):
            calls.append(item)
            self.obj.stop_agent_flag = True
            return {'error': 'rate_limit_exceeded'}
        self.obj._dispatch_request = dispatch
        self.assertEqual('request_cancelled', self.obj._website_fetch('https://example.test/a.js')['error'])
        self.assertEqual(1, len(calls))

    def test_ui_work_runs_on_background_thread_and_releases_run_state(self):
        started, release = threading.Event(), threading.Event()
        caller, worker_thread = threading.current_thread(), []
        class Field(object):
            def __init__(self, value=''): self.value = value
            def getText(self): return self.value
            def setText(self, value): self.value = value
        class Ui(object):
            website_query, website_file, website_offset = Field('login'), Field('yes'), Field('0')
            website_status, website_area = Field(), Field()
            def set_status(self, *args, **kwargs): pass
        self.obj.ui = Ui()
        self.obj._website_save_settings = lambda: {'website_last_url': 'https://example.test/'}
        self.obj._website_format_result = lambda action, result: 'rendered result'
        self.obj._safe_ui = lambda fn: fn()
        def search(args):
            worker_thread.append(threading.current_thread())
            started.set()
            release.wait(2)
            return {'ok': True, 'mode': 'semantic_hybrid'}
        self.obj._tool_website_search = search
        thread = self.obj._website_ui_run('search')
        try:
            self.assertTrue(started.wait(2))
            self.assertIsNot(caller, worker_thread[0])
            self.assertTrue(self.obj.agent_running)
        finally:
            release.set()
            thread.join(3)
        self.assertFalse(thread.is_alive())
        self.assertFalse(self.obj.agent_running)
        self.assertEqual('rendered result', self.obj.ui.website_area.value)

    def test_end_to_end_real_collection_index_search_and_source_read(self):
        from BurpAI_v4_Website import WebsiteCorpus
        from BurpAI_v4_Semantic import SemanticCodeIndex
        directory = tempfile.mkdtemp(prefix='burpai-e2e-', dir=os.path.dirname(__file__))
        try:
            class DeterministicIndex(SemanticCodeIndex):
                def _embed(self, texts, config, cancel_check=None):
                    return [[1.0, 0.0] if 'sessionStorage' in text or 'credentials kept' in text
                            else [0.0, 1.0] for text in texts]
            app_source = ('import "./refresh.js";\n'
                          'export function saveLogin(token) { sessionStorage.setItem("auth", token); }\n')
            fixtures = {
                '/': response('<html><script type="module" src="/app.js"></script>'
                              '<script>const theme="dark";</script></html>', ['Content-Type: text/html']),
                '/app.js': response(app_source),
                '/refresh.js': response('export function renewSession(){ return fetch("/session/refresh"); }\n')}
            class FixtureCallbacks(Callbacks):
                def makeHttpRequest(self, service, request):
                    target = request.decode('latin-1').split(' ', 2)[1]
                    self.raw = fixtures[target]
                    return Callbacks.makeHttpRequest(self, service, request)
            class EmptyHistory(object):
                def iter_js_sources(self, **kwargs): return iter([])
            corpus = WebsiteCorpus(directory)
            index = DeterministicIndex(os.path.join(corpus.site_root('https://example.test/'), 'semantic'))
            self.obj._website_context = lambda args: ('https://example.test/', corpus, index)
            dispatch = load_function('_dispatch_request', self.ns, 'BurpExtender')
            type(self.obj)._dispatch_request = dispatch
            self.obj._safe_ui = lambda fn: None
            self.obj.helpers, self.obj.callbacks = FakeHelpers(), FixtureCallbacks(None)
            self.obj.policy, self.obj.history, self.obj.send_times = Policy(), EmptyHistory(), []
            collected = self.obj._tool_website_collect({'url': 'https://example.test/'})
            self.assertTrue(collected['ok'], collected)
            self.assertEqual(3, collected['files_count'])
            self.assertEqual('semantic_hybrid', collected['index']['mode'])
            self.assertEqual(3, len(self.obj.callbacks.calls))
            search = self.obj._tool_website_search({'query': 'Where are sign-in credentials kept?'})
            self.assertEqual('semantic_hybrid', search['mode'])
            best = search['results'][0]
            self.assertEqual('https://example.test/app.js', best['url'])
            self.assertTrue(os.path.isfile(best['path']))
            self.assertIn('sessionStorage', best['excerpt'])
            original = self.obj._tool_website_read({'file_id': best['file_id'], 'offset': best['offset'],
                                                   'limit': best['end_offset'] - best['offset']})
            self.assertTrue(original['ok'])
            self.assertEqual(best['excerpt'], original['content'])
            self.assertEqual(app_source, original['content'])
            self.assertEqual(3, len(self.obj.callbacks.calls), 'Search/read must not fetch the website again')
        finally:
            directory = os.path.realpath(directory)
            if os.path.dirname(directory) == os.path.realpath(os.path.dirname(__file__)) and os.path.basename(directory).startswith('burpai-e2e-'):
                shutil.rmtree(directory)


if __name__ == '__main__':
    unittest.main()

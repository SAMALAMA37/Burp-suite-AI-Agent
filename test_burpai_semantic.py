# -*- coding: utf-8 -*-
from __future__ import division

import hashlib
import json
import math
import os
import shutil
import sys
import tempfile
import threading
import unittest
try:
    from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
except ImportError:
    from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from BurpAI_v4_Semantic import (SemanticCodeIndex, EmbeddingError, _chunk_source,
                               _normalized_vector, embedding_config, CHUNK_CHARS)
import BurpAI_v4_Semantic as semantic_module


class FakeSemantic(SemanticCodeIndex):
    def __init__(self, root):
        SemanticCodeIndex.__init__(self, root)
        self.calls = []
        self.fail = False
        self.dim = 3

    def _embed(self, texts, config, cancel_check=None):
        self.calls.append(list(texts))
        if self.fail:
            raise EmbeddingError('embedding_server_unavailable')
        if cancel_check and cancel_check():
            raise EmbeddingError('cancelled')
        vectors = []
        for text in texts:
            lower = text.lower()
            if 'login' in lower or 'identity' in lower:
                vector = [1., 0., 0.]
            elif 'theme' in lower or 'colour' in lower:
                vector = [0., 1., 0.]
            else:
                vector = [0., 0., 1.]
            vectors.append(vector[:self.dim])
        return vectors


class SemanticTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='burpai-semantic-test-')
        self.engine = FakeSemantic(os.path.join(self.tmp, 'index'))

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def source(self, name, text):
        path = os.path.join(self.tmp, name)
        raw = text.encode('utf-8')
        with open(path, 'wb') as handle:
            handle.write(raw)
        return {'id': name, 'url': 'https://example.test/' + name, 'path': path,
                'sha256': hashlib.sha256(raw).hexdigest(), 'kind': 'javascript'}

    def test_semantic_match_without_shared_words_and_persistent_cache(self):
        auth = self.source('auth.js', "function login() { return fetch('/session'); }")
        theme = self.source('theme.js', "function theme() { return '#ffffff'; }")
        files = [theme, auth]
        indexed = self.engine.index(files)
        self.assertEqual(indexed['mode'], 'semantic_hybrid')
        self.assertEqual(indexed['embedded'], 2)
        self.assertEqual(len(self.engine.calls), 2)
        fresh = FakeSemantic(self.engine.root)
        fresh.index(files)
        self.assertEqual(fresh.calls, [])
        result = fresh.search('Where is identity established?', files)
        self.assertEqual(result['results'][0]['file_id'], 'auth.js')
        self.assertEqual(result['results'][0]['lexical_score'], 0)
        self.assertEqual(result['mode'], 'semantic_hybrid')
        self.assertEqual(len(fresh.calls), 1)

    def test_membership_and_changed_content_do_not_reuse_old_vectors(self):
        auth = self.source('auth.js', 'login();')
        theme = self.source('theme.js', 'theme();')
        self.engine.index([auth, theme])
        result = self.engine.search('identity', [theme])
        self.assertFalse(any(row['file_id'] == 'auth.js' for row in result['results']))
        # Stale manifest metadata must not give changed bytes an old file ID.
        with open(auth['path'], 'wb') as handle:
            handle.write(b'theme();')
        result = self.engine.search('identity', [auth])
        self.assertEqual(result['results'], [])
        self.assertEqual(result['errors'][0]['error'], 'source_hash_mismatch_recollect_required')
        auth['sha256'] = hashlib.sha256(b'theme();').hexdigest()
        result = self.engine.search('identity', [auth])
        self.assertEqual(result['mode'], 'semantic_hybrid')
        # Changed bytes can legitimately reuse an existing identical blob cache.
        self.assertEqual(result['results'][0]['semantic_score'], 0)
        with open(auth['path'], 'wb') as handle:
            handle.write(b'brandNewFunction();')
        old_sha = auth['sha256']
        auth['sha256'] = hashlib.sha256(b'brandNewFunction();').hexdigest()
        result = self.engine.search('brand new', [auth])
        self.assertEqual(result['mode'], 'lexical')
        self.assertNotEqual(result['results'][0]['sha256'], old_sha)
        self.assertEqual(result['results'][0]['sha256'], auth['sha256'])

    def test_model_and_endpoint_changes_invalidate_cache(self):
        source = self.source('auth.js', 'login();')
        self.engine.index([source])
        self.engine.calls = []
        self.engine.index([source], {'model': 'another-model'})
        self.assertEqual(len(self.engine.calls), 1)
        self.engine.calls = []
        self.engine.index([source], {'base_url': 'http://localhost:11434'})
        self.assertEqual(len(self.engine.calls), 1)

    def test_lexical_fallback_is_explicit(self):
        source = self.source('auth.js', 'function loginUser() { return sessionStorage.token; }')
        self.engine.fail = True
        indexed = self.engine.index([source])
        self.assertTrue(indexed['ok'])
        self.assertEqual(indexed['mode'], 'lexical')
        self.assertIn('embedding_server_unavailable', indexed['errors'])
        result = self.engine.search('login user', [source])
        self.assertEqual(result['mode'], 'lexical')
        self.assertEqual(result['results'][0]['file_id'], 'auth.js')
        self.assertIsNone(result['results'][0]['semantic_score'])
        result = self.engine.search('unrelated term', [source])
        self.assertEqual(result['results'], [])

    def test_query_provider_failure_uses_lexical(self):
        source = self.source('auth.js', 'login();')
        self.engine.index([source])
        self.engine.fail = True
        result = self.engine.search('login', [source])
        self.assertEqual(result['mode'], 'lexical')
        self.assertEqual(len(result['results']), 1)
        self.assertIn('embedding_server_unavailable', result['errors'])

    def test_source_locations_unicode_and_minified_coverage(self):
        text = u'// za\u017c\u00f3\u0142\u0107 \U0001f680\n' + 'var value=1;' * 500 + '\nlogin();\n'
        chunks = _chunk_source(text)
        self.assertGreater(len(chunks), 2)
        self.assertEqual(chunks[0]['offset'], 0)
        self.assertEqual(chunks[-1]['end_offset'], len(text))
        for index, chunk in enumerate(chunks):
            self.assertEqual(chunk['text'], text[chunk['offset']:chunk['end_offset']])
            self.assertLessEqual(len(chunk['text']), CHUNK_CHARS)
            self.assertEqual(chunk['start_line'], text[:chunk['offset']].count('\n') + 1)
            self.assertEqual(chunk['end_line'], text[:chunk['end_offset']-1].count('\n') + 1)
            if index:
                self.assertLess(chunk['offset'], chunks[index-1]['end_offset'])
                self.assertGreater(chunk['offset'], chunks[index-1]['offset'])
        source = self.source('unicode.js', text)
        self.engine.index([source])
        result = self.engine.search('identity', [source])
        first = result['results'][0]
        self.assertEqual(first['excerpt'], text[first['offset']:first['end_offset']])
        self.assertIn('login', first['excerpt'])

    def test_cancellation_preserves_completed_cache(self):
        source = self.source('auth.js', 'login();')
        self.engine.index([source])
        self.engine.calls = []
        result = self.engine.index([source], cancel_check=lambda: True)
        self.assertTrue(result['stopped'])
        self.assertFalse(result['ok'])
        self.engine.index([source])
        self.assertEqual(self.engine.calls, [])
        result = self.engine.search('identity', [source], cancel_check=lambda: True)
        self.assertTrue(result['stopped'])

    def test_large_bundle_checkpoints_and_mid_file_cancel_resume(self):
        source = self.source('bundle.js', 'login();' * 50000)
        saves = []
        real_save = self.engine._save_cache

        def track_save(sha, chunks, vectors, config, positions=None):
            saves.append(sum(v is not None for v in vectors))
            real_save(sha, chunks, vectors, config, positions)

        self.engine._save_cache = track_save
        result = self.engine.index([source])
        self.assertGreater(result['chunks'], 200)
        self.assertLess(len(saves), 10)
        self.assertLess(sum(saves), 3 * result['chunks'])

        # Another model starts from zero. Stop after three batches (between
        # exponential checkpoints) and ensure its final eight vectors persist.
        self.engine.calls = []
        completed = [0]
        def progress(status):
            completed[0] = status['embedded']
        result = self.engine.index([source], {'model': 'cancel-test'},
                                   cancel_check=lambda: completed[0] >= 24, progress=progress)
        self.assertTrue(result['stopped'])
        self.assertEqual(result['embedded'], 24)
        self.engine.calls = []
        resumed = self.engine.index([source], {'model': 'cancel-test'})
        self.assertEqual(resumed['embedded'], result['chunks'])
        self.assertEqual(sum(len(batch) for batch in self.engine.calls), result['chunks'] - 24)

    def test_bad_vectors_are_rejected(self):
        for vector in ([], [float('nan')], [float('inf')], [0, 0], ['1'], [True], [1e308]):
            with self.assertRaises(EmbeddingError):
                _normalized_vector(vector)
        with self.assertRaises(EmbeddingError):
            _normalized_vector([1, 0], 3)
        self.assertAlmostEqual(sum(v*v for v in _normalized_vector([3, 4])), 1)

    def test_dimension_change_is_not_mixed(self):
        first = self.source('auth.js', 'login();')
        second = self.source('second.js', 'loginAgain();')
        self.engine.index([first])
        self.engine.dim = 2
        result = self.engine.index([first, second])
        self.assertEqual(result['mode'], 'semantic_partial')
        self.assertIn('embedding_dimension_mismatch', result['errors'])
        result = self.engine.search('identity', [first])
        self.assertEqual(result['mode'], 'lexical')
        self.assertIn('embedding_dimension_mismatch', result['errors'])

    def test_invalid_cache_recovers_without_touching_source(self):
        source = self.source('auth.js', 'login();')
        self.engine.index([source])
        config = embedding_config()
        cache = self.engine._cache_path(source['sha256'], config)
        with open(cache, 'wb') as handle:
            handle.write(b'{broken')
        self.engine.calls = []
        self.engine.index([source])
        self.assertEqual(len(self.engine.calls), 1)
        with open(source['path'], 'rb') as handle:
            self.assertEqual(handle.read(), b'login();')

    def test_bounded_shards_roundtrip_and_partial_recovery(self):
        old_size, old_cap = semantic_module.CACHE_SHARD_CHUNKS, semantic_module.MAX_CACHE_SHARD_BYTES
        semantic_module.CACHE_SHARD_CHUNKS = 2
        semantic_module.MAX_CACHE_SHARD_BYTES = 1024
        try:
            source = self.source('sharded.js', 'login();' * 5000)
            first = self.engine.index([source])
            config = embedding_config()
            shards = []
            for folder, unused, names in os.walk(self.engine.cache_dir):
                shards.extend(os.path.join(folder, name) for name in names if name.endswith('.json'))
            self.assertGreater(len(shards), 5)
            self.assertGreater(sum(os.path.getsize(path) for path in shards), 1024)
            self.assertTrue(all(os.path.getsize(path) <= 1024 for path in shards))
            # Total cache exceeds the read bound, each independent shard fits.
            fresh = FakeSemantic(self.engine.root)
            self.assertEqual(fresh.index([source])['embedded'], first['chunks'])
            self.assertEqual(fresh.calls, [])
            result = fresh.search('identity', [source])
            self.assertEqual(result['mode'], 'semantic_hybrid')
            # Corrupt one shard: exactly its two chunks are re-embedded.
            with open(self.engine._cache_path(source['sha256'], config, 2), 'wb') as handle:
                handle.write(b'{invalid')
            fresh.calls = []
            repaired = fresh.index([source])
            self.assertEqual(repaired['embedded'], first['chunks'])
            self.assertEqual(sum(len(batch) for batch in fresh.calls), 2)
        finally:
            semantic_module.CACHE_SHARD_CHUNKS = old_size
            semantic_module.MAX_CACHE_SHARD_BYTES = old_cap

    def test_config_protocols_and_no_secrets_in_identity(self):
        self.assertEqual(embedding_config()['endpoint'], 'http://127.0.0.1:11434/api/embed')
        self.assertEqual(embedding_config({'base_url': 'http://localhost:1234/v1'})['endpoint'],
                         'http://localhost:1234/v1/embeddings')
        self.assertEqual(embedding_config({'base_url': 'http://localhost:1234'})['protocol'], 'openai')
        self.assertEqual(embedding_config({'base_url': 'http://localhost:11434/api'})['protocol'], 'ollama')
        self.assertEqual(embedding_config({'api_key': 'secret'})['identity'], embedding_config()['identity'])
        for base in ('file:///tmp/server', 'http://u:p@localhost:1234',
                     'http://localhost:1234/?key=secret', 'http://localhost:broken'):
            with self.assertRaises(EmbeddingError):
                embedding_config({'base_url': base})

    def test_empty_and_unreadable_sources(self):
        empty = self.source('empty.js', '')
        result = self.engine.index([empty])
        self.assertEqual(result['chunks'], 0)
        self.assertEqual(self.engine.calls, [])
        missing = dict(empty, path=os.path.join(self.tmp, 'missing.js'))
        self.assertFalse(self.engine.index([missing])['ok'])
        self.assertEqual(self.engine.search('login', [missing])['results'], [])


class EmbeddingProtocolTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='burpai-semantic-protocol-')
        self.requests = []
        requests = self.requests

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers.get('Content-Length'))).decode('ascii'))
                requests.append((self.path, body, self.headers.get('Authorization')))
                if self.path == '/redirect/embeddings':
                    self.send_response(302)
                    self.send_header('Location', '/stolen')
                    self.end_headers()
                    return
                if self.path == '/api/embed':
                    data = {'embeddings': [[1, 0] for value in body['input']]}
                elif self.path == '/invalid/embeddings':
                    data = {'data': [{'index': 0, 'embedding': [1, 0]},
                                     {'index': 0, 'embedding': [0, 1]}]}
                else:
                    data = {'data': [{'index': 1, 'embedding': [0, 1]},
                                     {'index': 0, 'embedding': [1, 0]}]}
                raw = json.dumps(data).encode('ascii')
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

        self.server = HTTPServer(('127.0.0.1', 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.daemon = True
        self.thread.start()
        self.base = 'http://127.0.0.1:%s' % self.server.server_address[1]
        self.engine = SemanticCodeIndex(self.tmp)

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(2)
        shutil.rmtree(self.tmp)

    def test_native_ollama_payload_no_truncation(self):
        config = embedding_config({'base_url': self.base + '/api/embed', 'model': 'test-model'})
        vectors = self.engine._embed([u'za\u017c\u00f3\u0142\u0107', 'login()'], config)
        self.assertEqual(vectors, [[1, 0], [1, 0]])
        self.assertEqual(self.requests[0][0], '/api/embed')
        self.assertFalse(self.requests[0][1]['truncate'])
        self.assertEqual(self.requests[0][1]['input'][0], u'za\u017c\u00f3\u0142\u0107')

    def test_openai_reorders_results_and_sends_float_format(self):
        config = embedding_config({'base_url': self.base + '/v1', 'model': 'test-model', 'api_key': 'secret'})
        vectors = self.engine._embed(['one', 'two'], config)
        self.assertEqual(vectors, [[1, 0], [0, 1]])
        self.assertEqual(self.requests[0][1]['encoding_format'], 'float')
        self.assertEqual(self.requests[0][2], 'Bearer secret')

    def test_redirect_does_not_forward_body_or_credentials(self):
        config = embedding_config({'base_url': self.base + '/redirect/embeddings', 'api_key': 'secret'})
        with self.assertRaises(EmbeddingError):
            self.engine._embed(['private source'], config)
        self.assertEqual(len(self.requests), 1)

    def test_duplicate_response_indices_rejected(self):
        config = embedding_config({'base_url': self.base + '/invalid/embeddings'})
        with self.assertRaises(EmbeddingError) as caught:
            self.engine._embed(['one', 'two'], config)
        self.assertEqual(str(caught.exception), 'invalid_embedding_indices')
        self.assertEqual(len(self.requests), 1)


if __name__ == '__main__':
    unittest.main()

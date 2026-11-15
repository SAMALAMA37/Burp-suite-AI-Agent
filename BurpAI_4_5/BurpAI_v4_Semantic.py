# -*- coding: utf-8 -*-
"""Local JavaScript source retrieval for CPython 3 and Burp's Jython 2.7.

Embeddings are produced by a configured Ollama or OpenAI-compatible endpoint.
The default is local Ollama. Source text and vector caches remain on disk;
only indexing batches and queries are sent to the explicitly configured server.
This module never executes downloaded JavaScript.
"""
from __future__ import division

import bisect
import hashlib
import json
import math
import os
import re
import tempfile
import threading
import time
try:
    from urllib2 import Request, build_opener, ProxyHandler, HTTPRedirectHandler, HTTPError
    from urlparse import urlsplit, urlunsplit
    from Queue import Queue, Empty
except ImportError:
    from urllib.request import Request, build_opener, ProxyHandler, HTTPRedirectHandler
    from urllib.error import HTTPError
    from urllib.parse import urlsplit, urlunsplit
    from queue import Queue, Empty

try:
    text_type = unicode
    string_types = (basestring,)
except NameError:
    text_type = str
    string_types = (str,)

CACHE_VERSION = 2
CACHE_SHARD_CHUNKS = 32
# At most 32 vectors * 16,384 dimensions, even the maximum model size.
# Finite normalized JSON floats fit comfortably within this fixed bound.
MAX_CACHE_SHARD_BYTES = 32 * 1024 * 1024
CHUNK_CHARS = 1800
CHUNK_OVERLAP = 240
BATCH_SIZE = 8
MAX_FILE_BYTES = 32 * 1024 * 1024
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
MAX_VECTOR_DIMENSIONS = 16384
REQUEST_TIMEOUT = 30.0


def _text(value):
    if isinstance(value, bytes):
        return value.decode('utf-8', 'replace')
    return value if isinstance(value, string_types) else text_type(value)


def _sha(value):
    if not isinstance(value, bytes):
        value = value.encode('utf-8')
    return hashlib.sha256(value).hexdigest()


def _cancelled(check):
    return bool(check and check())


class EmbeddingError(Exception):
    """Only safe, fixed error codes are exposed to the extension/UI."""


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def embedding_config(config=None):
    config = config or {}
    base = _text(config.get('base_url') or 'http://127.0.0.1:11434').strip().rstrip('/')
    parts = urlsplit(base)
    if (parts.scheme not in ('http', 'https') or not parts.hostname or
            parts.username or parts.password or parts.query or parts.fragment or
            any(ord(c) < 32 for c in base)):
        raise EmbeddingError('invalid_embedding_url')
    try:
        parts.port
    except ValueError:
        raise EmbeddingError('invalid_embedding_port')
    path = parts.path.rstrip('/')
    if parts.hostname.lower() == 'openrouter.ai' and not path:
        path = '/api/v1'
    if path.endswith('/api/embed'):
        mode = 'ollama'
    elif path.endswith('/api'):
        mode, path = 'ollama', path + '/embed'
    elif path.endswith('/embeddings'):
        mode = 'openai'
    elif path.endswith('/v1'):
        mode, path = 'openai', path + '/embeddings'
    else:
        # The conventional Ollama port selects its native endpoint. Other
        # root URLs (LM Studio, llama.cpp) use the OpenAI-compatible route.
        mode = 'ollama' if (parts.port == 11434) else 'openai'
        path += '/api/embed' if mode == 'ollama' else '/v1/embeddings'
    model = _text(config.get('model') or 'embeddinggemma').strip()
    key = _text(config.get('api_key') or '').strip()
    if not model or len(model) > 256 or any(ord(c) < 32 for c in model):
        raise EmbeddingError('invalid_embedding_model')
    if '\r' in key or '\n' in key:
        raise EmbeddingError('invalid_embedding_api_key')
    endpoint = urlunsplit((parts.scheme.lower(), parts.netloc.lower(), path, '', ''))
    # Never persist or include the API key in a filename/cache identity.
    identity = _sha(json.dumps([CACHE_VERSION, endpoint, model, CHUNK_CHARS,
                               CHUNK_OVERLAP, CACHE_SHARD_CHUNKS], ensure_ascii=True))
    return {'endpoint': endpoint, 'model': model, 'api_key': key,
            'protocol': mode, 'identity': identity}


def _normalized_vector(value, expected=None):
    if not isinstance(value, (list, tuple)) or not (1 <= len(value) <= MAX_VECTOR_DIMENSIONS):
        raise EmbeddingError('invalid_embedding_dimensions')
    if expected is not None and len(value) != expected:
        raise EmbeddingError('embedding_dimension_mismatch')
    try:
        if any(isinstance(v, bool) or not isinstance(v, (int, float)) for v in value):
            raise ValueError()
        vector = [float(v) for v in value]
        if any(math.isnan(v) or math.isinf(v) for v in vector):
            raise ValueError()
        magnitude = math.sqrt(sum(v * v for v in vector))
        if not magnitude or math.isnan(magnitude) or math.isinf(magnitude):
            raise ValueError()
    except (ValueError, OverflowError, TypeError):
        raise EmbeddingError('invalid_embedding_values')
    return [v / magnitude for v in vector]


def _terms(text):
    text = re.sub(r'([a-z0-9])([A-Z])', r'\1 \2', text)
    return re.findall(r'[a-z0-9_$]{2,}', text.lower())


def _chunk_source(text):
    """Bounded overlapping windows with original Unicode offsets, even minified."""
    newlines = [i for i, char in enumerate(text) if char == '\n']
    chunks, start = [], 0
    while start < len(text):
        end = min(start + CHUNK_CHARS, len(text))
        if end < len(text):
            lower = start + int(CHUNK_CHARS * .65)
            boundary = max(text.rfind('\n', lower, end), text.rfind(';', lower, end),
                           text.rfind('}', lower, end))
            if boundary >= lower:
                end = boundary + 1
        chunks.append({'offset': start, 'end_offset': end,
                       'start_line': bisect.bisect_left(newlines, start) + 1,
                       'end_line': bisect.bisect_left(newlines, max(start, end - 1)) + 1,
                       'text': text[start:end]})
        if end == len(text):
            break
        start = max(start + 1, end - CHUNK_OVERLAP)
    return chunks


def _atomic_json(path, value):
    folder = os.path.dirname(path)
    if not os.path.isdir(folder):
        os.makedirs(folder)
    fd, temporary = tempfile.mkstemp(prefix='.semantic-', suffix='.tmp', dir=folder)
    try:
        with os.fdopen(fd, 'wb') as handle:
            handle.write(json.dumps(value, ensure_ascii=True, separators=(',', ':')).encode('ascii'))
            handle.flush()
            try:
                os.fsync(handle.fileno())
            except (OSError, AttributeError):
                pass
        try:
            os.chmod(temporary, 0o600)
        except OSError:
            pass
        if hasattr(os, 'replace'):
            os.replace(temporary, path)
        else:
            # Jython/Windows rename cannot replace existing destinations.
            try:
                from java.nio.file import Files, Paths, StandardCopyOption
                Files.move(Paths.get(temporary), Paths.get(path),
                           StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE)
            except ImportError:
                os.rename(temporary, path)
        temporary = None
    finally:
        if temporary and os.path.exists(temporary):
            os.remove(temporary)


class SemanticCodeIndex(object):
    def __init__(self, root, logger=None):
        self.root = os.path.abspath(root)
        self.cache_dir = os.path.join(self.root, 'semantic-v2')
        self.logger = logger
        self.lock = threading.RLock()
        self.opener = build_opener(ProxyHandler({}), _NoRedirect())

    def _embed(self, texts, config, cancel_check=None):
        """Replace in tests to provide deterministic vectors without a model."""
        if _cancelled(cancel_check):
            raise EmbeddingError('cancelled')
        payload = {'model': config['model'], 'input': list(texts)}
        if config['protocol'] == 'ollama':
            payload['truncate'] = False
        else:
            payload['encoding_format'] = 'float'
        body = json.dumps(payload, ensure_ascii=True).encode('ascii')
        request = Request(config['endpoint'], body)
        request.add_header('Content-Type', 'application/json')
        request.add_header('Accept', 'application/json')
        if config['api_key']:
            request.add_header('Authorization', 'Bearer ' + config['api_key'])
        queue, state = Queue(1), {}
        started = time.time()

        def request_worker():
            handle = None
            try:
                handle = self.opener.open(request, timeout=REQUEST_TIMEOUT)
                state['handle'] = handle
                raw = handle.read(MAX_RESPONSE_BYTES + 1)
                if len(raw) > MAX_RESPONSE_BYTES:
                    raise EmbeddingError('embedding_response_too_large')
                data = json.loads(raw.decode('utf-8'))
                if not isinstance(data, dict):
                    raise EmbeddingError('invalid_embedding_response')
                if config['protocol'] == 'ollama':
                    vectors = data.get('embeddings')
                else:
                    rows = data.get('data')
                    if not isinstance(rows, list) or len(rows) != len(texts):
                        raise EmbeddingError('invalid_embedding_count')
                    if sorted(row.get('index') for row in rows) != list(range(len(texts))):
                        raise EmbeddingError('invalid_embedding_indices')
                    vectors = [row.get('embedding') for row in sorted(rows, key=lambda row: row['index'])]
                if not isinstance(vectors, list) or len(vectors) != len(texts):
                    raise EmbeddingError('invalid_embedding_count')
                queue.put(('ok', vectors))
            except HTTPError as exc:
                queue.put(('error', 'embedding_http_%s' % exc.code))
            except EmbeddingError as exc:
                queue.put(('error', str(exc)))
            except Exception:
                # An exception may contain an endpoint, credentials or source.
                queue.put(('error', 'embedding_server_unavailable'))
            finally:
                if handle is not None:
                    try:
                        handle.close()
                    except Exception:
                        pass

        worker = threading.Thread(target=request_worker)
        worker.daemon = True
        worker.start()
        while True:
            if _cancelled(cancel_check) or time.time() - started > REQUEST_TIMEOUT:
                # Closing a response can itself wait for a socket on some JVMs.
                # Do that away from the caller so Stop always remains responsive.
                handle = state.get('handle')
                if handle is not None:
                    def close_handle():
                        try:
                            handle.close()
                        except Exception:
                            pass
                    closer = threading.Thread(target=close_handle)
                    closer.daemon = True
                    closer.start()
                raise EmbeddingError('cancelled' if _cancelled(cancel_check) else 'embedding_timeout')
            try:
                status, value = queue.get(timeout=.1)
            except Empty:
                continue
            if status == 'error':
                raise EmbeddingError(value)
            return value

    def _cache_path(self, sha, config, shard=0):
        return os.path.join(self.cache_dir, config['identity'], sha, '%06d.json' % shard)

    def _read_source(self, item):
        path = os.path.abspath(_text(item.get('path') or ''))
        if not os.path.isfile(path) or os.path.islink(path):
            raise ValueError('source_file_missing_or_link')
        with open(path, 'rb') as handle:
            raw = handle.read(MAX_FILE_BYTES + 1)
        if len(raw) > MAX_FILE_BYTES:
            raise ValueError('source_file_too_large')
        sha = _sha(raw)
        if item.get('sha256') and item['sha256'] != sha:
            raise ValueError('source_hash_mismatch_recollect_required')
        text = raw.decode('utf-8', 'strict')
        return path, sha, text

    def _cache(self, sha, chunks, config):
        result = [None for chunk in chunks]
        dimension = None
        for start in range(0, len(chunks), CACHE_SHARD_CHUNKS):
            shard = start // CACHE_SHARD_CHUNKS
            path = self._cache_path(sha, config, shard)
            group = chunks[start:start+CACHE_SHARD_CHUNKS]
            try:
                if os.path.islink(path):
                    continue
                # A malformed shard loses only its own derived vectors. Other
                # completed shards remain usable for search and resume.
                with open(path, 'rb') as handle:
                    raw = handle.read(MAX_CACHE_SHARD_BYTES + 1)
                if len(raw) > MAX_CACHE_SHARD_BYTES:
                    continue
                data = json.loads(raw.decode('ascii'))
                if (data.get('version') != CACHE_VERSION or data.get('sha256') != sha or
                        data.get('identity') != config['identity'] or data.get('shard') != shard or
                        data.get('ranges') != [[c['offset'], c['end_offset']] for c in group]):
                    continue
                values = data.get('vectors')
                if not isinstance(values, list) or len(values) != len(group):
                    continue
                shard_vectors, shard_dimension = [], dimension
                for vector in values:
                    if vector is None:
                        shard_vectors.append(None)
                    else:
                        vector = _normalized_vector(vector, shard_dimension)
                        shard_dimension = len(vector)
                        shard_vectors.append(vector)
                result[start:start+len(group)] = shard_vectors
                dimension = shard_dimension
            except (IOError, OSError, ValueError, TypeError, AttributeError, EmbeddingError):
                continue
        return result

    def _save_cache(self, sha, chunks, vectors, config, positions=None):
        positions = range(len(chunks)) if positions is None else positions
        shards = sorted(set(pos // CACHE_SHARD_CHUNKS for pos in positions))
        for shard in shards:
            start = shard * CACHE_SHARD_CHUNKS
            group = chunks[start:start+CACHE_SHARD_CHUNKS]
            values = vectors[start:start+CACHE_SHARD_CHUNKS]
            _atomic_json(self._cache_path(sha, config, shard), {
                'version': CACHE_VERSION, 'sha256': sha, 'identity': config['identity'],
                'shard': shard, 'ranges': [[c['offset'], c['end_offset']] for c in group],
                'vectors': values})

    def index(self, files, config=None, cancel_check=None, progress=None):
        with self.lock:
            return self._index(files, config, cancel_check, progress)

    def _index(self, files, config, cancel_check, progress):
        errors, total_chunks, embedded, file_count = [], 0, 0, 0
        stopped, provider_failed, dimension = False, False, None
        try:
            config = embedding_config(config)
        except EmbeddingError as exc:
            return {'ok': False, 'mode': 'lexical', 'files': 0, 'chunks': 0,
                    'embedded': 0, 'errors': [str(exc)], 'stopped': False}
        for item in files:
            if _cancelled(cancel_check):
                stopped = True
                break
            try:
                path, sha, text = self._read_source(item)
                chunks = _chunk_source(text)
                vectors = self._cache(sha, chunks, config)
                cached_dimension = next((len(v) for v in vectors if v is not None), None)
                if dimension is not None and cached_dimension is not None and dimension != cached_dimension:
                    vectors = [None for chunk in chunks]
                elif cached_dimension is not None:
                    dimension = cached_dimension
                missing = [i for i, v in enumerate(vectors) if v is None]
                dirty, newly_embedded, next_checkpoint = set(), 0, BATCH_SIZE
                if not provider_failed:
                    for start in range(0, len(missing), BATCH_SIZE):
                        if _cancelled(cancel_check):
                            stopped = True
                            break
                        positions = missing[start:start+BATCH_SIZE]
                        try:
                            raw_vectors = self._embed([chunks[i]['text'] for i in positions], config, cancel_check)
                            if not isinstance(raw_vectors, list) or len(raw_vectors) != len(positions):
                                raise EmbeddingError('invalid_embedding_count')
                            batch = []
                            for raw_vector in raw_vectors:
                                vector = _normalized_vector(raw_vector, dimension)
                                if dimension is None:
                                    dimension = len(vector)
                                batch.append(vector)
                            for pos, vector in zip(positions, batch):
                                vectors[pos] = vector
                            dirty.update(positions)
                            newly_embedded += len(batch)
                            # Geometrically spaced checkpoints write only the
                            # changed bounded shards, avoiding quadratic full-
                            # file rewrites and preserving completed old shards.
                            if newly_embedded >= next_checkpoint:
                                self._save_cache(sha, chunks, vectors, config, dirty)
                                dirty.clear()
                                next_checkpoint *= 2
                            if progress:
                                progress({'phase': 'embedding', 'path': path,
                                          'embedded': embedded + sum(v is not None for v in vectors),
                                          'chunks': total_chunks + len(chunks)})
                        except EmbeddingError as exc:
                            if str(exc) == 'cancelled':
                                stopped = True
                            else:
                                errors.append(str(exc))
                                provider_failed = True
                            break
                if dirty:
                    # Preserve work at the final file boundary, cancellation,
                    # and provider errors, including incomplete last batches.
                    self._save_cache(sha, chunks, vectors, config, dirty)
                total_chunks += len(chunks)
                embedded += sum(v is not None for v in vectors)
                file_count += 1
                if stopped:
                    break
            except (IOError, OSError, ValueError, TypeError) as exc:
                errors.append({'file_id': item.get('id'), 'error':
                               str(exc) if isinstance(exc, ValueError) else 'source_index_failed'})
        mode = ('semantic_hybrid' if embedded and embedded == total_chunks else
                ('semantic_partial' if embedded else 'lexical'))
        return {'ok': not stopped and (file_count > 0 or not files), 'mode': mode,
                'files': file_count, 'chunks': total_chunks, 'embedded': embedded,
                'errors': errors, 'stopped': stopped, 'model': config['model'],
                'endpoint': config['endpoint']}

    def search(self, query, files, config=None, limit=8, cancel_check=None):
        with self.lock:
            return self._search(query, files, config, limit, cancel_check)

    def _search(self, query, files, config, limit, cancel_check):
        query = _text(query or '').strip()
        if not query:
            return {'ok': False, 'error': 'empty_query', 'results': [], 'mode': 'lexical'}
        if len(query) > 4000:
            return {'ok': False, 'error': 'query_too_long', 'results': [], 'mode': 'lexical'}
        try:
            limit = max(1, min(50, int(limit)))
            config = embedding_config(config)
        except (ValueError, TypeError, EmbeddingError) as exc:
            return {'ok': False, 'error': str(exc), 'results': [], 'mode': 'lexical'}
        candidates, errors, dimensions = [], [], set()
        for item in files:
            if _cancelled(cancel_check):
                return {'ok': False, 'stopped': True, 'results': [], 'mode': 'lexical'}
            try:
                path, sha, text = self._read_source(item)
                chunks = _chunk_source(text)
                vectors = self._cache(sha, chunks, config)
                for chunk, vector in zip(chunks, vectors):
                    record = dict(chunk)
                    record.update({'file_id': item.get('id'), 'path': path,
                                   'url': item.get('url'), 'sha256': sha, 'vector': vector})
                    candidates.append(record)
                    if vector is not None:
                        dimensions.add(len(vector))
            except (IOError, OSError, ValueError, TypeError) as exc:
                errors.append({'file_id': item.get('id'), 'error':
                               str(exc) if isinstance(exc, ValueError) else 'source_read_failed'})
        query_vector = None
        if len(dimensions) > 1:
            errors.append('embedding_dimension_mismatch_reindex_required')
        elif dimensions:
            try:
                values = self._embed([query], config, cancel_check)
                if not isinstance(values, list) or len(values) != 1:
                    raise EmbeddingError('invalid_embedding_count')
                query_vector = _normalized_vector(values[0], next(iter(dimensions)))
            except EmbeddingError as exc:
                if str(exc) == 'cancelled':
                    return {'ok': False, 'stopped': True, 'results': [], 'mode': 'lexical'}
                errors.append(str(exc))
        else:
            errors.append('semantic_index_missing_use_index')
        query_terms = set(_terms(query))
        # A simple IDF-weighted lexical component rewards rare code identifiers
        # while semantic cosine similarity finds concepts without shared words.
        frequency = dict((term, 0) for term in query_terms)
        for record in candidates:
            if _cancelled(cancel_check):
                return {'ok': False, 'stopped': True, 'results': [], 'mode': 'lexical'}
            terms = set(_terms(record['text']))
            record['terms'] = terms
            for term in query_terms.intersection(terms):
                frequency[term] += 1
        weights = dict((term, math.log(1.0 + (len(candidates) + 1.0) / (count + 1.0)))
                       for term, count in frequency.items())
        total_weight = sum(weights.values()) or 1.0
        for record in candidates:
            lexical = sum(weights[term] for term in query_terms.intersection(record['terms'])) / total_weight
            vector = record['vector']
            semantic = None
            if query_vector is not None and vector is not None:
                semantic = sum(a*b for a, b in zip(vector, query_vector))
            record['lexical_score'] = lexical
            record['semantic_score'] = semantic
            record['score'] = .85 * semantic + .15 * lexical if semantic is not None else .15 * lexical
        ranked = sorted(candidates, key=lambda row: (-row['score'], row['path'], row['offset']))
        results = []
        for record in ranked:
            if _cancelled(cancel_check):
                return {'ok': False, 'stopped': True, 'results': [], 'mode': 'lexical'}
            if record['semantic_score'] is None and record['lexical_score'] == 0:
                continue
            # Suppress largely overlapping neighbors, retaining separate useful
            # regions of a large bundle and exact source offsets.
            if any(previous['path'] == record['path'] and
                   max(0, min(previous['end_offset'], record['end_offset']) -
                       max(previous['offset'], record['offset'])) >
                   .5 * min(previous['end_offset'] - previous['offset'],
                            record['end_offset'] - record['offset']) for previous in results):
                continue
            record.pop('vector', None)
            record.pop('terms', None)
            record['excerpt'] = record.pop('text')
            record['score'] = round(record['score'], 6)
            results.append(record)
            if len(results) >= limit:
                break
        embedded = sum(row['semantic_score'] is not None for row in candidates)
        mode = ('semantic_hybrid' if embedded and embedded == len(candidates) else
                ('semantic_partial' if embedded else 'lexical'))
        return {'ok': True, 'mode': mode, 'results': results, 'count': len(results),
                'total_chunks': len(candidates), 'embedded_chunks': embedded,
                'errors': errors, 'model': config['model'], 'stopped': False}

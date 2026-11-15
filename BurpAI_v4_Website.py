# -*- coding: utf-8 -*-
"""Scope-aware website JavaScript collection; compatible with Jython 2.7.

Networking is deliberately supplied by the Burp extension. This module never
executes downloaded JavaScript and never reads an arbitrary user-supplied path.
"""
from __future__ import unicode_literals

import hashlib
import json
import os
import re
import threading
import time
import uuid
from bisect import bisect_right
from collections import deque
try:
    from HTMLParser import HTMLParser
    from urlparse import urljoin, urlsplit, urlunsplit
except ImportError:
    from html.parser import HTMLParser
    from urllib.parse import urljoin, urlsplit, urlunsplit

try:
    text_type = unicode
except NameError:
    text_type = str

DISCOVERY_NOTE = ('Collects reachable HTML, captured JavaScript, inline scripts and '
                  'literal module/chunk references. Browser-only, computed, authenticated '
                  'or unvisited routes can contain additional scripts; browse them through '
                  'Burp and collect again. Files are never executed.')
JS_PATH = re.compile(r'\.(?:mjs|cjs|js)(?:$|[?#])', re.I)
JS_TYPES = frozenset(('', 'module', 'text/javascript', 'application/javascript',
                      'text/ecmascript', 'application/ecmascript',
                      'application/x-javascript', 'text/jscript'))
NON_PAGE = re.compile(r'\.(?:css|png|jpe?g|gif|svg|ico|webp|avif|woff2?|ttf|eot|'
                      r'mp[34]|webm|pdf|zip|gz|map|json|xml|txt)(?:$|[?#])', re.I)
IMPORT_RE = re.compile(r'''(?:\b(?:import|export)\s+(?:[^;\n]{0,500}?\s+from\s*)?|\b(?:import|require)\s*\(\s*)(["'])([^"'\r\n]{1,2048})\1''')
JS_LITERAL_RE = re.compile(r'''(["'`])([^"'`\r\n]{1,2048}?\.(?:mjs|cjs|js)(?:\?[^"'`\r\n]{0,1000})?)\1''', re.I)
HTML_BODY = re.compile(r'\s*(?:<!doctype\s+html|<(?:html|head|body|script|form)\b)', re.I)
NAV_SOURCE_BYTES = 32 * 1024 * 1024
NAV_SCAN_BYTES = 100 * 1024 * 1024
NAV_NOTE = 'Lexical source navigation; references are text occurrences, not type-resolved calls or verified runtime behavior.'


def _line_starts(source):
    return [0] + [m.end() for m in re.finditer(r'\r\n|\r|\n', source)]


def _navigation_mask(source, mask_strings=False):
    """Mask comments (and optionally string contents) without changing positions.

    This deliberately is a lexical helper, not an ECMAScript parser. Templates
    are treated as strings, so symbols inside template expressions may be omitted.
    """
    pattern = re.compile(r'''("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\])*`)|(//[^\r\n]*|/\*[\s\S]*?\*/)''')
    def replace(match):
        if match.group(2) is not None or mask_strings:
            return re.sub(r'[^\r\n]', ' ', match.group(0))
        return match.group(0)
    return pattern.sub(replace, source)


def _navigation_imports(source, base):
    code = _navigation_mask(source)
    starts = _line_starts(source)
    for match in IMPORT_RE.finditer(code):
        reference = match.group(2)
        if '${' in reference:
            continue
        resolved = None
        if reference.startswith(('.', '/', 'http://', 'https://')):
            try:
                resolved = canonical_url(reference, base)
            except ValueError:
                pass
        yield {'specifier': reference, 'target_url': resolved,
               'offset': match.start(2), 'line': bisect_right(starts, match.start(2)),
               'resolution': 'literal_url' if resolved else 'unresolved_package_or_specifier'}


def _text(value):
    if isinstance(value, bytes):
        return value.decode('utf-8', 'replace')
    return value if isinstance(value, text_type) else text_type(value or '')


def _digest(value):
    return hashlib.sha256(value if isinstance(value, bytes) else _text(value).encode('utf-8')).hexdigest()


def canonical_url(value, base=None):
    value = _text(value).strip()
    if not value or len(value) > 8192 or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError('invalid_http_url')
    if '\\' in value or re.search(r'\s', value):
        raise ValueError('invalid_http_url')
    u = urlsplit(urljoin(base, value) if base else value)
    if u.scheme.lower() not in ('http', 'https') or not u.hostname or u.username or u.password:
        raise ValueError('invalid_http_url')
    scheme, host = u.scheme.lower(), u.hostname.lower()
    try:
        port = u.port
    except ValueError:
        raise ValueError('invalid_http_url')
    if port is not None and not 1 <= port <= 65535:
        raise ValueError('invalid_http_url')
    # Python 2 urlparse silently returns None for an out-of-range port.
    authority_port = u.netloc[u.netloc.rfind(']') + 1:] if u.netloc.startswith('[') else (':' + u.netloc.rsplit(':', 1)[1] if ':' in u.netloc else '')
    if authority_port and (not re.match(r'^:[0-9]+$', authority_port) or not 1 <= int(authority_port[1:]) <= 65535):
        raise ValueError('invalid_http_url')
    if ':' in host:
        host = '[' + host + ']'
    if port is not None and port != (443 if scheme == 'https' else 80):
        host += ':' + str(port)
    return urlunsplit((scheme, host, u.path or '/', u.query, ''))


def _origin(url):
    u = urlsplit(canonical_url(url))
    return u.scheme + '://' + u.netloc


def _header(headers, name):
    if isinstance(headers, dict):
        for key, value in headers.items():
            if _text(key).lower() == name.lower():
                return _text(value).strip()
    else:
        for value in headers or []:
            key, sep, tail = _text(value).partition(':')
            if sep and key.lower() == name.lower():
                return tail.strip()
    return ''


def _bounded(value, default, minimum, maximum):
    try:
        return max(minimum, min(maximum, int(value)))
    except (TypeError, ValueError, OverflowError):
        return default


class _BoundedRecords(list):
    def __init__(self, limit=100):
        list.__init__(self)
        self.limit, self.total = limit, 0

    def append(self, item):
        self.total += 1
        if len(self) < self.limit:
            list.append(self, item)


class _Page(HTMLParser):
    def __init__(self):
        HTMLParser.__init__(self)
        self.base = None
        self.scripts = []
        self.links = []
        self._script = None
        self._inline_number = 0

    def handle_starttag(self, tag, attrs):
        attrs = dict((k.lower(), v or '') for k, v in attrs)
        tag = tag.lower()
        if tag == 'base' and self.base is None and attrs.get('href'):
            self.base = attrs['href']
        elif tag == 'script':
            self._inline_number += 1
            typ = attrs.get('type', '').lower().split(';')[0].strip()
            if typ in JS_TYPES:
                if attrs.get('src'):
                    self.scripts.append(('external', attrs['src'], self._inline_number))
                    self._script = None
                else:
                    self._script = [[], self._inline_number]
            else:
                self._script = None
        elif tag == 'link':
            rel = attrs.get('rel', '').lower().split()
            if 'modulepreload' in rel or ('preload' in rel and attrs.get('as', '').lower() == 'script'):
                if attrs.get('href'):
                    self.scripts.append(('external', attrs['href'], 0))
        elif tag in ('a', 'area') and attrs.get('href'):
            self.links.append(attrs['href'])
        elif tag in ('iframe', 'frame') and attrs.get('src'):
            self.links.append(attrs['src'])

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        self.handle_endtag(tag)

    def handle_data(self, data):
        if self._script is not None:
            self._script[0].append(data)

    def handle_entityref(self, name):
        self.handle_data('&' + name + ';')

    def handle_charref(self, name):
        self.handle_data('&#' + name + ';')

    def handle_endtag(self, tag):
        if tag.lower() == 'script' and self._script is not None:
            content = ''.join(self._script[0])
            if content.strip():
                self.scripts.append(('inline', content, self._script[1]))
            self._script = None


def _js_references(source):
    """Literal discovery, not a JS parser. Bare package names are not URLs."""
    seen = set()
    for match in IMPORT_RE.finditer(source):
        ref = match.group(2)
        if ref.startswith(('.', '/', 'http://', 'https://')) and '${' not in ref:
            if ref not in seen:
                seen.add(ref)
                yield ref
    for match in JS_LITERAL_RE.finditer(source):
        ref = match.group(2)
        if '${' not in ref and not re.search(r'\s', ref) and ref not in seen:
            seen.add(ref)
            yield ref


class WebsiteCorpus(object):
    def __init__(self, root, logger=None):
        self.root = os.path.realpath(os.path.abspath(_text(root)))
        self.logger = logger
        self.lock = threading.RLock()
        self._mkdir(self.root)

    def _mkdir(self, path):
        if os.path.islink(path):
            raise ValueError('symlink_directory_not_allowed')
        if not os.path.isdir(path):
            os.makedirs(path)
        try:
            os.chmod(path, 0o700)
        except OSError:
            pass

    def _within(self, path, root):
        result, root = os.path.realpath(path), os.path.realpath(root)
        if result != root and not result.startswith(root + os.sep):
            raise ValueError('path_outside_corpus')
        return result

    def site_root(self, site_url):
        origin = _origin(site_url)
        slug = re.sub(r'[^a-zA-Z0-9._-]+', '_', urlsplit(origin).netloc)[:80]
        return self._within(os.path.join(self.root, 'sites', slug + '-' + _digest(origin)[:16]), self.root)

    def _manifest(self, site_url):
        folder = self.site_root(site_url)
        path = self._within(os.path.join(folder, 'manifest.json'), folder)
        if not os.path.isfile(path):
            return {}
        with open(path, 'rb') as handle:
            data = json.loads(handle.read().decode('utf-8'))
        if not isinstance(data, dict) or data.get('origin') != _origin(site_url):
            raise ValueError('invalid_manifest')
        return data

    def _save_manifest(self, folder, data):
        path = self._within(os.path.join(folder, 'manifest.json'), folder)
        tmp = path + '.tmp-' + uuid.uuid4().hex
        raw = json.dumps(data, ensure_ascii=True, indent=2).encode('utf-8')
        try:
            with open(tmp, 'wb') as handle:
                handle.write(raw)
                handle.flush()
                try:
                    os.fsync(handle.fileno())
                except OSError:
                    pass
            try:
                os.chmod(tmp, 0o600)
            except OSError:
                pass
            if hasattr(os, 'replace'):
                os.replace(tmp, path)
            else:
                # Jython uses Java's replacement move on Windows.
                try:
                    from java.nio.file import Files, Paths, StandardCopyOption
                    Files.move(Paths.get(tmp), Paths.get(path), StandardCopyOption.REPLACE_EXISTING)
                except ImportError:
                    os.rename(tmp, path)
        finally:
            if os.path.isfile(tmp):
                os.remove(tmp)

    def list_files(self, site_url):
        with self.lock:
            folder = self.site_root(site_url)
            rows = self._manifest(site_url).get('files', [])
            result = []
            for row in rows:
                entry = dict(row)
                entry['path'] = self._within(os.path.join(folder, entry['path']), folder)
                if not os.path.isfile(entry['path']):
                    continue
                result.append(entry)
            return result

    def read_file(self, site_url, file_id, offset=0, limit=6500):
        with self.lock:
            row = next((item for item in self.list_files(site_url) if item['id'] == file_id), None)
            if row is None:
                return {'ok': False, 'error': 'unknown_file_id'}
            with open(row['path'], 'rb') as handle:
                raw = handle.read()
            if _digest(raw) != row['sha256']:
                return {'ok': False, 'error': 'source_integrity_mismatch'}
            source = raw.decode('utf-8')
            offset = _bounded(offset, 0, 0, len(source))
            limit = _bounded(limit, 6500, 1, 30000)
            end = min(len(source), offset + limit)
            result = dict(row)
            result.update({'ok': True, 'content': source[offset:end], 'offset': offset,
                           'end_offset': end, 'next_offset': end if end < len(source) else None,
                           'line_start': source.count('\n', 0, offset) + 1,
                           'line_end': source.count('\n', 0, max(offset, end - 1)) + 1})
            return result

    def _navigation_source(self, row):
        with open(row['path'], 'rb') as handle:
            raw = handle.read(NAV_SOURCE_BYTES + 1)
        if len(raw) > NAV_SOURCE_BYTES:
            raise ValueError('source_exceeds_navigation_limit')
        if _digest(raw) != row['sha256']:
            raise ValueError('source_integrity_mismatch')
        return raw.decode('utf-8', 'strict')

    def read_lines(self, site_url, file_id, start_line=1, end_line=150,
                   max_chars=24000, offset=None):
        """Read inclusive original lines; huge single lines use explicit continuation."""
        with self.lock:
            row = next((item for item in self.list_files(site_url) if item['id'] == file_id), None)
            if row is None:
                return {'ok': False, 'error': 'unknown_file_id'}
            try:
                start_line, end_line = int(start_line), int(end_line)
                if start_line < 1 or end_line < start_line:
                    raise ValueError('invalid_line_range')
                source = self._navigation_source(row)
                starts = _line_starts(source)
                if start_line > len(starts):
                    return {'ok': False, 'error': 'start_line_after_eof', 'total_lines': len(starts)}
                requested_end = end_line
                end_line = min(end_line, len(starts))
                lower = starts[start_line - 1]
                upper = starts[end_line] if end_line < len(starts) else len(source)
                position = lower if offset is None else int(offset)
                if position < lower or position > upper or (upper > lower and position == upper):
                    raise ValueError('offset_outside_requested_lines')
                end = min(upper, position + _bounded(max_chars, 24000, 1, 60000))
                first_line = bisect_right(starts, position)
                last_line = bisect_right(starts, max(position, end - 1))
                partial_start = position != starts[first_line - 1]
                partial_end = end < upper and end not in starts
                result = dict(row)
                result.update({'ok': True, 'content': source[position:end],
                    'start_line': first_line, 'end_line': last_line,
                    'line_start': first_line, 'line_end': last_line,
                    'requested_start_line': start_line, 'requested_end_line': requested_end,
                    'range_start_offset': lower, 'range_end_offset': upper,
                    'offset': position, 'end_offset': end, 'total_lines': len(starts),
                    'total_chars': len(source), 'range_clamped': requested_end > len(starts),
                    'partial': position > lower or end < upper,
                    'partial_start_line': partial_start, 'partial_end_line': partial_end,
                    'more': end < upper, 'next_offset': end if end < upper else None,
                    'next_start_line': bisect_right(starts, end) if end < upper else None})
                return result
            except (IOError, OSError, UnicodeError, ValueError, TypeError, OverflowError) as exc:
                return {'ok': False, 'error': _text(exc) if isinstance(exc, ValueError) else 'source_read_failed'}

    def outline(self, site_url, file_id, offset=0, limit=100, cancel_check=None):
        with self.lock:
            row = next((item for item in self.list_files(site_url) if item['id'] == file_id), None)
            if row is None:
                return {'ok': False, 'error': 'unknown_file_id'}
            try:
                source = self._navigation_source(row)
            except (IOError, OSError, ValueError, UnicodeError) as exc:
                return {'ok': False, 'error': _text(exc), 'note': NAV_NOTE}
            code, starts = _navigation_mask(source, True), _line_starts(source)
            # Bound parameter matching so broken/minified input cannot trigger
            # unbounded regular-expression backtracking.
            patterns = [
                ('function', re.compile(r'\bfunction\s*\*?\s*([\w$]+)\s*\(', re.UNICODE)),
                ('class', re.compile(r'\bclass\s+([\w$]+)', re.UNICODE)),
                ('function', re.compile(r'\b(?:const|let|var)\s+([\w$]+)\s*=\s*(?:async\s+)?function\b', re.UNICODE)),
                ('arrow', re.compile(r'\b(?:const|let|var)\s+([\w$]+)\s*=\s*(?:async\s+)?(?:[\w$]+|\([^()]{0,2000}\))\s*=>', re.UNICODE))]
            records, seen, stopped = [], set(), False
            ceiling = 20000
            for kind, pattern in patterns:
                for match in pattern.finditer(code):
                    if cancel_check and cancel_check():
                        stopped = True
                        break
                    pos, name = match.start(1), match.group(1)
                    if pos in seen:
                        continue
                    seen.add(pos)
                    records.append({'name': name, 'symbol': name, 'kind': kind,
                        'line': bisect_right(starts, pos), 'start_line': bisect_right(starts, pos),
                        'offset': pos, 'file_id': file_id, 'url': row['url'], 'path': row['path']})
                    if len(records) >= ceiling:
                        break
                if stopped or len(records) >= ceiling:
                    break
            records.sort(key=lambda item: item['offset'])
            off = _bounded(offset, 0, 0, len(records))
            lim = _bounded(limit, 100, 1, 200)
            return {'ok': True, 'file_id': file_id, 'url': row['url'], 'symbols': records[off:off+lim],
                    'total': len(records), 'next_offset': min(len(records), off+lim),
                    'more': off+lim < len(records), 'stopped': stopped,
                    'scan_truncated': len(records) >= ceiling, 'note': NAV_NOTE}

    def related_files(self, site_url, file_id, limit=50, allowed_ids=None, cancel_check=None):
        with self.lock:
            allowed = None if allowed_ids is None else set(allowed_ids)
            files = [f for f in self.list_files(site_url) if allowed is None or f['id'] in allowed]
            selected = next((f for f in files if f['id'] == file_id), None)
            if selected is None:
                return {'ok': False, 'error': 'unknown_or_out_of_scope_file'}
            by_url = dict((f['url'], f) for f in files if '#inline-' not in f['url'])
            outgoing, incoming, errors = [], [], []
            lim = _bounded(limit, 50, 1, 200)
            bytes_scanned, stopped, limited = 0, False, False
            # Selected file first, so its outgoing navigation remains useful
            # even if the incoming scan reaches its corpus budget.
            ordered = [selected] + [f for f in files if f['id'] != file_id]
            outgoing_count, incoming_count = 0, 0
            for row in ordered:
                if cancel_check and cancel_check():
                    stopped = True
                    break
                if bytes_scanned + row.get('size', 0) > NAV_SCAN_BYTES:
                    limited = True
                    break
                try:
                    source = self._navigation_source(row)
                    bytes_scanned += len(source.encode('utf-8'))
                except (IOError, OSError, ValueError, UnicodeError) as exc:
                    if len(errors) < 100:
                        errors.append({'file_id': row['id'], 'error': _text(exc)})
                    continue
                for reference in _navigation_imports(source, row['url']):
                    if cancel_check and cancel_check():
                        stopped = True
                        break
                    target = by_url.get(reference['target_url'])
                    record = dict(reference)
                    record.update({'source_file_id': row['id'], 'source_url': row['url'],
                        'target_file_id': target['id'] if target else None,
                        'file_id': target['id'] if target else None,
                        'missing': target is None})
                    if row['id'] == file_id:
                        outgoing_count += 1
                        if len(outgoing) < lim:
                            outgoing.append(record)
                    if target and target['id'] == file_id:
                        incoming_count += 1
                        if len(incoming) < lim:
                            record['file_id'] = row['id']
                            incoming.append(record)
                if stopped:
                    break
            return {'ok': True, 'file_id': file_id, 'outgoing': outgoing, 'incoming': incoming,
                    'outgoing_count': outgoing_count, 'incoming_count': incoming_count,
                    'more': outgoing_count > lim or incoming_count > lim,
                    'stopped': stopped, 'scan_truncated': limited, 'errors': errors, 'note': NAV_NOTE}

    def find_references(self, site_url, symbol, offset=0, limit=50, allowed_ids=None, cancel_check=None):
        symbol = _text(symbol)
        if not re.match(r'^(?:[^\W\d]|[$_])[\w$]*$', symbol, re.UNICODE) or len(symbol) > 200:
            return {'ok': False, 'error': 'invalid_identifier'}
        pattern = re.compile(r'(?<![\w$])' + re.escape(symbol) + r'(?![\w$])', re.UNICODE)
        with self.lock:
            allowed = None if allowed_ids is None else set(allowed_ids)
            files = [f for f in self.list_files(site_url) if allowed is None or f['id'] in allowed]
            off, lim = _bounded(offset, 0, 0, 10000000), _bounded(limit, 50, 1, 200)
            records, errors, total, bytes_scanned = [], [], 0, 0
            stopped, limited = False, False
            for row in files:
                if cancel_check and cancel_check():
                    stopped = True
                    break
                if bytes_scanned + row.get('size', 0) > NAV_SCAN_BYTES:
                    limited = True
                    break
                try:
                    source = self._navigation_source(row)
                    bytes_scanned += len(source.encode('utf-8'))
                except (IOError, OSError, ValueError, UnicodeError) as exc:
                    if len(errors) < 100:
                        errors.append({'file_id': row['id'], 'error': _text(exc)})
                    continue
                starts = _line_starts(source)
                for match in pattern.finditer(source):
                    if cancel_check and cancel_check():
                        stopped = True
                        break
                    pos, line = match.start(), bisect_right(starts, match.start())
                    if off <= total < off + lim:
                        excerpt_start = max(starts[line - 1], pos - 120)
                        line_end = starts[line] if line < len(starts) else len(source)
                        excerpt_end = min(line_end, pos + len(symbol) + 180)
                        records.append({'file_id': row['id'], 'url': row['url'], 'path': row['path'],
                            'symbol': symbol, 'line': line, 'start_line': line,
                            'offset': pos, 'end_offset': match.end(), 'column': pos - starts[line-1] + 1,
                            'excerpt': source[excerpt_start:excerpt_end], 'excerpt_offset': excerpt_start})
                    total += 1
                    if total >= 1000000:
                        limited = True
                        break
                if stopped or limited:
                    break
            return {'ok': True, 'symbol': symbol, 'results': records, 'total': total,
                    'offset': off, 'next_offset': min(total, off+lim), 'more': off+lim < total,
                    'stopped': stopped, 'scan_truncated': limited, 'errors': errors, 'note': NAV_NOTE}

    def collect(self, url, fetch, in_scope, cached_sources=None, max_pages=30,
                max_files=500, max_bytes=100 * 1024 * 1024, cancel_check=None,
                progress=None):
        """Save a fresh inventory; retained old blobs never masquerade as new hits."""
        with self.lock:
            return self._collect(url, fetch, in_scope, cached_sources, max_pages,
                                 max_files, max_bytes, cancel_check, progress)

    def _collect(self, url, fetch, in_scope, cached_sources, max_pages, max_files,
                 max_bytes, cancel_check, progress):
        try:
            url = canonical_url(url)
        except ValueError as exc:
            return {'ok': False, 'error': _text(exc)}
        if not in_scope(url):
            return {'ok': False, 'error': 'outside_burp_scope'}
        folder = self.site_root(url)
        self._mkdir(self._within(os.path.join(self.root, 'sites'), self.root))
        self._mkdir(folder)
        self._mkdir(self._within(os.path.join(folder, 'files'), folder))
        origin = _origin(url)
        max_pages = _bounded(max_pages, 30, 1, 1000)
        max_files = _bounded(max_files, 500, 1, 10000)
        max_bytes = _bounded(max_bytes, 100 * 1024 * 1024, 1, 1024 * 1024 * 1024)
        queue, queued, fetched = deque(), set(), set()
        files, failures, skipped, limits = {}, _BoundedRecords(), _BoundedRecords(), set()
        stats = {'bytes': 0, 'pages': 0, 'html_pages': 0, 'requests': 0, 'cached_files': 0}
        stopped = [False]

        def cancelled():
            if cancel_check and cancel_check():
                stopped[0] = True
            return stopped[0]

        def emit(message):
            if progress:
                progress(message)

        def enqueue(candidate, base, kind):
            try:
                target = canonical_url(candidate, base)
            except ValueError:
                skipped.append({'url': _text(candidate)[:500], 'reason': 'invalid_or_non_http_reference'})
                return
            if kind == 'page' and _origin(target) != origin:
                return
            if kind == 'page' and NON_PAGE.search(target):
                return
            if not in_scope(target):
                skipped.append({'url': target, 'reason': 'outside_burp_scope'})
                return
            if target not in queued and target not in fetched and target not in files:
                # Bound pending work independently of fetch limits.
                if len(queued) >= max_files * 10 + max_pages * 10:
                    limits.add('discovery_queue')
                    return
                queued.add(target)
                queue.append((target, kind))

        def save(source_url, source, kind, base=None):
            if cancelled():
                return False
            if source_url in files:
                return True
            if len(files) >= max_files:
                limits.add('max_files')
                return False
            source = _text(source)
            raw = source.encode('utf-8')
            if stats['bytes'] + len(raw) > max_bytes:
                limits.add('max_bytes')
                return False
            sha = _digest(raw)
            file_id = _digest(source_url)[:24] + '-' + sha[:16]
            basename = urlsplit(source_url).path.rsplit('/', 1)[-1] or 'inline'
            basename = re.sub(r'[^a-zA-Z0-9._-]', '_', basename)[:65].strip('.') or 'source'
            if not re.search(r'\.(?:js|mjs|cjs)$', basename, re.I):
                basename += '.js'
            relative = os.path.join('files', file_id + '-' + basename)
            path = self._within(os.path.join(folder, relative), folder)
            if os.path.isfile(path):
                with open(path, 'rb') as handle:
                    if _digest(handle.read()) != sha:
                        failures.append({'url': source_url, 'error': 'source_file_conflict'})
                        return False
            else:
                with open(path, 'wb') as handle:
                    handle.write(raw)
                try:
                    os.chmod(path, 0o600)
                except OSError:
                    pass
            entry = {'id': file_id, 'url': source_url, 'path': relative,
                     'sha256': sha, 'chars': len(source), 'size': len(raw),
                     'kind': kind, 'line_count': source.count('\n') + 1}
            files[source_url] = entry
            stats['bytes'] += len(raw)
            emit('Saved {} JavaScript files ({} bytes)'.format(len(files), stats['bytes']))
            for ref in _js_references(source):
                if cancelled():
                    break
                enqueue(ref, base or source_url, 'script')
            return True

        enqueue(url, None, 'script' if JS_PATH.search(url) else 'page')
        for row in cached_sources or []:
            if cancelled():
                break
            try:
                cached_url = canonical_url(row.get('url'))
                if _origin(cached_url) != origin or not in_scope(cached_url):
                    continue
                if row.get('complete', row.get('body_complete', False)) is not True:
                    failures.append({'url': cached_url, 'error': 'incomplete_cached_source'})
                    continue
                source = _text(row.get('body', ''))
                if HTML_BODY.match(source):
                    failures.append({'url': cached_url, 'error': 'html_at_javascript_url'})
                    continue
                if save(cached_url, source, 'captured'):
                    stats['cached_files'] += 1
            except (ValueError, TypeError) as exc:
                failures.append({'url': _text(row.get('url')), 'error': _text(exc)})

        while queue and not cancelled():
            target, kind = queue.popleft()
            if target in fetched or target in files:
                continue
            if kind == 'page' and stats['pages'] >= max_pages:
                limits.add('max_pages')
                continue
            if len(files) >= max_files:
                limits.add('max_files')
                break
            if stats['bytes'] >= max_bytes:
                limits.add('max_bytes')
                break
            current, response, chain = target, None, set()
            for redirect in range(6):
                if cancelled():
                    break
                if not in_scope(current):
                    failures.append({'url': current, 'error': 'redirect_outside_burp_scope'})
                    break
                if kind == 'page' and _origin(current) != origin:
                    failures.append({'url': current, 'error': 'page_redirect_outside_origin'})
                    break
                if current in chain:
                    failures.append({'url': current, 'error': 'redirect_loop'})
                    break
                chain.add(current)
                fetched.add(current)
                if kind == 'page':
                    if stats['pages'] >= max_pages:
                        limits.add('max_pages')
                        break
                    stats['pages'] += 1
                stats['requests'] += 1
                emit('Collecting ' + current)
                try:
                    result = fetch(current)
                except Exception as exc:
                    failures.append({'url': current, 'error': 'fetch_failed: ' + _text(exc)[:200]})
                    break
                if not isinstance(result, dict) or not result.get('ok'):
                    failures.append({'url': current, 'error': (result or {}).get('error', 'fetch_failed') if isinstance(result, dict) else 'invalid_fetch_result'})
                    break
                try:
                    status = int(result.get('status', 0))
                except (ValueError, TypeError, OverflowError):
                    failures.append({'url': current, 'error': 'invalid_http_status'})
                    break
                if status in (301, 302, 303, 307, 308):
                    location = _header(result.get('headers'), 'location')
                    if not location or redirect == 5:
                        failures.append({'url': current, 'error': 'redirect_limit_or_missing_location'})
                        break
                    try:
                        current = canonical_url(location, current)
                    except ValueError:
                        failures.append({'url': current, 'error': 'invalid_redirect'})
                        break
                    continue
                if status < 200 or status >= 300:
                    failures.append({'url': current, 'error': 'http_status_' + str(status)})
                    break
                if result.get('body_complete') is not True:
                    failures.append({'url': current, 'error': 'incomplete_response'})
                    break
                response = result
                break
            if not response or cancelled():
                continue
            body = _text(response.get('body', ''))
            content_type = _header(response.get('headers'), 'content-type').lower().split(';')[0].strip()
            is_html = content_type in ('text/html', 'application/xhtml+xml') or bool(HTML_BODY.match(body))
            if kind == 'script' or 'javascript' in content_type or 'ecmascript' in content_type or JS_PATH.search(current):
                if is_html:
                    failures.append({'url': current, 'error': 'html_at_javascript_url'})
                elif content_type and not any(x in content_type for x in ('javascript', 'ecmascript', 'text/plain', 'octet-stream')):
                    failures.append({'url': current, 'error': 'non_javascript_content_type:' + content_type})
                else:
                    save(current, body, 'external')
                continue
            if not is_html:
                skipped.append({'url': current, 'reason': 'not_html_or_javascript'})
                continue
            stats['html_pages'] += 1
            parser = _Page()
            try:
                parser.feed(body)
                parser.close()
                base = canonical_url(parser.base, current) if parser.base else current
            except Exception as exc:
                failures.append({'url': current, 'error': 'html_parse_failed:' + _text(exc)[:200]})
                continue
            for script_kind, value, number in parser.scripts:
                if script_kind == 'inline':
                    save(current + '#inline-' + str(number), value, 'inline', base)
                else:
                    enqueue(value, base, 'script')
            for ref in parser.links:
                enqueue(ref, base, 'script' if JS_PATH.search(ref) else 'page')

        result = {'ok': True, 'stopped': stopped[0], 'root': folder,
                  'site_url': url, 'origin': origin, 'files_count': len(files),
                  'bytes': stats['bytes'], 'pages': stats['pages'],
                  'html_pages': stats['html_pages'],
                  'requests': stats['requests'], 'cached_files': stats['cached_files'],
                  'failures': failures, 'skipped': skipped,
                  'failure_count': failures.total, 'skipped_count': skipped.total,
                  'diagnostics_truncated': failures.total > len(failures) or skipped.total > len(skipped),
                  'limits_reached': sorted(limits), 'complete_discovery': False,
                  'discovery_exhausted': not stopped[0] and not limits and not failures,
                  'discovery_note': DISCOVERY_NOTE,
                  'manifest_path': os.path.join(folder, 'manifest.json')}
        manifest = dict(result)
        manifest.update({'schema_version': 1, 'collected_at': time.time(),
                         'files': sorted(files.values(), key=lambda item: item['url'])})
        self._save_manifest(folder, manifest)
        return result

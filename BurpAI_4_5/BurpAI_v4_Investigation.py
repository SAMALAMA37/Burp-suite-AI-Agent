# -*- coding: utf-8 -*-
"""Deterministic investigation state and evidence comparisons. Python 2.7/3.

No network I/O, payload generation, or automatic vulnerability verdicts.
"""
from __future__ import unicode_literals
import copy
import hashlib
import json
import time

try:
    text_type = unicode
    integer_types = (int, long)
except NameError:
    text_type = str
    integer_types = (int,)


def text(value):
    return text_type(value if value is not None else '')


def plan_metadata(item, args, tests):
    """Validate priority/dependencies before the caller commits a plan edit."""
    result = dict(item)
    for key in ('target', 'category'):
        if key in args: result[key] = text(args[key]).strip()[:240]
    priority = args.get('priority', result.get('priority', 3))
    if isinstance(priority, bool) or not isinstance(priority, integer_types) or priority not in (1, 2, 3, 4, 5):
        raise ValueError('priority_must_be_1_to_5')
    result['priority'] = priority
    deps = args.get('depends_on', result.get('depends_on', []))
    if not isinstance(deps, list) or len(deps) > 10:
        raise ValueError('depends_on_must_be_a_list_of_at_most_10_ids')
    deps = list(dict.fromkeys(text(value) for value in deps))
    known = dict((row['id'], row) for row in tests)
    if any(dep not in known or dep == item['id'] for dep in deps):
        raise ValueError('unknown_or_self_dependency')
    result['depends_on'] = deps
    known[item['id']] = result
    def visit(ref, ancestors):
        if ref in ancestors: raise ValueError('cyclic_test_dependencies')
        for dep in known[ref].get('depends_on', []):
            if dep in known: visit(dep, ancestors | set([ref]))
    visit(item['id'], set())
    return result


def plan_snapshot(tests):
    rows = copy.deepcopy(tests)
    by_id = dict((row['id'], row) for row in rows)
    ready, waiting, counts, coverage = [], [], {}, {}
    for row in rows:
        status = row.get('status', 'planned')
        counts[status] = counts.get(status, 0) + 1
        key = (row.get('target') or 'Unspecified target', row.get('category') or 'Unclassified')
        cell = coverage.setdefault(key, {'target':key[0], 'category':key[1], 'total':0,
                                        'resolved':0, 'supported':0, 'blocked':0})
        cell['total'] += 1
        if status in ('supported', 'not_reproduced'): cell['resolved'] += 1
        if status in ('supported', 'blocked'): cell[status] += 1
        if status not in ('planned', 'testing', 'inconclusive'): continue
        row['waiting_for'] = [dep for dep in row.get('depends_on', [])
            if by_id.get(dep, {}).get('status') not in ('supported', 'not_reproduced')]
        (waiting if row['waiting_for'] else ready).append(row)
    ready.sort(key=lambda row: (row.get('priority', 3),
        0 if row.get('status') == 'testing' else 1, row['id']))
    return {'tests':rows, 'counts':counts, 'ready':ready, 'waiting':waiting,
            'next_test':ready[0] if ready else None,
            'coverage':[coverage[key] for key in sorted(coverage)],
            'coverage_note':'Coverage describes planned checks only, not the whole application. '
                            'Supported is a model assessment, not a verified vulnerability.'}


def _http(payload):
    if not isinstance(payload, dict) or payload.get('error') or payload.get('ok') is False:
        raise ValueError('evidence_is_not_a_successful_http_observation')
    if payload.get('queued') and not payload.get('sent'):
        raise ValueError('queued_request_has_no_response')
    value = payload.get('entry', payload)
    if not isinstance(value, dict) or not value.get('url') or not value.get('status') or 'body' not in value:
        raise ValueError('http_response_fields_missing')
    complete = value.get('body_complete') is True or value.get('body_is_preview') is False
    body = text(value['body'])
    if not complete or '[truncated]' in body or '[decode' in body.lower():
        raise ValueError('complete_decoded_response_required')
    if len(body) > 1024 * 1024: raise ValueError('response_exceeds_comparison_limit')
    headers = value.get('resp_headers', value.get('headers', []))
    normalized = {}
    pairs = headers.items() if isinstance(headers, dict) else [
        h.split(':', 1) for h in headers if ':' in h and not h.startswith('HTTP/')]
    for key, val in pairs:
        key = text(key).strip().lower()
        normalized.setdefault(key, []).append(text(val).strip())
    return {'url':text(value['url']), 'method':text(value.get('method', 'GET')),
            'status':int(value['status']), 'body':body, 'headers':normalized,
            'request_sha256':value.get('request_sha256')}


def _json_changes(left, right, limit=60):
    changes = []
    def walk(a, b, path, depth):
        if len(changes) > limit: return
        if depth > 30:
            if a != b: changes.append(path or '/')
            return
        if isinstance(a, dict) and isinstance(b, dict):
            for key in sorted(set(a) | set(b)):
                child = path + '/' + text(key).replace('~','~0').replace('/','~1')
                if key not in a or key not in b: changes.append(child)
                else: walk(a[key], b[key], child, depth + 1)
                if len(changes) > limit: break
        elif isinstance(a, list) and isinstance(b, list):
            for i in range(max(len(a), len(b))):
                if i >= len(a) or i >= len(b): changes.append(path + '/' + text(i))
                else: walk(a[i], b[i], path + '/' + text(i), depth + 1)
                if len(changes) > limit: break
        elif type(a) != type(b) or a != b: changes.append(path or '/')
    walk(left, right, '', 0)
    return changes[:limit], len(changes) > limit


def compare_http(baseline, candidate, repeat=None, ignore_headers=None):
    """Compare exact saved HTTP results; expose paths/metadata, never body secrets."""
    a, b = _http(baseline), _http(candidate)
    if ignore_headers is None: ignore_headers = ['date', 'x-request-id', 'traceparent']
    if not isinstance(ignore_headers, list) or len(ignore_headers) > 20:
        raise ValueError('ignore_headers_must_be_a_list_of_at_most_20_names')
    ignored = set(text(h).lower().strip() for h in ignore_headers)
    if ignored & set(['location', 'set-cookie', 'www-authenticate', 'access-control-allow-origin']):
        raise ValueError('security_relevant_headers_cannot_be_ignored')
    def digest(body): return hashlib.sha256(body.encode('utf-8')).hexdigest()
    delta = {'status': [a['status'], b['status']], 'status_changed':a['status'] != b['status'],
        'body_equal':a['body'] == b['body'], 'body_chars':[len(a['body']), len(b['body'])],
        'body_sha256':[digest(a['body']), digest(b['body'])],
        'changed_headers':sorted(key for key in set(a['headers']) | set(b['headers'])
            if key not in ignored and a['headers'].get(key) != b['headers'].get(key)),
        'ignored_headers':sorted(ignored), 'same_url':a['url'] == b['url'],
        'same_method':a['method'] == b['method'], 'json_compared':False,
        'same_request':a['request_sha256'] == b['request_sha256'] if a['request_sha256'] and b['request_sha256'] else None,
        'baseline_stability':'not_checked', 'assessment':'observation_only',
        'note':'Differences do not confirm a vulnerability. Check the expected permission/behavior, '
               'request changes, session context, and reproducibility against original evidence.'}
    try:
        ja, jb = json.loads(a['body']), json.loads(b['body'])
        paths, capped = _json_changes(ja, jb)
        delta.update(json_compared=True, json_equal=not paths,
                     changed_json_paths=paths, json_paths_truncated=capped)
    except (ValueError, TypeError): pass
    if repeat is not None:
        r = _http(repeat)
        if a['url'] != r['url'] or a['method'] != r['method']:
            raise ValueError('repeat_baseline_must_match_url_and_method')
        if a['request_sha256'] and a['request_sha256'] != r['request_sha256']:
            raise ValueError('repeat_baseline_request_differs')
        stable = (a['status'] == r['status'] and a['body'] == r['body'] and
            all(a['headers'].get(k) == r['headers'].get(k)
                for k in (set(a['headers']) | set(r['headers'])) - ignored))
        delta['baseline_stability'] = 'stable_observed' if stable else 'unstable_observed'
    return delta


class Investigation(object):
    """Durable activity journal and a request-attempt budget shared across replans."""
    def __init__(self, ledger, clock=None):
        self.ledger = ledger
        self.clock = clock or time.time
        self.active = False
        with ledger.lock:
            run = ledger.data.get('investigation_run', {})
            if run.get('state') in ('running', 'paused', 'pausing'):
                run.update(state='interrupted', activity='Extension reloaded; resume explicitly.')
                ledger._persist()

    def start(self, request_limit=20):
        with self.ledger.lock:
            self.active = True
            self.ledger.data['investigation_run'] = {'state':'running', 'started':self.clock(),
                'request_limit':max(0, min(500, int(request_limit))), 'requests':0,
                'activity':'Planning the next check', 'next_step':''}
            self.ledger._persist()
        self.event('run', 'Investigation started')

    def event(self, kind, message, test_id='', evidence_id='', next_step=''):
        with self.ledger.lock:
            events = self.ledger.data.setdefault('investigation_events', [])
            events.append({'at':self.clock(), 'kind':text(kind)[:40], 'message':text(message)[:600],
                           'test_id':text(test_id)[:40], 'evidence_id':text(evidence_id)[:40],
                           'next_step':text(next_step)[:400]})
            self.ledger.data['investigation_events'] = events[-200:]
            run = self.ledger.data.setdefault('investigation_run', {})
            run['activity'] = text(message)[:600]
            if next_step: run['next_step'] = text(next_step)[:400]
            self.ledger._persist()

    def state(self, value):
        with self.ledger.lock:
            self.ledger.data.setdefault('investigation_run', {})['state'] = value
            if value in ('finished', 'stopped', 'error', 'interrupted'): self.active = False
            self.ledger._persist()

    def reserve_request(self):
        with self.ledger.lock:
            if not self.active: return {'ok':True}
            run = self.ledger.data['investigation_run']
            if run.get('state') in ('paused', 'pausing'): return {'ok':False, 'error':'investigation_paused'}
            if run['requests'] >= run['request_limit']:
                return {'ok':False, 'error':'investigation_request_budget_exhausted',
                        'hint':'Review saved evidence or finish the run. A new run gets a fresh budget.'}
            run['requests'] += 1  # Count attempts before I/O, including ambiguous failures.
            self.ledger._persist()
            return {'ok':True}

    def snapshot(self):
        with self.ledger.lock:
            result = plan_snapshot(self.ledger.data.get('test_plan', []))
            result['run'] = copy.deepcopy(self.ledger.data.get('investigation_run', {}))
            result['events'] = copy.deepcopy(self.ledger.data.get('investigation_events', [])[-60:])
            return result

    def report(self):
        snapshot = self.snapshot()
        lines = ['# Investigation checkpoint', '', snapshot['coverage_note'], '',
                 'Run state: ' + snapshot['run'].get('state', 'idle'),
                 'Request attempts: {}/{}'.format(snapshot['run'].get('requests',0),snapshot['run'].get('request_limit',0)),
                 '', '## Tests', '']
        for row in snapshot['tests']:
            lines.extend(['### ' + row['id'] + ': ' + row['title'], '',
                'Status: ' + row['status'] + ' | Priority: ' + text(row.get('priority', 3)),
                'Target: ' + row.get('target', 'Unspecified'),
                'Category: ' + row.get('category', 'Unclassified'), '',
                'Hypothesis: ' + row.get('hypothesis', ''),
                'Baseline: ' + row.get('baseline', ''), 'Check: ' + row.get('check', ''),
                'Result: ' + row.get('result', 'Not completed'),
                'Evidence: ' + ', '.join(row.get('evidence_ids', [])),
                'Next step: ' + row.get('next_step', ''), ''])
        if not snapshot['tests']: lines.extend(['No tests recorded. Coverage is unknown.', ''])
        lines.extend(['## Activity (latest 60 events)', ''])
        for event in snapshot['events']:
            lines.append('- ' + time.strftime('%H:%M:%S', time.localtime(event['at'])) + ' ' +
                         event['message'] + (' [' + event['evidence_id'] + ']' if event['evidence_id'] else '') +
                         (' Next: ' + event['next_step'] if event.get('next_step') else ''))
        return '\n'.join(lines)

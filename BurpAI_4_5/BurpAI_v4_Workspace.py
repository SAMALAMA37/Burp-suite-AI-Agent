# -*- coding: utf-8 -*-
"""Persistent site notes with source-linked relationships.

Portable on CPython/Jython. Model-written notes are hypotheses or observations, not verified facts.
No source is executed and this module makes no target HTTP requests.
"""
from __future__ import division
import json
import os
import re
import threading
import time
import uuid
from BurpAI_v4_Semantic import _atomic_json, _text


def _terms(text):
    return set(re.findall(r'[a-z][a-z0-9_]{2,}', _text(text).lower()))


class SiteWorkspace(object):
    def __init__(self, root):
        self.root = os.path.abspath(root)
        self.lock = threading.RLock()

    def _read(self, name):
        path = os.path.join(self.root, name + '.json')
        if not os.path.isfile(path): return {}
        if os.path.islink(path): raise ValueError('workspace_link_not_allowed')
        with open(path, 'rb') as handle:
            value = json.loads(handle.read().decode('utf-8'))
        if not isinstance(value, dict): raise ValueError('invalid_workspace_data')
        return value

    def _write(self, name, value):
        _atomic_json(os.path.join(self.root, name + '.json'), value)

    def save_note(self, title, text, sources, current_files, kind='hypothesis',
                  note_id=None, related=None, mission=None):
        title, text = _text(title).strip(), _text(text).strip()
        if not title or not text or len(title) > 180 or len(text) > 6000:
            raise ValueError('note_requires_title_and_text_within_limits')
        if kind not in ('hypothesis', 'observation', 'todo', 'conclusion'):
            raise ValueError('invalid_note_kind')
        available = dict((f['id'], f) for f in current_files)
        checked = []
        for source in sources or []:
            fid = source.get('file_id')
            if fid not in available: raise ValueError('unknown_or_out_of_scope_file')
            row = available[fid]
            start, end = int(source.get('start_line', 1)), int(source.get('end_line', source.get('start_line', 1)))
            if start < 1 or end < start or end > int(row.get('line_count') or end):
                raise ValueError('invalid_source_lines')
            checked.append({'file_id': fid, 'sha256': row['sha256'],
                            'start_line': start, 'end_line': end})
        with self.lock:
            data = self._read('mind_map')
            notes = data.setdefault('notes', {})
            if note_id and note_id not in notes: raise ValueError('unknown_note_id')
            related = related or []
            if any(r not in notes for r in related): raise ValueError('unknown_related_note')
            nid = note_id or 'note-' + uuid.uuid4().hex[:16]
            notes[nid] = {'id': nid, 'title': title, 'text': text, 'kind': kind,
                          'sources': checked, 'related': list(related), 'mission': mission,
                          'updated': int(time.time()), 'model_authored': True}
            self._write('mind_map', data)
            return {'ok': True, 'note': notes[nid]}

    def notes(self, files, query='', limit=30):
        current = dict((f['id'], f) for f in files)
        wanted = _terms(query)
        found = []
        for note in self._read('mind_map').get('notes', {}).values():
            score = len(wanted & _terms(note['title'] + ' ' + note['text']))
            if wanted and not score: continue
            row = dict(note)
            row['sources'] = [dict(s, current=bool(s['file_id'] in current and
                               current[s['file_id']]['sha256'] == s['sha256']))
                              for s in note.get('sources', [])]
            row['stale_sources'] = any(not s['current'] for s in row['sources'])
            found.append((score, row))
        found.sort(key=lambda r: (-r[0], -r[1]['updated'], r[1]['id']))
        return {'ok': True, 'total': len(found), 'notes': [r[1] for r in found[:limit]],
                'more': len(found) > limit}


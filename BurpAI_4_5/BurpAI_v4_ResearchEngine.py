#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""BurpAI v4 local, PASSIVE research engine (Python 3.9+; standard library only).

This service does not fetch sites, run subprocesses, control Burp, or run exploits.
All inbound evidence is data; all observations require source provenance.
"""
from __future__ import annotations
import argparse
import contextlib
import hashlib
import hmac
import json
import os
from pathlib import Path
from bisect import bisect_right
import re
import secrets
import sqlite3
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

PROTOCOL = 1
DB_VERSION = 1
MAX_BODY = 12 * 1024 * 1024
MAX_SOURCE = 8 * 1024 * 1024
IDENT_RE = re.compile(r'^[A-Za-z0-9:_./-]{1,160}$')
SHA_RE = re.compile(r'^[0-9a-f]{64}$')
SENSITIVE = re.compile(r'(?i)(bearer\s+\S+|(?:password|token|api[_-]?key|secret)\s*[:=]\s*["\']?[^\s,"\']+)')


def to_json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'))


def digest_bytes(data):
    return hashlib.sha256(data).hexdigest()


def utc_time():
    return int(time.time())


def secure_dir(path):
    path = Path(path).expanduser().resolve()
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name == 'posix':
        os.chmod(str(path), 0o700)
    return path


def secure_write_once(path, content):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    # A preexisting object is validated, never overwritten.
    if path.exists():
        if path.is_symlink() or path.read_bytes() != content:
            raise ValueError('object_file_conflict')
        return
    fd, tmp = tempfile.mkstemp(prefix='.pending-', dir=str(path.parent))
    try:
        with os.fdopen(fd, 'wb') as f:
            if os.name == 'posix':
                os.fchmod(f.fileno(), 0o600)
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        # New blob is content-addressed: an existing destination must match.
        if path.exists():
            if path.read_bytes() != content:
                raise ValueError('object_file_conflict')
        else:
            os.replace(tmp, path)
            tmp = None
    finally:
        if tmp and os.path.exists(tmp):
            os.unlink(tmp)


class EngineError(Exception):
    def __init__(self, code, status=400):
        super().__init__(code)
        self.code, self.status = code, status


def clean_id(value, name='identifier'):
    if not isinstance(value, str) or not IDENT_RE.fullmatch(value):
        raise EngineError('invalid_' + name)
    return value


def clean_url(value):
    if not isinstance(value, str) or len(value) > 4096:
        raise EngineError('invalid_url')
    u = urlparse(value)
    if u.scheme not in ('https', 'http') or not u.hostname or u.username or u.password:
        raise EngineError('invalid_url')
    if any(ord(c) < 32 for c in value):
        raise EngineError('invalid_url')
    return value


def js_mask_comments(src):
    """Return comment-masked JS with offsets/newlines preserved.

    Handles standard strings, template strings and line/block comments. This is
    a robust lexical fallback, NOT an ECMAScript AST or full semantic parser.
    """
    out = list(src)
    n, i, state = len(src), 0, 'code'
    quote = ''
    while i < n:
        c = src[i]
        d = src[i + 1] if i + 1 < n else ''
        if state == 'line':
            if c == '\n': state = 'code'
            else: out[i] = ' '
        elif state == 'block':
            if c == '*' and d == '/':
                out[i] = out[i + 1] = ' '; i += 1; state = 'code'
            elif c != '\n': out[i] = ' '
        elif state == 'string':
            if c == '\\': i += 1
            elif c == quote: state = 'code'
        else:
            if c == '/' and d == '/': out[i] = out[i+1] = ' '; i += 1; state = 'line'
            elif c == '/' and d == '*': out[i] = out[i+1] = ' '; i += 1; state = 'block'
            elif c in ('"', "'", '`'): state = 'string'; quote = c
        i += 1
    return ''.join(out)


# Patterns recognize literal references. Deducing runtime flows is explicitly
# outside their scope. We maintain source positions and never claim a vulnerability.
JS_PATTERNS = [
    ('fetch', re.compile(r'''\bfetch\s*\(\s*(["'`])([^"'`\n]{1,500})\1''')),
    ('axios', re.compile(r'''\baxios\s*\.\s*(?:get|post|put|delete|patch|head)\s*\(\s*(["'`])([^"'`\n]{1,500})\1''')),
    ('xhr', re.compile(r'''\bopen\s*\(\s*(["'])(GET|POST|PUT|PATCH|DELETE|HEAD)\1\s*,\s*(["'`])([^"'`\n]{1,500})\3''')),
    ('api_literal', re.compile(r'''(["'`])(/(?:api|graphql|v\d+|rest|rpc|auth|users)/?[a-zA-Z0-9_/?&=.:{}$-]{0,450})\1''')),
]
JS_SIGNALS = [
    ('dom_assignment', re.compile(r'\.\s*innerHTML\s*=')),
    ('dynamic_eval', re.compile(r'\beval\s*\(')),
    ('message_listener', re.compile(r'''\baddEventListener\s*\(\s*["']message["']''')),
    ('storage_access', re.compile(r'\b(?:localStorage|sessionStorage)\s*(?:\.|\[)')),
]


def analyze_js(source):
    """Deterministic passive observations; offsets are Unicode code point offsets."""
    code = js_mask_comments(source)
    newlines = [i for i, c in enumerate(code) if c == '\n']
    findings = []
    seen = set()
    capped_patterns = []
    per_pattern_ceiling = 300
    for tag, pattern in JS_PATTERNS:
        pattern_count = 0
        for m in pattern.finditer(code):
            if pattern_count >= per_pattern_ceiling:
                capped_patterns.append(tag)
                break
            value_group = 4 if tag == 'xhr' else 2
            val = m.group(value_group)
            if val.startswith(('javascript:', 'data:')): continue
            pos = m.start(value_group)
            key = ('endpoint_reference', pos, val)
            if key in seen: continue
            seen.add(key)
            pattern_count += 1
            findings.append({'kind': 'endpoint_reference', 'category': tag,
                             'value': val, 'offset': pos,
                             'line': bisect_right(newlines,pos) + 1,
                             'excerpt': source[max(0, pos-60):min(len(source), pos+min(len(val), 180)+60)]})
    for tag, pattern in JS_SIGNALS:
        pattern_count = 0
        for m in pattern.finditer(code):
            if pattern_count >= per_pattern_ceiling:
                capped_patterns.append(tag)
                break
            pattern_count += 1
            pos = m.start()
            findings.append({'kind': 'code_signal', 'category': tag,
                             'value': tag, 'offset': pos,
                             'line': bisect_right(newlines,pos) + 1,
                             'excerpt': source[max(0, pos-60):min(len(source), pos+100)]})
    # Avoid overwhelming the evidence index for huge or minified assets.
    return {'parser': 'lexical-v1', 'complete': not bool(capped_patterns),
            'observations': findings,
            'observation_count': len(findings),
            'observation_count_is_lower_bound':bool(capped_patterns),
            'indexed_count': len(findings),
            'index_truncated': bool(capped_patterns),
            'capped_patterns':capped_patterns,
            'line_count': len(newlines) + 1}


class ResearchDB:
    """SQLite source of truth, transactionally commits analysis + task status."""
    def __init__(self, root):
        self.root = secure_dir(root)
        self.blobs = secure_dir(self.root / 'v4_blobs')
        self.dbfile = self.root / 'research_v4.sqlite3'
        self.lock = threading.RLock()
        self.conn = sqlite3.connect(str(self.dbfile), timeout=20, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute('PRAGMA busy_timeout=20000')
        self.conn.execute('PRAGMA foreign_keys=ON')
        self.conn.execute('PRAGMA journal_mode=WAL')
        self.conn.execute('PRAGMA synchronous=FULL')
        self._migrate()
        if os.name == 'posix':
            os.chmod(str(self.dbfile), 0o600)
        # FTS is optional for constrained Python/SQLite builds; exact/LIKE
        # retrieval stays available even when the module is missing.
        self.fts_available = False
        try:
            with self.tx() as db:
                db.execute("""CREATE VIRTUAL TABLE IF NOT EXISTS observations_fts
                             USING fts5(id UNINDEXED,mission UNINDEXED,category,value,excerpt)""")
                db.execute("""CREATE TRIGGER IF NOT EXISTS observations_fts_insert
                             AFTER INSERT ON observations BEGIN
                             INSERT INTO observations_fts(id,mission,category,value,excerpt)
                             VALUES (new.id,new.mission,new.category,new.value,new.excerpt);
                             END""")
                db.execute("""INSERT INTO observations_fts(id,mission,category,value,excerpt)
                             SELECT o.id,o.mission,o.category,o.value,o.excerpt
                             FROM observations o LEFT JOIN observations_fts f ON f.id=o.id
                             WHERE f.id IS NULL""")
            self.fts_available = True
        except sqlite3.OperationalError:
            self.fts_available = False

    def close(self):
        with self.lock: self.conn.close()

    @contextlib.contextmanager
    def tx(self):
        with self.lock:
            self.conn.execute('BEGIN IMMEDIATE')
            try:
                yield self.conn
                self.conn.commit()
            except Exception:
                self.conn.rollback()
                raise

    def _migrate(self):
        with self.tx() as db:
            db.executescript('''
                CREATE TABLE IF NOT EXISTS schema_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS missions (
                    mission TEXT PRIMARY KEY, created INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS sources (
                    sha TEXT PRIMARY KEY, size INTEGER NOT NULL, language TEXT NOT NULL,
                    object_path TEXT NOT NULL, created INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS source_versions (
                    mission TEXT NOT NULL REFERENCES missions(mission),
                    url TEXT NOT NULL, sha TEXT NOT NULL REFERENCES sources(sha),
                    first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL,
                    PRIMARY KEY(mission,url,sha));
                CREATE TABLE IF NOT EXISTS tasks (
                    id TEXT PRIMARY KEY, mission TEXT NOT NULL REFERENCES missions(mission),
                    task_type TEXT NOT NULL, source_sha TEXT REFERENCES sources(sha),
                    state TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0,
                    detail TEXT NOT NULL DEFAULT '{}', updated INTEGER NOT NULL,
                    UNIQUE(mission,task_type,source_sha));
                CREATE TABLE IF NOT EXISTS observations (
                    id TEXT PRIMARY KEY, mission TEXT NOT NULL REFERENCES missions(mission),
                    source_sha TEXT NOT NULL REFERENCES sources(sha),
                    kind TEXT NOT NULL, category TEXT NOT NULL, value TEXT NOT NULL,
                    offset INTEGER NOT NULL, line INTEGER NOT NULL, excerpt TEXT NOT NULL,
                    created INTEGER NOT NULL);
                CREATE INDEX IF NOT EXISTS obs_by_mission_source ON observations(mission,source_sha);
                CREATE INDEX IF NOT EXISTS obs_by_kind ON observations(mission,kind,category);
                CREATE INDEX IF NOT EXISTS obs_by_value ON observations(mission,value);
                CREATE TABLE IF NOT EXISTS relations (
                    mission TEXT NOT NULL REFERENCES missions(mission),
                    src_id TEXT NOT NULL, predicate TEXT NOT NULL,
                    dst_id TEXT NOT NULL, evidence_id TEXT NOT NULL REFERENCES observations(id),
                    PRIMARY KEY(mission,src_id,predicate,dst_id,evidence_id));
                CREATE TABLE IF NOT EXISTS findings (
                    id TEXT PRIMARY KEY, mission TEXT NOT NULL REFERENCES missions(mission),
                    title TEXT NOT NULL, summary TEXT NOT NULL,
                    state TEXT NOT NULL, created INTEGER NOT NULL, updated INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS finding_evidence (
                    finding_id TEXT NOT NULL REFERENCES findings(id),
                    evidence_id TEXT NOT NULL REFERENCES observations(id),
                    role TEXT NOT NULL CHECK(role IN ('support','contradict','verification')),
                    PRIMARY KEY(finding_id,evidence_id,role));
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, mission TEXT NOT NULL,
                    kind TEXT NOT NULL, payload TEXT NOT NULL, created INTEGER NOT NULL);
                CREATE INDEX IF NOT EXISTS events_mission ON events(mission,id);
                CREATE TABLE IF NOT EXISTS imports (
                    import_key TEXT PRIMARY KEY, completed INTEGER NOT NULL);
            ''')
            # DDL executescript may commit an implicit transaction in sqlite3;
            # the outer tx still safely commits remaining schema bookkeeping.
            db.execute('INSERT OR REPLACE INTO schema_meta(key,value) VALUES (?,?)',
                       ('schema_version', str(DB_VERSION)))

    def _blob_path(self, sha):
        if not SHA_RE.fullmatch(sha): raise EngineError('invalid_hash')
        return self.blobs / sha[:2] / (sha + '.blob')

    def _mission(self, db, mission):
        clean_id(mission, 'mission')
        db.execute('INSERT OR IGNORE INTO missions(mission,created) VALUES (?,?)', (mission,utc_time()))

    def ingest_js(self, mission, url, source, expected_sha=None):
        clean_id(mission,'mission')
        clean_url(url)
        if not isinstance(source,str): raise EngineError('source_must_be_text')
        raw = source.encode('utf-8')
        if len(raw) > MAX_SOURCE: raise EngineError('source_too_large',413)
        sha = digest_bytes(raw)
        if expected_sha and expected_sha != sha: raise EngineError('source_hash_mismatch')
        secure_write_once(self._blob_path(sha), raw)
        scan = analyze_js(source)
        task_id = 'JS-' + hashlib.sha256((mission + ':' + sha).encode()).hexdigest()[:24]
        now = utc_time()
        with self.tx() as db:
            self._mission(db,mission)
            db.execute('INSERT OR IGNORE INTO sources VALUES (?,?,?,?,?)',
                       (sha,len(raw),'javascript',str(self._blob_path(sha)),now))
            db.execute('''INSERT INTO source_versions VALUES (?,?,?,?,?)
                          ON CONFLICT(mission,url,sha) DO UPDATE SET last_seen=excluded.last_seen''',
                       (mission,url,sha,now,now))
            existing = db.execute('SELECT state FROM tasks WHERE id=?', (task_id,)).fetchone()
            if not existing:
                db.execute('''INSERT INTO tasks (id,mission,task_type,source_sha,state,attempts,detail,updated)
                              VALUES (?,?,?,?,?,?,?,?)''',
                           (task_id,mission,'passive_js',sha,'running',1,'{}',now))
            if not existing or existing['state'] != 'completed':
                for obs in scan['observations']:
                    identity = [mission,sha,obs['kind'],obs['category'],obs['offset'],obs['value']]
                    obs_id = 'OBS-' + hashlib.sha256(to_json(identity).encode()).hexdigest()[:28]
                    db.execute('''INSERT OR IGNORE INTO observations
                        (id,mission,source_sha,kind,category,value,offset,line,excerpt,created)
                        VALUES (?,?,?,?,?,?,?,?,?,?)''',
                        (obs_id,mission,sha,obs['kind'],obs['category'],obs['value'],
                         obs['offset'],obs['line'],obs['excerpt'][:500],now))
                    dest_kind = 'END' if obs['kind']=='endpoint_reference' else 'SIG'
                    entity = dest_kind+'-'+hashlib.sha256(
                        to_json([mission,obs['value']]).encode()).hexdigest()[:24]
                    db.execute('''INSERT OR IGNORE INTO relations
                         (mission,src_id,predicate,dst_id,evidence_id) VALUES (?,?,?,?,?)''',
                        (mission,'SRC-'+sha,'references_endpoint' if dest_kind=='END'
                            else 'has_code_signal',entity,obs_id))
                    # A code signal is just a review candidate. It is NOT a verified vulnerability.
                    if obs['kind'] == 'code_signal':
                        fid = 'FIND-' + hashlib.sha256((mission + ':' + obs_id).encode()).hexdigest()[:24]
                        db.execute('''INSERT OR IGNORE INTO findings VALUES (?,?,?,?,?,?,?)''',
                           (fid,mission,'Review ' + obs['category'],
                            'Static code signal, requires human review and independent verification.',
                            'candidate',now,now))
                        db.execute('''INSERT OR IGNORE INTO finding_evidence VALUES (?,?,?)''',
                                   (fid,obs_id,'support'))
                db.execute('UPDATE tasks SET state=?, detail=?, updated=? WHERE id=?',
                           ('completed',to_json({'parser':scan['parser'],
                                'indexed':scan['indexed_count'],
                                'truncated':scan['index_truncated']}),now,task_id))
                db.execute('INSERT INTO events(mission,kind,payload,created) VALUES (?,?,?,?)',
                           (mission,'source_indexed',to_json({'sha':sha,'task':task_id}),now))
        return {'sha256':sha,'task':task_id,'state':'completed','reused':bool(existing and existing['state']=='completed'),
                'observation_count':scan['observation_count'],
                'indexed_count':scan['indexed_count'],
                'index_truncated':scan['index_truncated'],
                'capped_patterns':scan['capped_patterns'],
                'source_bytes':len(raw),'analysis':'passive','parser':scan['parser']}

    def status(self, mission):
        clean_id(mission,'mission')
        with self.lock:
            db=self.conn
            def scalar(table):
                return db.execute('SELECT count(*) FROM '+table+' WHERE mission=?',(mission,)).fetchone()[0]
            counts={k:scalar(k) for k in ('source_versions','tasks','observations','findings','events')}
            task_states={x[0]:x[1] for x in db.execute(
                'SELECT state,count(*) FROM tasks WHERE mission=? GROUP BY state',(mission,))}
            return {'mission':mission,'counts':counts,'task_states':task_states,
                    'db_version':DB_VERSION,'provider':'local-passive-engine',
                    'no_network_execution':True,'fts_available':self.fts_available}

    def search(self, mission, query, limit=25, source_sha=None):
        clean_id(mission,'mission')
        if not isinstance(query,str) or len(query)>256: raise EngineError('invalid_query')
        limit=min(max(int(limit),1),100)
        # Escape LIKE metacharacters to avoid unexpectedly broad results.
        needle='%'+query.lower().replace('\\','\\\\').replace('%','\\%').replace('_','\\_')+'%'
        args=[mission,needle,needle,needle]
        # Use full-text indexed search for normal terms and quoted phrases.
        # Wildcard/short-substring queries still use exact LIKE fallback.
        if self.fts_available and query.strip() and len(query.strip()) > 2:
            safe_query='"'+query.strip().replace('"','""')+'"'
            try:
                with self.lock:
                    ids=self.conn.execute('''SELECT o.id,o.kind,o.category,o.value,o.line,o.offset,o.source_sha
                        FROM observations_fts f JOIN observations o ON f.id=o.id
                        WHERE observations_fts MATCH ? AND f.mission=?
                        ORDER BY rank LIMIT ?''',
                        (safe_query,mission,limit)).fetchall()
                if ids:
                    if source_sha: ids=[x for x in ids if x['source_sha']==source_sha]
                    return {'results':[dict(row) for row in ids],'count':len(ids),
                            'search_mode':'fts5'}
            except sqlite3.OperationalError:
                pass
        filter_sha=''
        if source_sha:
            if not SHA_RE.fullmatch(source_sha): raise EngineError('invalid_hash')
            filter_sha=' AND source_sha=?'; args.append(source_sha)
        args.append(limit)
        with self.lock:
            rows=self.conn.execute('''SELECT id,kind,category,value,line,offset,source_sha
                FROM observations WHERE mission=? AND
                (lower(value) LIKE ? ESCAPE '\\' OR lower(category) LIKE ? ESCAPE '\\'
                 OR lower(excerpt) LIKE ? ESCAPE '\\')'''+filter_sha+
                ' ORDER BY created DESC,id LIMIT ?',args).fetchall()
        return {'results':[dict(row) for row in rows],'count':len(rows),'search_mode':'literal'}

    def correlate_endpoints(self, mission, limit=60):
        clean_id(mission,'mission')
        limit=min(max(int(limit),1),150)
        with self.lock:
            rows=self.conn.execute('''SELECT value AS endpoint,COUNT(*) AS observations,
                COUNT(DISTINCT source_sha) AS source_versions
                FROM observations WHERE mission=? AND kind='endpoint_reference'
                GROUP BY value ORDER BY source_versions DESC,observations DESC,value LIMIT ?''',
                (mission,limit)).fetchall()
            return {'endpoints':[dict(row) for row in rows],
                    'count':len(rows),'interpretation':'Observed references, not proof of accessibility'}

    def render_report(self, mission, limit=100):
        clean_id(mission,'mission')
        info=self.status(mission)
        findings=self.list_findings(mission,limit=limit)['findings']
        endpoints=self.correlate_endpoints(mission,limit=limit)['endpoints']
        lines=['# BurpAI passive research report', '',
               'Mission: `'+mission+'`',
               'Generated from local captured sources. No live tests performed.', '',
               '## Coverage', '',
               '- Source observations: '+str(info['counts']['source_versions']),
               '- Indexed observations: '+str(info['counts']['observations']),
               '- Review items: '+str(info['counts']['findings']), '',
               '## Observed endpoint references', '']
        for ep in endpoints:
            lines.append('- `'+ep['endpoint'].replace('`','\\`')+'` — '+str(ep['source_versions'])+' source versions')
        lines.extend(['','## Review items',''])
        for f in findings:
            ev=f['evidence'][0] if f['evidence'] else None
            where=('source SHA256 `'+ev['source_sha']+'`, line '+str(ev['line'])) if ev else 'no evidence'
            lines.extend(['- **'+f['title']+'** ['+f['state']+'] — '+where,
                          '  - '+f['summary']])
        lines.extend(['','*Important: static-code signals are not automatically security vulnerabilities.*'])
        output='\n'.join(lines)
        return {'markdown':output[:160000],'truncated':len(output)>160000}

    def list_findings(self, mission, state=None, limit=50):
        clean_id(mission,'mission')
        if state is not None and state not in ('candidate','corroborated','verified','rejected','inconclusive'):
            raise EngineError('invalid_state')
        limit=min(max(int(limit),1),200)
        where='mission=?'+(' AND state=?' if state else '')
        vals=[mission]+([state] if state else [])+[limit]
        with self.lock:
            rows=self.conn.execute('SELECT * FROM findings WHERE '+where+' ORDER BY updated DESC,id LIMIT ?',vals).fetchall()
            out=[]
            for row in rows:
                item=dict(row)
                item['evidence']=[dict(r) for r in self.conn.execute('''
                    SELECT fe.evidence_id,fe.role,o.source_sha,o.line,o.offset,o.value
                    FROM finding_evidence fe JOIN observations o ON o.id=fe.evidence_id
                    WHERE fe.finding_id=? ORDER BY fe.role,fe.evidence_id''',(row['id'],))]
                out.append(item)
            return {'findings':out,'count':len(out)}

    def review_finding(self, mission, finding_id, state, reviewer, evidence_id=None):
        clean_id(mission,'mission')
        clean_id(finding_id,'finding')
        if state not in ('candidate','corroborated','verified','rejected','inconclusive'):
            raise EngineError('invalid_state')
        if not isinstance(reviewer,str) or not 1 <= len(reviewer) <= 120:
            raise EngineError('reviewer_required')
        if state == 'verified':
            raise EngineError('use_explicit_human_attestation_for_verification')
        with self.tx() as db:
            row=db.execute('SELECT state FROM findings WHERE mission=? AND id=?',
                (mission,finding_id)).fetchone()
            if not row: raise EngineError('finding_not_found',404)
            if evidence_id:
                obs=db.execute('SELECT id FROM observations WHERE mission=? AND id=?',
                    (mission,evidence_id)).fetchone()
                if not obs: raise EngineError('evidence_not_in_mission')
                role='verification' if state=='verified' else 'support'
                db.execute('INSERT OR IGNORE INTO finding_evidence VALUES (?,?,?)',
                           (finding_id,evidence_id,role))
            db.execute('UPDATE findings SET state=?,updated=? WHERE mission=? AND id=?',
                       (state,utc_time(),mission,finding_id))
            db.execute('INSERT INTO events(mission,kind,payload,created) VALUES (?,?,?,?)',
                (mission,'finding_reviewed',to_json({'id':finding_id,'new_state':state,
                          'reviewer':reviewer}),utc_time()))
        return {'finding':finding_id,'state':state,'reviewer':reviewer,
                'verification_is_human_attestation':state=='verified'}

    def attest_finding(self, mission, finding_id, reviewer, procedure, reference, outcome):
        """Explicit human statement; does not perform active testing.

        Verified here means a named reviewer attested to a specific external
        verification reference and procedure. This is never invoked by the LLM.
        """
        clean_id(mission,'mission')
        clean_id(finding_id,'finding')
        if outcome not in ('confirmed','refuted','inconclusive'):
            raise EngineError('invalid_attestation_outcome')
        for name, value, min_len, max_len in (
                ('reviewer',reviewer,2,120),('procedure',procedure,20,4000),
                ('reference',reference,8,1024)):
            if not isinstance(value,str) or not min_len<=len(value)<=max_len:
                raise EngineError('invalid_'+name)
        note={'reviewer':reviewer,'procedure':procedure,'reference':reference,
              'outcome':outcome,'finding':finding_id,'created':utc_time()}
        raw=to_json(note).encode('utf-8')
        sha=digest_bytes(raw)
        secure_write_once(self._blob_path(sha),raw)
        oid='OBS-'+hashlib.sha256((mission+':attestation:'+sha).encode()).hexdigest()[:28]
        new_state={'confirmed':'verified','refuted':'rejected',
                   'inconclusive':'inconclusive'}[outcome]
        with self.tx() as db:
            found=db.execute('SELECT id FROM findings WHERE mission=? AND id=?',
                             (mission,finding_id)).fetchone()
            if not found: raise EngineError('finding_not_found',404)
            db.execute('INSERT OR IGNORE INTO sources VALUES (?,?,?,?,?)',
                       (sha,len(raw),'human-attestation',str(self._blob_path(sha)),utc_time()))
            db.execute('''INSERT OR IGNORE INTO observations
                   (id,mission,source_sha,kind,category,value,offset,line,excerpt,created)
                   VALUES (?,?,?,?,?,?,?,?,?,?)''',
                (oid,mission,sha,'verification_record','human-attestation',
                 reference[:400],0,1,procedure[:500],utc_time()))
            role='verification' if outcome=='confirmed' else 'contradict'
            db.execute('INSERT OR IGNORE INTO finding_evidence VALUES (?,?,?)',
                       (finding_id,oid,role))
            db.execute('UPDATE findings SET state=?,updated=? WHERE id=? AND mission=?',
                       (new_state,utc_time(),finding_id,mission))
            db.execute('INSERT INTO events(mission,kind,payload,created) VALUES (?,?,?,?)',
                       (mission,'human_attestation',to_json({'finding':finding_id,
                            'evidence':oid,'state':new_state,'reviewer':reviewer}),utc_time()))
        return {'state':new_state,'finding':finding_id,'observation_id':oid,
                'source_sha256':sha,'human_attested':True,
                'verification_proof_not_independently_validated':True}

    def import_v3(self, limit=1000):
        """Import exact local source objects from prior v3 index. No network activity.

        Imported sources have no mission-level attribution unless v3 provides one:
        they are indexed in a clearly labeled legacy-import mission.
        """
        idx=self.root/'sources_v3'/'index.json'
        if not idx.exists(): return {'imported':0,'skipped':0,'reason':'no_v3_index'}
        metadata=json.loads(idx.read_text(encoding='utf-8'))
        urls=metadata.get('urls',{})
        imported=skipped=0
        for url, hashes in list(urls.items())[:limit]:
            for sha in hashes:
                if not SHA_RE.fullmatch(sha): skipped+=1;continue
                source_path=self.root/'sources_v3'/'objects'/sha[:2]/(sha+'.bin')
                try:
                    raw=source_path.read_bytes()
                    if digest_bytes(raw)!=sha or len(raw)>MAX_SOURCE: raise ValueError('bad legacy source')
                    self.ingest_js('legacy-v3-import',url,raw.decode('utf-8','strict'),expected_sha=sha)
                    imported+=1
                except Exception:
                    skipped+=1
        return {'imported':imported,'skipped':skipped,
                'mission':'legacy-v3-import','legacy_data_preserved':True}


class ResearchServer(ThreadingHTTPServer):
    daemon_threads=True
    allow_reuse_address=True
    def __init__(self, address, db, token):
        self.db=db; self.token=token
        self.workslots=threading.BoundedSemaphore(4)
        super().__init__(address, ResearchHandler)


class ResearchHandler(BaseHTTPRequestHandler):
    server_version='BurpAIResearch/4'
    sys_version=''
    def log_message(self, fmt, *args):
        # Do not log request bodies or authentication material.
        sys.stderr.write('[sidecar] %s\n'%fmt.replace('%s','{}').format(*[str(x)[:120] for x in args]))

    def _respond(self, status, data):
        body=to_json(data).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type','application/json; charset=utf-8')
        self.send_header('Cache-Control','no-store')
        self.send_header('Content-Length',str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self._respond(405,{'ok':False,'error':'post_only'})

    def do_POST(self):
        if self.path!='/v1/rpc':
            self._respond(404,{'ok':False,'error':'unknown_path'});return
        auth=self.headers.get('X-BurpAI-Token','')
        if not hmac.compare_digest(auth,self.server.token):
            self._respond(401,{'ok':False,'error':'unauthorized'});return
        if self.headers.get('Content-Encoding'):
            self._respond(415,{'ok':False,'error':'content_encoding_not_supported'});return
        try:
            n=int(self.headers.get('Content-Length','-1'))
        except (ValueError,TypeError):n=-1
        if n<2 or n>MAX_BODY:
            self._respond(413,{'ok':False,'error':'invalid_body_size'});return
        if not self.server.workslots.acquire(blocking=False):
            self._respond(503,{'ok':False,'error':'busy'});return
        try:
            self.connection.settimeout(30)
            raw=self.rfile.read(n)
            if len(raw) != n: raise EngineError('truncated_request_body')
            body=json.loads(raw.decode('utf-8','strict'))
            if not isinstance(body,dict) or body.get('protocol_version')!=PROTOCOL:
                raise EngineError('protocol_mismatch')
            action=body.get('action')
            mission=body.get('mission_id')
            request=body.get('request_id')
            clean_id(request,'request')
            clean_id(mission,'mission')
            payload=body.get('payload') or {}
            if not isinstance(payload,dict):raise EngineError('invalid_payload')
            db=self.server.db
            if action=='status': result=db.status(mission)
            elif action=='ingest_js':
                result=db.ingest_js(mission,payload.get('url'),payload.get('source'),
                                    payload.get('expected_sha'))
            elif action=='search':
                result=db.search(mission,payload.get('query',''),payload.get('limit',25),
                                 payload.get('source_sha'))
            elif action=='findings':
                result=db.list_findings(mission,payload.get('state'),payload.get('limit',50))
            elif action=='correlate':
                result=db.correlate_endpoints(mission,payload.get('limit',60))
            elif action=='report':
                result=db.render_report(mission,payload.get('limit',100))
            elif action=='attest':
                # Sidecar has no active testing; reviewer supplies independent evidence.
                if payload.get('human_confirmation') is not True:
                    raise EngineError('human_confirmation_required')
                result=db.attest_finding(mission,payload.get('finding_id'),
                    payload.get('reviewer'),payload.get('procedure'),
                    payload.get('reference'),payload.get('outcome'))
            elif action=='review':
                # Deliberately human-review-only; the Burp model bridge never exposes it.
                # CLI call / authenticated operator must provide explicit confirmation.
                if payload.get('human_confirmation') is not True:
                    raise EngineError('human_confirmation_required')
                result=db.review_finding(mission,payload.get('finding_id'),
                     payload.get('state'),payload.get('reviewer'),payload.get('evidence_id'))
            else:raise EngineError('unknown_action',404)
            self._respond(200,{'ok':True,'request_id':request,'result':result})
        except EngineError as ex:
            self._respond(ex.status,{'ok':False,'error':ex.code})
        except (json.JSONDecodeError,UnicodeError,ValueError,TypeError):
            self._respond(400,{'ok':False,'error':'invalid_request'})
        except Exception:
            self._respond(500,{'ok':False,'error':'internal_error'})
        finally:
            self.server.workslots.release()


def token_from_file(root):
    path=Path(root)/'sidecar_token_v4'
    if path.exists():
        if path.is_symlink(): raise RuntimeError('refuse_symlink_token')
        data=path.read_text('ascii').strip()
        if not re.fullmatch(r'[a-f0-9]{64}',data):raise RuntimeError('invalid_existing_token')
        return data
    token=secrets.token_hex(32)
    fd=os.open(str(path),os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'w',encoding='ascii') as f: f.write(token+'\n')
    return token


def main(argv=None):
    parser=argparse.ArgumentParser(description='Burp AI passive local research service')
    parser.add_argument('--data-dir',default=str(Path.home()/'.burpai_context_v2'))
    parser.add_argument('--port',type=int,default=18743)
    parser.add_argument('--serve',action='store_true')
    parser.add_argument('--import-v3',action='store_true')
    parser.add_argument('--check',action='store_true')
    parser.add_argument('--attest-finding',default=None)
    parser.add_argument('--mission',default=None)
    parser.add_argument('--reviewer',default=None)
    parser.add_argument('--review-procedure',default=None)
    parser.add_argument('--review-reference',default=None)
    parser.add_argument('--review-outcome',choices=['confirmed','refuted','inconclusive'],default=None)
    args=parser.parse_args(argv)
    root=secure_dir(args.data_dir)
    db=ResearchDB(root)
    try:
        if args.import_v3: print(to_json(db.import_v3()))
        if args.attest_finding:
            if not args.mission or not args.reviewer or not args.review_procedure or not args.review_reference or not args.review_outcome:
                parser.error('attestation requires --mission, --reviewer, --review-procedure, --review-reference and --review-outcome')
            print(to_json(db.attest_finding(args.mission,args.attest_finding,
                 args.reviewer,args.review_procedure,args.review_reference,args.review_outcome)))
        if args.check:
            print(to_json({'database':str(db.dbfile),'db_version':DB_VERSION,
                           'integrity':db.conn.execute('PRAGMA integrity_check').fetchone()[0]}))
        if args.serve:
            if not 1024<=args.port<=65535: raise SystemExit('port must be 1024..65535')
            token=token_from_file(root)
            server=ResearchServer(('127.0.0.1',args.port),db,token)
            print('BurpAI passive research service on 127.0.0.1:%d'%(args.port),flush=True)
            print('Live network requests are disabled in this service.',flush=True)
            try:server.serve_forever(poll_interval=0.3)
            except KeyboardInterrupt:pass
            finally:server.server_close()
    finally: db.close()


if __name__=='__main__': main()

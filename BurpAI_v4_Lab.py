# -*- coding: utf-8 -*-
"""Traffic-derived hypotheses and bounded, reproducible HTTP experiments.

Python 2.7/3; all transport is injected by the Burp adapter. Credentials and
request templates are memory-only. Public state omits scalar query/body/header
values; route names and structured field names remain visible.
"""
from __future__ import unicode_literals
import copy
import hashlib
import json
import re
import threading
import time
import sys
if sys.version_info[0]>=3:
    from urllib.parse import urlsplit, urlunsplit
else:
    from urlparse import urlsplit, urlunsplit
from BurpAI_v4_Investigation import compare_http, text

AUTH_HEADERS = frozenset(('authorization','cookie','x-api-key','x-auth-token',
                         'x-csrf-token','x-xsrf-token'))
HOP_HEADERS = frozenset(('host','content-length','transfer-encoding','connection',
                        'proxy-connection','proxy-authorization','keep-alive','te','trailer','upgrade'))
CONTROL_HEADERS = frozenset(('if-none-match','if-modified-since','range','if-range','accept-encoding'))
SECRET_NAME = re.compile(r'pass|token|secret|session|auth|api.?key|cookie', re.I)
ACTION_PATH = re.compile(r'/(?:logout|signout|delete|remove|reset|unsubscribe|checkout|transfer|activate)(?:/|$)', re.I)


def unquote_plus(value):
    # Jython's urllib imports socket/Netty even for this pure decoding helper.
    raw=bytearray(text(value).replace('+',' ').encode('utf-8')); decoded=bytearray(); i=0
    while i<len(raw):
        if raw[i]==37 and i+2<len(raw):
            try:
                decoded.append(int(chr(raw[i+1])+chr(raw[i+2]),16)); i+=3; continue
            except ValueError: pass
        decoded.append(raw[i]); i+=1
    return decoded.decode('utf-8','replace')


def digest(value):
    return hashlib.sha256(text(value).encode('utf-8')).hexdigest()


def origin(url):
    parts = urlsplit(text(url))
    if parts.scheme.lower() not in ('http','https') or not parts.hostname or parts.username or parts.password:
        raise ValueError('invalid_http_origin')
    port = parts.port or (443 if parts.scheme.lower() == 'https' else 80)
    host = parts.hostname.lower()
    if ':' in host: host = '[' + host + ']'
    return '{}://{}:{}'.format(parts.scheme.lower(),host,port)


def route_path(url):
    path = urlsplit(text(url)).path or '/'
    pieces = []
    for part in path.split('/'):
        if re.match(r'^\d+$',part): part = '{number}'
        elif re.match(r'^[a-fA-F0-9-]{16,}$',part): part = '{identifier}'
        elif '@' in part or '%40' in part.lower() or len(part) > 64: part = '{value}'
        pieces.append(part)
    return '/'.join(pieces)[:400]


def query_names(url):
    query = urlsplit(text(url)).query
    if len(query) > 8192: raise ValueError('query_too_large_for_lab')
    names = [text(unquote_plus(part.split('=',1)[0])) for part in query.split('&') if part]
    if len(names) > 80: raise ValueError('too_many_query_parameters')
    return names


def shape(body):
    """Return bounded JSON structure/type information, with no scalar values."""
    if len(text(body)) > 128*1024: return []
    try: value = json.loads(body)
    except (ValueError, TypeError): return []
    paths = set()
    def walk(obj, path, depth):
        if depth > 4 or len(paths) >= 80: return
        if isinstance(obj, dict):
            paths.add(path + ':object')
            for key in sorted(obj)[:40]:
                safe_key = key if re.match(r'^[A-Za-z_][A-Za-z0-9_-]{0,63}$',text(key)) else '{key}'
                walk(obj[key],path + '/' + safe_key,depth+1)
        elif isinstance(obj, list):
            paths.add(path + ':array')
            for child in obj[:3]: walk(child,path + '/[]',depth+1)
        else:
            kind = ('null' if obj is None else 'boolean' if isinstance(obj,bool) else
                    'number' if isinstance(obj,(int,float)) else 'string')
            paths.add(path + ':' + kind)
    walk(value,'$',0)
    return sorted(paths)[:80]


def observe(request, response, selection):
    """Reduce one captured exchange to value-free, source-linked features."""
    names = query_names(request['url'])
    headers = dict((text(k).lower(),text(v)) for k,v in request.get('headers',{}).items())
    return {'origin':origin(request['url']), 'route':route_path(request['url']),
        'method':text(request.get('method','GET')).upper(), 'query_names':sorted(set(names)),
        'duplicate_query_names':sorted(n for n in set(names) if names.count(n)>1),
        'request_shape':shape(request.get('body','')), 'response_shape':shape(response.get('body','')),
        'status':int(response.get('status',0)), 'auth_present':bool(set(headers) & AUTH_HEADERS),
        'body_complete':bool(response.get('body_complete')),
        'response_digest':digest(response.get('body','')) if response.get('body_complete') else '',
        'selection':dict(selection)}


def discover(observations, target_origin):
    groups = {}
    for item in observations:
        if item['origin'] != target_origin: continue
        key = item['method'] + ' ' + item['route']
        group = groups.setdefault(key, {'route_key':key,'route':item['route'],'method':item['method'],
            'observations':[], 'query_names':set(),'statuses':set(),'response_shapes':set()})
        group['observations'].append(item)
        group['query_names'].update(item['query_names']); group['statuses'].add(item['status'])
        if 200 <= item['status'] < 300 and item['body_complete'] and item['response_shape']:
            group['response_shapes'].add(tuple(item['response_shape']))
    routes, leads = [], []
    for key in sorted(groups):
        group = groups[key]; obs = group['observations']
        sample = next((o for o in reversed(obs) if 200<=o['status']<300),obs[-1])
        route = {'route_key':key,'method':group['method'],'route':group['route'],
            'count':len(obs),'query_names':sorted(group['query_names']), 'statuses':sorted(group['statuses']),
            'response_shape_variants':len(group['response_shapes']),
            'auth_states':sorted(set(o['auth_present'] for o in obs)),
            'samples':[copy.deepcopy(o) for o in obs[-12:]]}
        routes.append(route)
        def lead(kind, title, why, falsifier, parameter='', priority=3):
            leads.append({'id':'L'+digest(target_origin+'|'+key+'|'+kind+'|'+parameter)[:14],
                'kind':kind,'title':title,'why':why,'falsifier':falsifier,'priority':priority,
                'origin':target_origin,'route_key':key,'parameter':parameter,
                'selection':dict(sample['selection']),'state':'unverified','evidence_ids':[],
                'next_step':'Inspect captured controls and run a bounded comparison if useful.'})
        if any(status>=500 for status in group['statuses']):
            lead('server_error','Explain server failures on '+key,
                'Captured responses include a server error. Inspect the request conditions that distinguish it.',
                'A transient outage or documented rejection explains the failure; stable controls do not reproduce it.',priority=1)
        if len(group['response_shapes']) > 1:
            lead('contract_drift','Check response-contract drift on '+key,
                'Successful captured responses have different JSON structures.',
                'Optional fields, pagination, endpoint IDs or version negotiation explain the different structures.',priority=2)
        if ('{number}' in group['route'] or '{identifier}' in group['route'] or
                any(re.search(r'(^|_)(id|owner|user|account|tenant|org)(_|$)',n,re.I) for n in group['query_names'])):
            lead('object_boundary','Compare object visibility on '+key,
                'An observed route or parameter selects an object. Compare the same request using user-selected sessions.',
                'The object is intentionally public/shared, or the alternate session is correctly denied.',priority=2)
        public = [o for o in obs if not o['auth_present'] and 200<=o['status']<300 and o['response_digest']]
        private = [o for o in obs if o['auth_present'] and 200<=o['status']<300 and o['response_digest']]
        if set(o['response_digest'] for o in public) & set(o['response_digest'] for o in private):
            lead('anonymous_equivalence','Review anonymous/authenticated equivalence on '+key,
                'Captured responses with and without recognized auth headers share a complete body digest.',
                'The response is public, a generic login page, or authentication uses an unrecognized mechanism.',priority=2)
        if group['method'] in ('GET','HEAD'):
            for parameter in sorted(group['query_names'])[:6]:
                if SECRET_NAME.search(parameter): continue
                lead('parameter_contract','Test '+parameter+' on '+key,
                    'This parameter is present in captured traffic. Omission, an empty value and duplication can reveal inconsistent handling.',
                    'The server consistently validates the parameter or the observed behavior matches its intended contract.',parameter)
    leads.sort(key=lambda item:(item['priority'],item['id']))
    return {'origin':target_origin,'routes':routes,'leads':leads[:60], 'observations':sum(r['count'] for r in routes),
            'note':'Traffic-derived hypotheses, not confirmed bugs. Captured traffic is a partial view of the application.'}


def parameter_variant(url, parameter, mutation):
    parts = urlsplit(text(url)); tokens = parts.query.split('&')
    if parameter not in query_names(url): raise ValueError('parameter_not_in_captured_request')
    if SECRET_NAME.search(parameter): raise ValueError('use_session_matrix_for_authentication_changes')
    matched = lambda token: text(unquote_plus(token.split('=',1)[0])) == parameter
    if mutation == 'omit': tokens = [t for t in tokens if not matched(t)]
    elif mutation == 'empty': tokens = [t.split('=',1)[0]+'=' if matched(t) else t for t in tokens]
    elif mutation == 'duplicate':
        first = next(t for t in tokens if matched(t)); tokens.append(first)
    else: raise ValueError('unknown_parameter_mutation')
    return urlunsplit((parts.scheme,parts.netloc,parts.path,'&'.join(tokens),''))


class LabEngine(object):
    def __init__(self, ledger):
        self.ledger = ledger
        self.lock = threading.RLock()
        self.mission = None
        self.templates = {}
        self.profiles = {}
        self.profile_revision = 0
        self.running = set()
        with self.lock, self.ledger.lock:
            self._state()
            for exp in self._state()['experiments']:
                if exp['state'] == 'running':
                    exp.update(state='interrupted',assessment='interrupted_review_existing_evidence')
            self.ledger._persist()

    def _state(self):
        mission = self.ledger.data['mission_id']
        if self.mission != mission:
            self.mission = mission; self.templates = {}; self.profiles = {}; self.running = set()
            self.profile_revision += 1
        return self.ledger.data.setdefault('lab',{'maps':{},'leads':[],'experiments':[]})

    def ingest(self, result, evidence_id):
        with self.lock, self.ledger.lock:
            state = self._state()
            if result['origin'] not in state['maps'] and len(state['maps']) >= 8:
                raise ValueError('application_map_limit_reached')
            result = copy.deepcopy(result)
            previous = dict((l['id'],l) for l in state['leads'])
            new = []
            for lead in result['leads']:
                lead['evidence_ids'] = [evidence_id]
                old = previous.get(lead['id'])
                if old:
                    for key in ('state','assessment','counterevidence_ids'): 
                        if key in old: lead[key] = old[key]
                    if old.get('assessment'):
                        lead['evidence_ids']=list(dict.fromkeys(old.get('evidence_ids',[])+[evidence_id]))[-16:]
                else: new.append(lead)
            fresh = set(l['id'] for l in result['leads'])
            keep = [l for l in state['leads'] if l['id'] not in fresh]
            for lead in keep:
                if lead['origin']==result['origin']: lead['stale']=True
            state['leads'] = (result['leads'] + keep)[:120]
            result['evidence_id'] = evidence_id
            state['maps'][result['origin']] = result
            self.ledger._persist()
            return copy.deepcopy(new)

    def get_lead(self, lead_id):
        with self.lock, self.ledger.lock:
            lead = next((l for l in self._state()['leads'] if l['id']==lead_id),None)
            if not lead: raise ValueError('unknown_lead_id')
            return copy.deepcopy(lead)

    def create_hypothesis(self, target_origin, route_key, title, hypothesis, falsifier, evidence_ids, parameter=''):
        if not all(text(v).strip() for v in (title,hypothesis,falsifier)):
            raise ValueError('title_hypothesis_and_falsifier_required')
        with self.lock,self.ledger.lock:
            state=self._state(); mapped=state['maps'].get(target_origin,{})
            route=next((r for r in mapped.get('routes',[]) if r['route_key']==route_key),None)
            if not route: raise ValueError('route_not_in_application_map')
            samples=[s for s in route['samples'] if not parameter or parameter in s['query_names']]
            if not samples: raise ValueError('parameter_not_observed_on_route')
            sample=next((s for s in samples if 200<=s['status']<300),samples[0])
            identifier='L'+digest(target_origin+'|'+route_key+'|'+text(title))[:14]
            old=next((l for l in state['leads'] if l['id']==identifier),None)
            if old: return copy.deepcopy(old)
            if len(state['leads'])>=120: raise ValueError('discovery_limit_reached')
            lead={'id':identifier,'kind':'custom_hypothesis','title':text(title)[:200],
                'why':text(hypothesis)[:1200],'falsifier':text(falsifier)[:800],'priority':2,
                'origin':target_origin,'route_key':route_key,'parameter':text(parameter),
                'selection':copy.deepcopy(sample['selection']),'state':'unverified',
                'evidence_ids':list(evidence_ids),'next_step':'Challenge this interpretation against original evidence and a controlled comparison.'}
            state['leads'].insert(0,lead); self.ledger._persist(); return copy.deepcopy(lead)

    def challenge(self, lead_id):
        with self.lock, self.ledger.lock:
            lead = self.get_lead(lead_id)
            mapped = self._state()['maps'].get(lead['origin'],{})
            route = next((r for r in mapped.get('routes',[]) if r['route_key']==lead['route_key']),{})
            controls = route.get('samples',[])
            negatives = [s for s in controls if (s['status'] in (401,403) and not s['auth_present'])]
            successes = [s for s in controls if 200<=s['status']<300]
            return {'ok':True,'lead_id':lead_id,'assessment':'challenge_not_verdict',
                'alternative_explanation':lead['falsifier'],
                'counter_observations':copy.deepcopy(negatives[:4]),
                'successful_controls':copy.deepcopy(successes[:4]),
                'missing':['Expected application permission/behavior','A stable repeated baseline',
                           'A single controlled change isolating the suspected cause'],
                'evidence_ids':lead['evidence_ids'],
                'note':'A denied anonymous sample weakens a blanket missing-authentication claim; it does not settle access for every object or role.'}

    def add_profile(self, name, request):
        name = text(name).strip()
        if not name or len(name)>60: raise ValueError('profile_name_required_max_60_chars')
        headers = dict((text(k),text(v)) for k,v in request.get('headers',{}).items() if text(k).lower() in AUTH_HEADERS)
        if not headers: raise ValueError('no_recognized_session_headers_in_selected_request')
        with self.lock, self.ledger.lock:
            self._state()
            if len(self.profiles)>=8: raise ValueError('session_profile_limit_reached')
            profile_id = 'P'+digest(name+'|'+origin(request['url']))[:12]
            self.profile_revision += 1
            self.templates = dict((k,v) for k,v in self.templates.items() if v['mode']!='session_matrix')
            self.profiles[profile_id] = {'id':profile_id,'name':name,'origin':origin(request['url']),'headers':headers}
            return {'id':profile_id,'name':name,'origin':origin(request['url']),
                    'header_names':sorted(headers),'note':'Memory only; role label is supplied by the user, not inferred.'}

    def forget_profiles(self):
        with self.lock:
            self.profiles = {}
            self.profile_revision += 1
            # Session experiments must be rebuilt explicitly after session changes.
            self.templates = dict((k,v) for k,v in self.templates.items() if v['mode']!='session_matrix')

    def prepare(self, request, selection, mode, parameter='', profile_ids=None, lead_id=''):
        method = text(request.get('method','GET')).upper()
        if method not in ('GET','HEAD') or request.get('body'):
            raise ValueError('lab_replay_requires_bodyless_get_or_head')
        if ACTION_PATH.search(urlsplit(request['url']).path): raise ValueError('action_endpoint_requires_manual_repeater_review')
        source_origin = origin(request['url'])
        headers = dict((text(k),text(v)) for k,v in request.get('headers',{}).items()
                       if text(k).lower() not in HOP_HEADERS|CONTROL_HEADERS)
        headers['Accept-Encoding']='identity'
        if any('\r' in k+v or '\n' in k+v for k,v in headers.items()): raise ValueError('invalid_header')
        profiles = list(profile_ids or [])
        if len(profiles)>3 or len(set(profiles))!=len(profiles): raise ValueError('choose_at_most_three_distinct_session_profiles')
        with self.lock, self.ledger.lock:
            state = self._state()
            if lead_id: self.get_lead(lead_id)
            baseline = {'method':method,'url':request['url'],'headers':headers,'body':''}
            cases = [('baseline',copy.deepcopy(baseline))]
            if mode == 'parameter_boundaries':
                if profiles: raise ValueError('profile_ids_only_apply_to_session_matrix')
                for mutation in ('omit','empty','duplicate'):
                    changed = copy.deepcopy(baseline)
                    changed['url'] = parameter_variant(baseline['url'],parameter,mutation)
                    if changed['url'] != baseline['url']: cases.append((mutation+' '+parameter,changed))
            elif mode == 'session_matrix':
                parameter=''
                if any(SECRET_NAME.search(n) for n in query_names(request['url'])):
                    raise ValueError('session_matrix_query_authentication_not_supported')
                if not profiles: profiles = ['anonymous']
                for profile_id in profiles:
                    changed = copy.deepcopy(baseline)
                    changed['headers'] = dict((k,v) for k,v in headers.items() if k.lower() not in AUTH_HEADERS)
                    name = 'Anonymous (recognized auth headers removed)'
                    if profile_id != 'anonymous':
                        profile = self.profiles.get(profile_id)
                        if not profile: raise ValueError('session_profile_missing_reselect_after_reload')
                        if profile['origin'] != source_origin: raise ValueError('session_profile_origin_mismatch')
                        changed['headers'].update(profile['headers']); name=profile['name']
                    if changed['headers'] == baseline['headers']: raise ValueError('session_profile_does_not_change_request')
                    cases.append((name,changed))
            else: raise ValueError('unknown_experiment_mode')
            cases.append(('repeat baseline',copy.deepcopy(baseline)))
            profile_fingerprints=[(pid,digest(json.dumps(self.profiles[pid]['headers'],sort_keys=True)))
                                  for pid in profiles if pid!='anonymous']
            identity={'request_sha256':selection['request_sha256'],'url_sha256':selection['url_sha256']}
            fingerprint = json.dumps([self.mission,identity,mode,parameter,sorted(profiles),sorted(profile_fingerprints)],sort_keys=True)
            exp_id = 'X'+digest(fingerprint)[:14]
            old = next((e for e in state['experiments'] if e['id']==exp_id),None)
            if old and old['state']!='draft': return copy.deepcopy(old)
            if not old and len(state['experiments'])>=40: raise ValueError('experiment_limit_reached')
            public = {'id':exp_id,'origin':source_origin,'route':route_path(request['url']),
                'method':method,'mode':mode,'parameter':parameter,'profile_ids':profiles,
                'lead_id':lead_id,'selection':dict(selection),'state':'draft','request_count':len(cases),
                'cases':[{'label':label,'state':'planned'} for label,req in cases],
                'comparisons':[], 'assessment':'not_run',
                'normalizations':'All cases remove hop-by-hop, conditional-cache and range headers; request identity encoding.',
                'note':'Baseline, controlled variants and repeat baseline. A difference is a lead, not vulnerability proof.'}
            self.templates[exp_id] = {'mode':mode,'cases':cases,'profile_revision':self.profile_revision}
            if old: state['experiments'][state['experiments'].index(old)] = public
            else: state['experiments'].append(public)
            self.ledger._persist()
            return copy.deepcopy(public)

    def get_experiment(self, exp_id):
        with self.lock, self.ledger.lock:
            exp = next((e for e in self._state()['experiments'] if e['id']==exp_id),None)
            if not exp: raise ValueError('unknown_experiment_id')
            return copy.deepcopy(exp)

    def run(self, exp_id, send, capture, boundary, approved=False, available_requests=None, on_update=None):
        with self.lock, self.ledger.lock:
            state = self._state()
            exp = next((e for e in state['experiments'] if e['id']==exp_id),None)
            if not exp: raise ValueError('unknown_experiment_id')
            if not approved: return {'ok':False,'error':'experiment_approval_required','experiment':copy.deepcopy(exp)}
            if exp['state']!='draft' or exp_id in self.running:
                return {'ok':False,'error':'experiment_already_attempted_no_automatic_replay','experiment':copy.deepcopy(exp)}
            template = self.templates.get(exp_id)
            if not template: return {'ok':False,'error':'request_template_missing_prepare_again'}
            if available_requests is not None and available_requests < len(template['cases']):
                return {'ok':False,'error':'insufficient_run_request_budget','required':len(template['cases'])}
            cases = copy.deepcopy(template['cases'])
            profile_revision = self.profile_revision
            exp['state']='running'; self.running.add(exp_id); self.ledger._persist()
        responses = []
        try:
            if on_update: on_update()
            for i,(label,request) in enumerate(cases):
                if not boundary() or (template['mode']=='session_matrix' and profile_revision!=self.profile_revision):
                    with self.ledger.lock:
                        exp['state']='interrupted'; exp['assessment']='incomplete'; self.ledger._persist()
                    break
                with self.ledger.lock:
                    exp['cases'][i]['state']='attempting'; self.ledger._persist()
                if on_update: on_update()
                result = send(request)
                ref = capture(exp_id,label,result)
                complete = bool(result.get('ok') and result.get('body_complete'))
                with self.ledger.lock:
                    exp['cases'][i].update(state='observed' if complete else 'failed', evidence_id=ref,
                        status=result.get('status'), error=result.get('error',''))
                    self.ledger._persist()
                if on_update: on_update()
                if not complete:
                    with self.ledger.lock:
                        exp['state']='incomplete'; exp['assessment']='incomplete_response_or_transport_failure'; self.ledger._persist()
                    break
                responses.append(result)
                if i==0 and template['mode']=='session_matrix' and not 200<=result.get('status',0)<300:
                    with self.ledger.lock:
                        exp.update(state='incomplete',assessment='baseline_not_successful'); self.ledger._persist()
                    break
            if len(responses)==len(cases):
                comparisons = []
                for i,result in enumerate(responses[1:-1],1):
                    comparison = compare_http(responses[0],result,responses[-1])
                    comparison.update(label=cases[i][0],baseline_id=exp['cases'][0]['evidence_id'],
                        candidate_id=exp['cases'][i]['evidence_id'],repeat_baseline_id=exp['cases'][-1]['evidence_id'])
                    comparisons.append(comparison)
                unstable = any(c['baseline_stability']!='stable_observed' for c in comparisons)
                differences = any(c['status_changed'] or not c['body_equal'] or c['changed_headers'] for c in comparisons)
                with self.ledger.lock:
                    exp.update(state='completed',comparisons=comparisons,
                        assessment='unstable_baseline' if unstable else 'baseline_not_successful' if not 200<=responses[0].get('status',0)<300
                        else 'differences_observed' if differences else 'no_difference_observed')
                    self.ledger._persist()
            return {'ok':True,'experiment':copy.deepcopy(exp)}
        except Exception:
            with self.ledger.lock:
                exp.update(state='interrupted',assessment='unexpected_failure_do_not_replay'); self.ledger._persist()
            raise
        finally:
            with self.lock:
                self.running.discard(exp_id); self.templates.pop(exp_id,None)
            if on_update: on_update()

    def snapshot(self, include_routes=False):
        with self.lock, self.ledger.lock:
            state = self._state()
            result = {'ok':True,'maps':[{'origin':key,'routes':len(value['routes']),
                     'observations':value['observations'],'evidence_id':value['evidence_id']} for key,value in sorted(state['maps'].items())],
                'leads':copy.deepcopy(state['leads']), 'experiments':copy.deepcopy(state['experiments']),
                'session_profiles':[{'id':p['id'],'name':p['name'],'origin':p['origin']} for p in self.profiles.values()]}
            if include_routes:
                result['routes']=[{'origin':key,'route_key':r['route_key'],'count':r['count'],
                    'statuses':list(r['statuses']),'query_names':list(r['query_names'])}
                    for key,value in sorted(state['maps'].items()) for r in value['routes']]
            return result

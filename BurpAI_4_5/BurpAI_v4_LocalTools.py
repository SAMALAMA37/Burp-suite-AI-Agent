# -*- coding: utf-8 -*-
"""Read-only WSL inventory and bounded checks on user-selected JSON data."""
from __future__ import unicode_literals

import hashlib
import os
import json
import math
import re
import threading

try:
    text_type = unicode
    integer_types = (int, long)
except NameError:
    text_type = str
    integer_types = (int,)

MAX_FIXTURE_BYTES = 512 * 1024
MAX_PLAN_BYTES = 32 * 1024
MAX_INVENTORY_BYTES = 512 * 1024
MAX_CHECKS = 32
OPERATORS = ('exists', 'missing', 'equals', 'type_is', 'contains')
JSON_TYPES = ('null', 'boolean', 'number', 'string', 'array', 'object')
TOOL_NAME = re.compile(r'^[A-Za-z0-9_.+@-]{1,128}\Z')
DISTRO_NAME = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_. +()-]{0,79}\Z')
_MISSING = object()


def parse_json(raw, maximum):
    if len(raw) > maximum:
        raise ValueError('JSON exceeds the {} KiB limit.'.format(maximum // 1024))

    depth = 0
    quoted = False
    escaped = False
    for char in bytearray(raw):
        if quoted:
            if escaped:
                escaped = False
            elif char == 92:
                escaped = True
            elif char == 34:
                quoted = False
        elif char == 34:
            quoted = True
        elif char in (91, 123):
            depth += 1
            if depth > 40:
                raise ValueError('JSON is nested more than 40 levels.')
        elif char in (93, 125):
            depth -= 1
            if depth < 0:
                raise ValueError('JSON contains an unmatched closing bracket.')

    def reject_constant(value):
        raise ValueError('JSON numbers must be finite.')

    def read_number(value, converter):
        if len(value) > 128:
            raise ValueError('JSON numbers are limited to 128 characters.')
        number = converter(value)
        if isinstance(number, float) and (math.isnan(number) or math.isinf(number)):
            raise ValueError('JSON numbers must be finite.')
        return number

    def unique_keys(pairs):
        obj = {}
        for key, value in pairs:
            if key in obj:
                raise ValueError('JSON contains a duplicate key.')
            obj[key] = value
        return obj

    try:
        return json.loads(raw.decode('utf-8-sig'), parse_constant=reject_constant,
                          parse_int=lambda value: read_number(value, int),
                          parse_float=lambda value: read_number(value, float), object_pairs_hook=unique_keys)
    except (ValueError, RuntimeError, OverflowError):
        raise ValueError('Use valid UTF-8 JSON with unique keys and finite numbers up to 128 characters.')


def _json_type(value):
    if value is None:
        return 'null'
    if isinstance(value, bool):
        return 'boolean'
    if isinstance(value, integer_types + (float,)):
        return 'number'
    if isinstance(value, text_type):
        return 'string'
    if isinstance(value, list):
        return 'array'
    return 'object'


def _pointer(value):
    if not isinstance(value, text_type) or len(value) > 384:
        raise ValueError('Each path must be a JSON pointer of at most 384 characters.')
    if value == '':
        return []
    if not value.startswith('/') or re.search(r'~(?![01])', value):
        raise ValueError('Use a JSON pointer such as /status or /items/0/name.')
    parts = value[1:].split('/')
    if len(parts) > 32:
        raise ValueError('A JSON pointer may have at most 32 segments.')
    return [part.replace('~1', '/').replace('~0', '~') for part in parts]


def _resolve(document, parts):
    value = document
    for part in parts:
        if isinstance(value, dict):
            value = value.get(part, _MISSING)
        elif isinstance(value, list) and re.match(r'^(0|[1-9][0-9]{0,5})\Z', part):
            index = int(part)
            value = value[index] if index < len(value) else _MISSING
        else:
            return _MISSING
    return value


def _normalize_checks(checks):
    if not isinstance(checks, list) or not 1 <= len(checks) <= MAX_CHECKS:
        raise ValueError('Provide between 1 and {} checks.'.format(MAX_CHECKS))
    result = []
    for index, check in enumerate(checks, 1):
        if not isinstance(check, dict) or set(check) - {'label', 'path', 'op', 'expected'}:
            raise ValueError('Each check accepts only label, path, op and expected.')
        path = check.get('path')
        parts = _pointer(path)
        op = check.get('op')
        if op not in OPERATORS:
            raise ValueError('Unknown check operation.')
        label = check.get('label', 'Check {}'.format(index))
        if not isinstance(label, text_type) or not 1 <= len(label.strip()) <= 120:
            raise ValueError('Check labels must have 1 to 120 characters.')
        normalized = {'label': label.strip(), 'path': path, 'op': op}
        needs_expected = op in ('equals', 'type_is', 'contains')
        if needs_expected != ('expected' in check):
            raise ValueError('Provide expected only for equals, type_is and contains.')
        if needs_expected:
            expected = check['expected']
            kind = _json_type(expected)
            if op == 'type_is' and expected not in JSON_TYPES:
                raise ValueError('type_is expects a JSON type name.')
            if op == 'contains' and (kind != 'string' or not expected):
                raise ValueError('contains expects a nonempty string.')
            if op == 'equals' and kind in ('array', 'object'):
                raise ValueError('equals expects a scalar JSON value.')
            if kind == 'string' and len(expected) > 1024:
                raise ValueError('Expected strings are limited to 1,024 characters.')
            if isinstance(expected, float) and (math.isnan(expected) or math.isinf(expected)):
                raise ValueError('Expected numbers must be finite.')
            normalized['expected'] = expected
        result.append((normalized, parts))
    return result


def evaluate_checks(document, checks):
    normalized = _normalize_checks(checks)
    outcomes = []
    for check, parts in normalized:
        value = _resolve(document, parts)
        op = check['op']
        expected = check.get('expected')
        if op == 'exists':
            passed = value is not _MISSING
        elif op == 'missing':
            passed = value is _MISSING
        elif value is _MISSING:
            passed = False
        elif op == 'type_is':
            passed = _json_type(value) == expected
        elif op == 'contains':
            passed = isinstance(value, text_type) and expected in value
        else:
            passed = _json_type(value) == _json_type(expected) and value == expected
        outcomes.append({'passed': passed, 'reason': 'matched' if passed else
                         ('path_missing' if value is _MISSING else 'assertion_failed')})
    return {'checks': [check for check, _ in normalized], 'outcomes': outcomes,
            'passed': sum(outcome['passed'] for outcome in outcomes), 'total': len(outcomes)}


def normalize_checks(checks):
    normalized = [check for check, _ in _normalize_checks(checks)]
    if len(json.dumps(normalized, ensure_ascii=True)) > MAX_PLAN_BYTES:
        raise ValueError('The check plan exceeds 32 KiB.')
    return normalized


def read_fixture(path):
    if not os.path.isfile(path):
        raise ValueError('Select a regular JSON file.')
    with open(path, 'rb') as handle:
        return handle.read(MAX_FIXTURE_BYTES + 1)


def save_report(path, report):
    content = (json.dumps(report, ensure_ascii=True, sort_keys=True, indent=2) + '\n').encode('utf-8')
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'wb') as handle:
        handle.write(content)


class FixtureWorkspace(object):
    def __init__(self):
        self._lock = threading.RLock()
        self._fixture = None

    def load(self, raw):
        document = parse_json(raw, MAX_FIXTURE_BYTES)
        metadata = {'fixture_id': hashlib.sha256(raw).hexdigest(), 'root_type': _json_type(document),
                    'size_bytes': len(raw)}
        with self._lock:
            self._fixture = (metadata, document)
        return dict(metadata)

    def clear(self):
        with self._lock:
            self._fixture = None

    def info(self):
        with self._lock:
            return dict(self._fixture[0]) if self._fixture else None

    def run(self, fixture_id, checks):
        with self._lock:
            if not self._fixture or fixture_id != self._fixture[0]['fixture_id']:
                raise ValueError('Select a fixture and use its current fixture ID.')
            metadata, document = self._fixture
            report = evaluate_checks(document, checks)
            report.update(metadata)
            return report


def decode_wsl_output(raw):
    if raw.startswith(b'\xff\xfe'):
        return raw.decode('utf-16')
    if b'\x00' in raw:
        return raw.decode('utf-16-le', 'replace')
    return raw.decode('utf-8-sig', 'replace')


def distro_names(raw):
    return sorted(set(line.strip() for line in decode_wsl_output(raw).splitlines()
                      if DISTRO_NAME.match(line.strip())), key=lambda name: (name.lower(), name))


def inventory_names(raw):
    return sorted(set(line for line in decode_wsl_output(raw).splitlines() if TOOL_NAME.match(line)),
                  key=lambda name: (name.lower(), name))


def inventory_arguments(distro):
    if not DISTRO_NAME.match(distro):
        raise ValueError('Choose a listed WSL distribution.')
    return ['--distribution', distro, '--exec', '/usr/bin/find', '/usr/bin', '/usr/local/bin',
            '-maxdepth', '1', '(', '-type', 'f', '-o', '-xtype', 'f', ')', '-executable',
            '-printf', r'%f\n']


def list_distributions():
    return distro_names(_read_wsl(['--list', '--quiet']))


def list_tools(distro):
    return inventory_names(_read_wsl(inventory_arguments(distro)))


def _read_wsl(arguments):
    """Run the fixed inventory queries through Java, outside the Swing event thread."""
    import os
    from java.io import BufferedInputStream, ByteArrayOutputStream
    from java.lang import ProcessBuilder, System
    from java.util.concurrent import TimeUnit
    from jarray import zeros

    if not System.getProperty('os.name', '').lower().startswith('windows'):
        raise ValueError('WSL inventory is available on Windows.')
    system_root = System.getenv('SystemRoot')
    if not system_root:
        raise ValueError('Could not locate the Windows WSL executable.')
    executable = os.path.join(system_root, 'System32', 'wsl.exe')
    process = ProcessBuilder([executable] + arguments).redirectErrorStream(True).start()
    stream = BufferedInputStream(process.getInputStream())
    output = ByteArrayOutputStream()
    errors = []

    def drain():
        try:
            chunk = zeros(8192, 'b')
            while True:
                count = stream.read(chunk)
                if count < 0:
                    return
                if output.size() + count > MAX_INVENTORY_BYTES:
                    errors.append('WSL inventory exceeded the output limit.')
                    process.destroyForcibly()
                    return
                output.write(chunk, 0, count)
        except Exception:
            errors.append('Could not read the WSL inventory output.')

    reader = threading.Thread(target=drain, name='BurpAI WSL inventory')
    reader.daemon = True
    try:
        process.getOutputStream().close()
        reader.start()
        if not process.waitFor(15, TimeUnit.SECONDS):
            raise ValueError('WSL inventory timed out. Check that the distribution starts normally.')
        reader.join(1)
        if reader.is_alive() or errors:
            raise ValueError(errors[0] if errors else 'WSL inventory output did not close.')
        raw = output.toByteArray().tostring()
        if process.exitValue() != 0:
            if 'E_ACCESSDENIED' in decode_wsl_output(raw):
                raise ValueError('WSL access was denied by Windows.')
            raise ValueError('WSL inventory failed (exit {}). Check the distribution and /usr/bin/find.'.format(process.exitValue()))
        return raw
    finally:
        if process.isAlive():
            process.destroyForcibly()
        try:
            stream.close()
        except Exception:
            pass

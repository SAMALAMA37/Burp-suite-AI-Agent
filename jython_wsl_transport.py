# -*- coding: utf-8 -*-
"""Exercise real JVM process pipes with a harmless local Python fixture, not WSL."""
from __future__ import unicode_literals
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from BurpAI_v4_WSL import _exchange, launch_arguments
if not sys.platform.startswith('java') or len(sys.argv) != 2:
    raise SystemExit('Run on Jython and pass the absolute path of a local Python 3 executable.')
python = sys.argv[1]
def exchange(program, payload=b'', cancelled=lambda:False):
    return _exchange([python,'-I','-u','-c',program], payload, {'timeout':2}, cancelled)

payload = json.dumps({'text':'Unicode: \u03bb\u00f3\u017a; $(); quotes " \' \\ '*10000},ensure_ascii=True).encode('ascii') + b'\n'
program = "import json,sys; a=json.loads(sys.stdin.buffer.readline()); print(json.dumps(dict(protocol=1,ok=True,chars=len(a['text']))))"
result = exchange(program,payload)
assert result['ok'] and result['chars'] == len(json.loads(payload)['text']), result
program = "import json,sys; sys.stderr.write('fixture warning\\n'); print(json.dumps(dict(protocol=1,ok=True)))"
result = exchange(program)
assert result['ok'] and result['stderr'] == 'fixture warning', result
program = "import json,sys; print(json.dumps(dict(protocol=1,ok=True))); sys.stderr.write('fixture crash\\n'); sys.exit(7)"
result = exchange(program)
assert not result['ok'] and result['bridge_exit_code'] == 7 and 'fixture crash' in result['stderr'], result
program = "import json,sys; a=json.loads(sys.stdin.buffer.readline()); print(json.dumps(dict(protocol=1,ok=True,chars=len(a['text']))))"
helper = (program + '\n').encode('utf-8')
bootstrap = launch_arguments('Fixture','',len(helper))[-1]
result = _exchange([python,'-I','-u','-c',bootstrap],helper+payload,{'timeout':2},lambda:False)
assert result['ok'] and result['chars'] == len(json.loads(payload)['text']), result
start = time.time()
result = exchange('import sys; sys.stdin.buffer.read()', cancelled=lambda:time.time()-start>.3)
assert result.get('cancelled') and time.time()-start < 6, result
start = time.time()
program = "import sys,json; sys.stdin.buffer.read(); print(json.dumps(dict(protocol=1,ok=False,stdout='partial output',cancelled=True)))"
result = exchange(program,cancelled=lambda:time.time()-start>.3)
assert result.get('cancelled') and result['stdout']=='partial output', result
try:
    exchange("print('not JSON')")
    raise AssertionError('Malformed reply accepted')
except ValueError as exc:
    assert 'JSON' in str(exc), exc
try:
    exchange("print('Wsl/E_ACCESSDENIED')")
    raise AssertionError('Access denial accepted')
except ValueError as exc:
    assert 'E_ACCESSDENIED' in str(exc), exc
try:
    exchange("import sys; sys.stderr.write('Wsl/E_ACCESSDENIED'); sys.exit(1)")
    raise AssertionError('Stderr access denial accepted')
except ValueError as exc:
    assert 'E_ACCESSDENIED' in str(exc), exc
result = exchange("import sys,time; sys.stdout.write('x'*3000000);sys.stdout.flush();time.sleep(2)")
assert not result['ok'] and result.get('transport_error'), result
result = exchange("import sys,time; sys.stderr.write('x'*3000000);sys.stderr.flush();time.sleep(2)")
assert not result['ok'] and result.get('transport_error'), result
print('PASS: JVM subprocess Unicode, large stdin, EOF cancellation, stderr separation, crash detection, malformed response, access denial, and combined output cap.')

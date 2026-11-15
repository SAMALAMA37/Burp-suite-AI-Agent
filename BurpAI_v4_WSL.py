# -*- coding: utf-8 -*-
"""Jython/CPython client for the sandboxed WSL command bridge.

Commands are data on stdin, never part of a Windows shell command line. The
Linux helper is streamed from beside this module, not installed as a daemon.
"""
from __future__ import unicode_literals
import json
import os
import posixpath
import re
import sys
import threading
import time
from BurpAI_v4_LocalTools import DISTRO_NAME, decode_wsl_output

try:
    text_type = unicode
    string_types = (basestring,)
    integer_types = (int, long)
except NameError:
    text_type = str
    string_types = (str,)
    integer_types = (int,)

MAX_COMMAND = 32768
MAX_FILE = 512 * 1024
MAX_WIRE = 2 * 1024 * 1024
USER_NAME = re.compile(r'^[a-zA-Z_][a-zA-Z0-9_-]{0,31}\Z')


def bounded_integer(value, low, high, label):
    if isinstance(value, bool) or not isinstance(value, integer_types) or not low <= value <= high:
        raise ValueError('{} must be an integer from {} to {}.'.format(label, low, high))
    return value


def workspace_path(value, allow_root=False):
    if not isinstance(value, string_types) or '\x00' in value or '\\' in value or len(value) > 1024:
        raise ValueError('Use a relative Linux workspace path.')
    if value == '/workspace' or value.startswith('/workspace/'):
        value = value[len('/workspace'):].lstrip('/')
    if value.startswith('/') or '..' in value.split('/'):
        raise ValueError('Paths must stay inside /workspace.')
    value = posixpath.normpath(value or '.')
    if value == '.' and not allow_root:
        raise ValueError('Enter a filename inside /workspace.')
    return value


def normalize_request(operation, arguments, allow_network=False):
    if not isinstance(arguments, dict):
        raise ValueError('Tool arguments must be an object.')
    specs = {'probe': (), 'exec': ('command', 'cwd', 'timeout', 'network', 'max_output'),
             'write_file': ('path', 'content', 'overwrite'),
             'read_file': ('path', 'offset', 'limit'), 'list_files': ('path', 'offset'),
             'list_tools': ('query', 'offset')}
    if operation not in specs or set(arguments) - set(specs[operation]):
        raise ValueError('Unknown WSL operation or argument.')
    result = dict(arguments, operation=operation)
    if operation == 'exec':
        command = arguments.get('command')
        if not isinstance(command, string_types) or not command.strip() or '\x00' in command:
            raise ValueError('Provide a nonempty Bash command without NUL characters.')
        if len(command.encode('utf-8')) > MAX_COMMAND:
            raise ValueError('Commands are limited to 32 KiB; use wsl_write_file for scripts.')
        result['cwd'] = workspace_path(arguments.get('cwd', '.'), True)
        result['timeout'] = bounded_integer(arguments.get('timeout', 60), 1, 300, 'Timeout')
        result['max_output'] = bounded_integer(arguments.get('max_output', 65536), 1024, 262144, 'Output limit')
        network = arguments.get('network', allow_network)
        if not isinstance(network, bool):
            raise ValueError('network must be true or false.')
        if network and not allow_network:
            raise ValueError('Network access is off. Enable it in Local Tools > WSL terminal and reconnect.')
        result['network'] = network
    elif operation in ('write_file', 'read_file', 'list_files'):
        result['path'] = workspace_path(arguments.get('path', '.'), operation == 'list_files')
        if operation == 'write_file':
            content = arguments.get('content')
            if not isinstance(content, string_types) or len(content.encode('utf-8')) > MAX_FILE:
                raise ValueError('File content must be UTF-8 text up to 512 KiB.')
            if not isinstance(arguments.get('overwrite', False), bool):
                raise ValueError('overwrite must be true or false.')
            result['overwrite'] = arguments.get('overwrite', False)
        else:
            result['offset'] = bounded_integer(arguments.get('offset', 0), 0, 67108864, 'Offset')
            if operation == 'read_file':
                result['limit'] = bounded_integer(arguments.get('limit', 16384), 1, 65536, 'Read limit')
    elif operation == 'list_tools':
        query = arguments.get('query', '')
        if not isinstance(query, string_types) or len(query) > 128:
            raise ValueError('Tool filter must be text up to 128 characters.')
        result['offset'] = bounded_integer(arguments.get('offset', 0), 0, 100000, 'Offset')
    return result


def launch_arguments(distro, user, helper_size):
    if not isinstance(distro, string_types) or not DISTRO_NAME.match(distro):
        raise ValueError('Select a WSL distribution.')
    if user and (not isinstance(user, string_types) or not USER_NAME.match(user)):
        raise ValueError('Use a valid Linux username, or leave it blank for the default user.')
    args = ['--distribution', distro]
    if user:
        args += ['--user', user]
    # The exact-sized bootstrap precedes one JSON line. Keep stdin open after it:
    # EOF is the authenticated, per-process cancellation channel.
    # Single quotes avoid Windows/Java command-line double-quote interpretation.
    bootstrap = "import sys;exec(compile(sys.stdin.buffer.read(%d),'<burpai-wsl>','exec'))" % helper_size
    return args + ['--exec', '/usr/bin/python3', '-I', '-u', '-c', bootstrap]


class WSLBridge(object):
    def __init__(self, transport=None):
        self.transport = transport or run_wsl
        self.lock = threading.RLock()
        self.busy = threading.Lock()
        self.cancel_event = None
        self.config = None
        self.details = {}
        self.revision = 0

    def status(self):
        with self.lock:
            result = dict(self.details)
            result.update(connected=self.config is not None, running=self.cancel_event is not None)
            if self.config:
                result.update(distribution=self.config[0], user=self.config[1], network_allowed=self.config[2])
            return result

    def cancel(self):
        with self.lock:
            self.revision += 1
            if self.cancel_event:
                self.cancel_event.set()

    def disconnect(self):
        with self.lock:
            self.config = None
            self.details = {}
            self.cancel()

    def connect(self, distro, user='', network=True, cancelled=None):
        launch_arguments(distro, user, 1)
        if not isinstance(network, bool):
            raise ValueError('Network setting must be boolean.')
        self.disconnect()
        with self.lock:
            revision = self.revision
        result = self._perform((distro, user, network), 'probe', {}, cancelled, revision)
        if result.get('ok'):
            with self.lock:
                if revision != self.revision or (cancelled and cancelled()):
                    result.update(ok=False, cancelled=True)
                else:
                    self.config = (distro, user, network)
                    self.details = result
        return result

    def request(self, operation, arguments=None, cancelled=None):
        with self.lock:
            config = self.config
            revision = self.revision
        if config is None:
            return {'ok': False, 'error': 'Connect in Local Tools > WSL terminal first.'}
        return self._perform(config, operation, arguments if arguments is not None else {}, cancelled, revision)

    def _perform(self, config, operation, arguments, cancelled, revision):
        if not self.busy.acquire(False):
            return {'ok': False, 'error': 'A WSL operation is already running. Stop it or wait for its result.'}
        event = threading.Event()
        try:
            request = normalize_request(operation, arguments, config[2])
            with self.lock:
                self.cancel_event = event
            def stopped():
                return event.is_set() or self.revision != revision or bool(cancelled and cancelled())
            if stopped():
                return {'ok': False, 'cancelled': True, 'error': 'WSL operation cancelled.'}
            result = self.transport(config[0], config[1], request, stopped)
            if stopped():
                result.update(ok=False, cancelled=True)
            return result
        except Exception as exc:
            return {'ok': False, 'error': text_type(exc)[:1000]}
        finally:
            with self.lock:
                self.cancel_event = None
            self.busy.release()


def run_wsl(distro, user, request, cancelled):
    """Bounded transport for Burp's JVM; the Linux helper supervises descendants."""
    from java.lang import System
    if not System.getProperty('os.name', '').lower().startswith('windows'):
        raise ValueError('The WSL bridge requires Burp running on Windows.')
    system_root = System.getenv('SystemRoot')
    if not system_root:
        raise ValueError('Could not locate wsl.exe.')
    executable = os.path.join(system_root, 'System32', 'wsl.exe')
    if System.getProperty('sun.arch.data.model') == '32':
        executable = os.path.join(system_root, 'Sysnative', 'wsl.exe')
    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'burpai_wsl_runner.py'), 'rb') as handle:
        helper = handle.read(128 * 1024 + 1)
    if len(helper) > 128 * 1024:
        raise ValueError('WSL helper exceeds the expected source size.')
    payload = helper + (json.dumps(request, ensure_ascii=True) + '\n').encode('ascii')
    return _exchange([executable] + launch_arguments(distro, user, len(helper)), payload, request, cancelled)


def _exchange(argv, payload, request, cancelled):
    """Private transport seam also exercised using a local fixture process."""
    from java.io import BufferedInputStream, ByteArrayOutputStream
    from java.lang import ProcessBuilder, String
    from jarray import zeros
    process = ProcessBuilder(argv).start()
    incoming = BufferedInputStream(process.getInputStream())
    diagnostic_input = BufferedInputStream(process.getErrorStream())
    outgoing = process.getOutputStream()
    output = ByteArrayOutputStream()
    diagnostics = ByteArrayOutputStream()
    output_lock = threading.Lock()
    errors = []

    def drain(source, target):
        try:
            chunk = zeros(8192, 'b')
            while True:
                count = source.read(chunk)
                if count < 0:
                    return
                with output_lock:
                    if output.size() + diagnostics.size() + count > MAX_WIRE:
                        errors.append('WSL bridge response exceeded 2 MiB.')
                        return
                    target.write(chunk, 0, count)
        except Exception:
            errors.append('WSL output closed unexpectedly.')

    def send():
        try:
            outgoing.write(String(payload.decode('utf-8')).getBytes('UTF-8'))
            outgoing.flush()
        except Exception:
            errors.append('Could not send the operation to WSL.')

    reader = threading.Thread(target=drain, args=(incoming, output), name='BurpAI WSL output')
    diagnostic_reader = threading.Thread(target=drain, args=(diagnostic_input, diagnostics), name='BurpAI WSL diagnostics')
    writer = threading.Thread(target=send, name='BurpAI WSL input')
    reader.daemon = diagnostic_reader.daemon = writer.daemon = True
    start = time.time()
    stopping = None
    reason = None
    try:
        reader.start()
        diagnostic_reader.start()
        writer.start()
        while process.isAlive():
            if stopping is None and (cancelled() or errors or time.time() - start > request.get('timeout', 20) + 15):
                reason = 'cancelled' if cancelled() else 'transport_error' if errors else 'timed_out'
                stopping = time.time()
                # Linux observes EOF, kills its process group and waits for cleanup.
                # close() can block behind an in-flight Java write; keep Stop responsive.
                closer = threading.Thread(target=outgoing.close, name='BurpAI WSL cancel')
                closer.daemon = True
                closer.start()
            if stopping is not None and time.time() - stopping > 4:
                process.destroyForcibly()
                break
            time.sleep(.05)
        reader.join(2)
        diagnostic_reader.join(2)
        raw = output.toByteArray().tostring()
        decoded = decode_wsl_output(raw).strip()
        diagnostic_text = decode_wsl_output(diagnostics.toByteArray().tostring()).strip()
        if reader.is_alive() or diagnostic_reader.is_alive():
            raise ValueError('WSL output did not close.')
        if process.isAlive():
            raise ValueError('WSL helper did not exit after cancellation.')
        exit_code = process.exitValue()
        try:
            result = json.loads(decoded)
        except ValueError:
            if 'E_ACCESSDENIED' in decoded or 'E_ACCESSDENIED' in diagnostic_text:
                raise ValueError('Windows denied WSL access (E_ACCESSDENIED). Check WSL from your normal Windows session.')
            if reason or errors:
                return {'ok': False, reason or 'transport_error': True,
                        'error': errors[0] if errors else 'WSL operation ' + reason}
            detail = diagnostic_text or decoded
            raise ValueError('WSL helper returned invalid JSON (exit {}). {}'.format(exit_code, detail[:700]))
        if not isinstance(result, dict) or result.get('protocol') != 1:
            raise ValueError('Invalid WSL bridge response.')
        if diagnostic_text:
            result['stderr'] = (text_type(result.get('stderr') or '') + '\n' + diagnostic_text).strip()
        if exit_code != 0:
            result.update(ok=False, bridge_exit_code=exit_code,
                          error='WSL helper exited with code {}.'.format(exit_code))
        if reason or errors:
            result.update(ok=False, error=errors[0] if errors else 'WSL operation ' + reason)
            result[reason or 'transport_error'] = True
        return result
    finally:
        if process.isAlive():
            process.destroyForcibly()
        try: outgoing.close()
        except Exception: pass
        try: incoming.close()
        except Exception: pass
        try: diagnostic_input.close()
        except Exception: pass

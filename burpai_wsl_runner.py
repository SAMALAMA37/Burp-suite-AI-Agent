#!/usr/bin/env python3
"""Trusted Linux supervisor. Streamed into WSL by BurpAI_v4_WSL.py.

No listener, shell profile, sudo, Windows mount, or unsandboxed fallback.
Only this supervisor touches the host; all model-supplied data runs in bwrap.
"""
from __future__ import unicode_literals
import json
import os
import select
import signal
import stat
import subprocess
import sys
import threading
import time

SYSTEM_TREES = ('/usr', '/bin', '/sbin', '/lib', '/lib64', '/opt')
CONFIG_TREES = ('/etc/ssl', '/etc/alternatives', '/etc/java-17-openjdk', '/etc/java-21-openjdk')
CONFIG_FILES = ('/etc/resolv.conf', '/etc/hosts', '/etc/nsswitch.conf',
                '/etc/ld.so.cache', '/etc/services', '/etc/protocols', '/etc/passwd', '/etc/group')
TOOL_PATH = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'

# This program executes only *inside* the same sandbox as terminal commands.
# File paths additionally reject traversal and symlinks, including FIFOs/devices.
FILE_PROGRAM = r'''
import json, os, stat, sys, tempfile
args = json.loads(sys.stdin.read())
operation = args['operation']
def location(value):
    if value.startswith('/') or '..' in value.split('/') or '\\' in value or '\x00' in value:
        raise ValueError('Use a workspace-relative path.')
    path = os.path.join('/workspace', value)
    current = '/workspace'
    for part in value.split('/'):
        if part in ('', '.'): continue
        current = os.path.join(current, part)
        if os.path.islink(current): raise ValueError('File tools do not follow symlinks.')
    return path
result = {'ok': True}
if operation == 'probe':
    assert os.path.isdir('/workspace') and not os.path.exists('/mnt/c') and not os.path.exists('/init')
    assert not os.environ.get('WSL_INTEROP')
    assert os.statvfs('/usr').f_flag & os.ST_RDONLY, 'System mount is not read-only'
    # Verify an actual protected system write fails, not just bwrap's exit code.
    try:
        fd, path = tempfile.mkstemp(prefix='.burpai-probe-', dir='/usr')
    except OSError:
        pass
    else:
        os.close(fd); os.unlink(path)
        raise RuntimeError('System tree unexpectedly writable.')
    fd, path = tempfile.mkstemp(prefix='.burpai-probe-', dir='/workspace')
    os.close(fd); os.unlink(path)
    result.update(sandbox='bubblewrap', workspace='/workspace', uid=os.getuid())
elif operation == 'list_tools':
    tools = {}
    for folder in os.environ['PATH'].split(':'):
        if not os.path.isdir(folder): continue
        for name in os.listdir(folder):
            path = os.path.join(folder, name)
            if os.path.isfile(path) and os.access(path, os.X_OK) and name not in tools:
                tools[name] = path
    query = args.get('query', '').lower()
    names = sorted(n for n in tools if query in n.lower())
    start = args.get('offset', 0); end = min(start + 100, len(names))
    result.update(tools=[{'name': n, 'path': tools[n]} for n in names[start:end]],
                  total=len(names), next_offset=end if end < len(names) else None)
elif operation == 'write_file':
    path = location(args['path'])
    parent = os.path.dirname(path)
    os.makedirs(parent, mode=0o700, exist_ok=True)
    location(args['path'])
    # Atomic replacement prevents editing a host hardlink imported into workspace.
    # O_EXCL via link also makes no-overwrite atomic.
    fd, temporary = tempfile.mkstemp(prefix='.burpai-write-', dir=parent)
    try:
        with os.fdopen(fd, 'wb') as stream: stream.write(args['content'].encode('utf-8'))
        if args.get('overwrite', False): os.replace(temporary, path)
        else: os.link(temporary, path)
    finally:
        if os.path.exists(temporary): os.unlink(temporary)
    result.update(path=args['path'], bytes_written=len(args['content'].encode('utf-8')))
elif operation == 'read_file':
    path = location(args['path'])
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode): raise ValueError('Select a regular file.')
        start = args.get('offset', 0); stream.seek(start)
        raw = stream.read(args.get('limit', 16384))
    end = start + len(raw)
    result.update(path=args['path'], content=raw.decode('utf-8', 'replace'),
                  offset=start, size_bytes=info.st_size, next_offset=end if end < info.st_size else None,
                  encoding='UTF-8; offsets are bytes, invalid/split characters are replaced')
elif operation == 'list_files':
    path = location(args.get('path', '.'))
    names = sorted(os.listdir(path))
    start = args.get('offset', 0); end = min(start + 100, len(names))
    items = []
    for name in names[start:end]:
        info = os.lstat(os.path.join(path, name))
        kind = 'symlink' if stat.S_ISLNK(info.st_mode) else 'directory' if stat.S_ISDIR(info.st_mode) else 'file' if stat.S_ISREG(info.st_mode) else 'special'
        items.append({'name': name, 'kind': kind, 'size_bytes': info.st_size})
    result.update(path=args.get('path', '.'), entries=items, total=len(names),
                  next_offset=end if end < len(names) else None)
else:
    raise ValueError('Unknown operation.')
print(json.dumps(result, ensure_ascii=True))
'''


def workspace_directory(home):
    """Create only our private data directory, never traverse user symlinks."""
    home = os.path.abspath(home)
    if home == '/' or os.path.realpath(home) != home:
        raise ValueError('The Linux home directory must be a real, non-root directory.')
    current = home
    # Keep the parent private. The sandbox never sees it and cannot rename its
    # own workspace mount or replace it with a symlink to another host directory.
    for name in ('.burpai-wsl', 'workspace'):
        current = os.path.join(current, name)
        try:
            os.mkdir(current, 0o700)
        except OSError:
            if not os.path.lexists(current): raise
        info = os.lstat(current)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError('WSL workspace must be a private, owned directory without symlinks: ' + current)
    return current


def sandbox_arguments(workspace, home, network, cwd='.'):
    args = ['/usr/bin/bwrap', '--unshare-user', '--unshare-pid', '--unshare-ipc',
            '--unshare-uts', '--unshare-cgroup-try', '--die-with-parent', '--new-session',
            '--cap-drop', 'ALL', '--clearenv']
    if not network:
        args.append('--unshare-net')
    # Start from bwrap's empty root. /home, /root, /mnt, /run and /init are absent.
    for path in SYSTEM_TREES:
        if os.path.lexists(path):
            if os.path.islink(path):
                args += ['--symlink', os.readlink(path), path]
            else:
                args += ['--ro-bind', path, path]
    args += ['--dir', '/etc']
    for path in CONFIG_TREES + CONFIG_FILES:
        if os.path.exists(path):
            args += ['--ro-bind', os.path.realpath(path), path]
    search = TOOL_PATH
    # User-installed Python/pipx and Go tools, with dependencies, read-only.
    # Bind at their original location so interpreter shebangs continue to work.
    for relative in ('.local/bin', '.local/lib', '.local/share/pipx', '.local/pipx', 'go'):
        path = os.path.join(home, relative)
        if os.path.isdir(path) and os.path.realpath(path) == path:
            args += ['--ro-bind', path, path]
            if relative == '.local/bin': search += ':' + path
            elif relative == 'go': search += ':' + path + '/bin'
    args += ['--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp',
             '--bind', workspace, '/workspace', '--chdir', '/workspace/' + cwd,
             '--setenv', 'HOME', '/workspace', '--setenv', 'PATH', search,
             '--setenv', 'LANG', 'C.UTF-8', '--setenv', 'TERM', 'dumb',
             '--setenv', 'PYTHONUSERBASE', os.path.join(home, '.local'),
             '--setenv', 'PYTHONUNBUFFERED', '1', '--setenv', 'PIP_CACHE_DIR', '/workspace/.cache/pip',
             '--setenv', 'XDG_CACHE_HOME', '/workspace/.cache',
             '--setenv', 'XDG_CONFIG_HOME', '/workspace/.config',
             '--setenv', 'XDG_DATA_HOME', '/workspace/.local/share']
    return args


def resource_limits(timeout):
    import resource
    # These are per-process limits, not a whole-workspace disk quota.
    for name, limit in (('RLIMIT_CORE', 0), ('RLIMIT_FSIZE', 64 * 1024 * 1024),
                        ('RLIMIT_NOFILE', 512), ('RLIMIT_NPROC', 128),
                        ('RLIMIT_AS', 2 * 1024 * 1024 * 1024), ('RLIMIT_CPU', timeout + 1)):
        key = getattr(resource, name)
        soft, hard = resource.getrlimit(key)
        ceiling = limit if hard == resource.RLIM_INFINITY else min(limit, hard)
        resource.setrlimit(key, (ceiling, ceiling))


def supervise(argv, input_bytes, timeout, maximum, control=None):
    """Drain both pipes concurrently; enforce deadlines and kill the PID tree."""
    process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               start_new_session=True, preexec_fn=lambda: resource_limits(timeout))
    overflow = threading.Event()
    lock = threading.Lock()
    retained = [0]
    output = {'stdout': [], 'stderr': []}
    started = time.monotonic()
    def control_ready():
        # The caller keeps this pipe open until cancellation. Readability means
        # EOF or a cancellation byte. Never block a daemon thread on Python's
        # buffered stdin: it would hold its lock during interpreter shutdown.
        return control is not None and bool(select.select([control], [], [], 0)[0])
    def drain(stream, key):
        while True:
            chunk = os.read(stream.fileno(), 8192)
            if not chunk: break
            with lock:
                keep = max(0, maximum - retained[0])
                output[key].append(chunk[:keep])
                retained[0] += min(keep, len(chunk))
                if len(chunk) > keep: overflow.set()
    def send():
        try:
            process.stdin.write(input_bytes)
            process.stdin.close()
        except (OSError, ValueError): pass
    readers = []
    for stream, key in ((process.stdout, 'stdout'), (process.stderr, 'stderr')):
        worker = threading.Thread(target=drain, args=(stream, key), daemon=True)
        worker.start(); readers.append(worker)
    writer = threading.Thread(target=send, daemon=True); writer.start()
    reason = None
    try:
        while process.poll() is None:
            if control_ready(): reason = 'cancelled'
            elif overflow.is_set(): reason = 'output_limit'
            elif time.monotonic() - started >= timeout: reason = 'timed_out'
            if reason: break
            time.sleep(.04)
    finally:
        # Also kill when the leader exited: disowned/background commands must
        # never persist. Killing bwrap PID 1 tears down the private PID namespace.
        try: os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError: pass
        try: process.wait(timeout=1)
        except subprocess.TimeoutExpired: pass
        try: os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError: pass
        process.wait()
        for worker in readers: worker.join(1)
        writer.join(1)
        process.stdout.close()
        process.stderr.close()
    if overflow.is_set() and reason is None: reason = 'output_limit'
    if reason is None and control_ready(): reason = 'cancelled'
    result = dict((key, b''.join(chunks).decode('utf-8', 'replace')) for key, chunks in output.items())
    result.update(ok=process.returncode == 0 and reason is None, exit_code=process.returncode,
                  duration_ms=int((time.monotonic() - started) * 1000),
                  timed_out=reason == 'timed_out', cancelled=reason == 'cancelled', truncated=overflow.is_set())
    if reason: result['error'] = reason
    return result


def run(request, control=None):
    import pwd
    if os.getuid() == 0:
        raise ValueError('Choose a non-root Linux user in WSL terminal. Root execution is not supported.')
    if not os.path.isfile('/usr/bin/bwrap'):
        raise ValueError('bubblewrap is missing. In your WSL terminal run: sudo apt install bubblewrap python3')
    home = pwd.getpwuid(os.getuid()).pw_dir
    workspace = workspace_directory(home)
    operation = request['operation']
    network = operation == 'exec' and request.get('network') is True
    argv = sandbox_arguments(workspace, home, network, request.get('cwd', '.'))
    if operation == 'exec':
        argv += ['--', '/bin/bash', '--noprofile', '--norc', '-c', request['command']]
        input_bytes = b''
    else:
        argv += ['--', '/usr/bin/python3', '-I', '-c', FILE_PROGRAM]
        input_bytes = json.dumps(request, ensure_ascii=True).encode('ascii')
    result = supervise(argv, input_bytes, request.get('timeout', 20), request.get('max_output', 524288), control)
    if operation != 'exec' and result['ok']:
        result = json.loads(result['stdout'])
    if operation == 'probe' and result.get('ok'):
        result.update(host_workspace=workspace, linux_user=pwd.getpwuid(os.getuid()).pw_name,
                      system_read_only=True, windows_drives=False)
    result.update(network=network, workspace='/workspace')
    return result


def main():
    try:
        raw = sys.stdin.buffer.readline(4 * 1024 * 1024)
        if not raw.endswith(b'\n'): raise ValueError('Bridge request too large or incomplete.')
        request = json.loads(raw)
        result = run(request, sys.stdin.buffer)
    except Exception as exc:
        result = {'ok': False, 'error': str(exc)[:1000]}
    result['protocol'] = 1
    print(json.dumps(result, ensure_ascii=True))


if __name__ == '__main__':
    main()

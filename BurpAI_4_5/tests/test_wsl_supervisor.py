"""Supervisor lifecycle regressions with harmless child processes and fixtures."""
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import burpai_wsl_runner as runner


# Windows cannot supervise a Linux process group or select a pipe. Substitute
# those platform operations only; exercise the real supervisor and main(),
# including interpreter shutdown while the parent still holds stdin open.
SHUTDOWN_FIXTURE = r'''
import json, os, signal, subprocess, sys, threading
from unittest.mock import patch
sys.path.insert(0, sys.argv[1])
import burpai_wsl_runner as runner
real_popen = subprocess.Popen
def launch(argv, **kwargs):
    kwargs.pop('preexec_fn', None)
    kwargs.pop('start_new_session', None)
    return real_popen(argv, **kwargs)
def execute(request, control):
    result = runner.supervise([sys.executable, '-I', '-u', '-c',
        "print('probe fixture')"], b'', 3, 4096, control)
    result['active_workers'] = [t.name for t in threading.enumerate()
                                if t is not threading.main_thread()]
    return result
import select
with patch.object(runner, 'run', execute), patch.object(runner.subprocess, 'Popen', launch), \
     patch.object(runner.os, 'killpg', lambda *args: None, create=True), \
     patch.object(signal, 'SIGKILL', 9, create=True), \
     patch.object(select, 'select', return_value=([], [], [])):
    runner.main()
'''


class SupervisorTests(unittest.TestCase):
    def test_helper_exits_cleanly_while_parent_keeps_stdin_open(self):
        process = subprocess.Popen([sys.executable, '-I', '-u', '-c', SHUTDOWN_FIXTURE, str(ROOT)],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            process.stdin.write(b'{"operation":"probe"}\n')
            process.stdin.flush()
            # communicate() would close stdin and conceal the reported bug.
            process.wait(timeout=8)
            output, errors = process.stdout.read(), process.stderr.read()
            self.assertEqual(0, process.returncode, errors.decode('utf-8', 'replace'))
            self.assertEqual(b'', errors)
            result = json.loads(output)
            self.assertTrue(result['ok'], result)
            self.assertEqual(1, result['protocol'])
            self.assertEqual([], result['active_workers'])
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=3)
            for stream in (process.stdin, process.stdout, process.stderr):
                stream.close()

    def test_control_readiness_cancels_without_reading_buffered_stdin(self):
        class Control:
            def read(self, *args):
                raise AssertionError('Buffered control reads can block interpreter shutdown')
        control = Control()
        with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
            class Process:
                pid = 12345
                returncode = None
                stdin = io.BytesIO()
                def poll(self): return self.returncode
                def wait(self, timeout=None): return self.returncode
            process = Process()
            process.stdout, process.stderr = stdout, stderr
            def kill(pid, sig):
                self.assertEqual(process.pid, pid)
                process.returncode = -15
            with patch.object(runner.subprocess, 'Popen', return_value=process), \
                 patch.object(runner.os, 'killpg', side_effect=kill, create=True), \
                 patch.object(runner.signal, 'SIGKILL', 9, create=True), \
                 patch('select.select', return_value=([control], [], [])) as poll:
                result = runner.supervise(['fixture'], b'', 1, 1024, control)
            self.assertTrue(result['cancelled'], result)
            self.assertFalse(result['ok'])
            self.assertFalse(result['timed_out'])
            self.assertEqual(([control], [], [], 0), poll.call_args[0])


if __name__ == '__main__':
    unittest.main()

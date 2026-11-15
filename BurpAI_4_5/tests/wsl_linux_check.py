#!/usr/bin/env python3
"""Optional real Linux sandbox checks. No target traffic; requires non-root + bwrap.

In WSL: python3 /mnt/c/kali/BurpAI_4_5/tests/wsl_linux_check.py
Test files remain in the dedicated workspace for inspection.
"""
import json
import os
import subprocess
import sys
import time
import unittest
import uuid

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import burpai_wsl_runner as runner
from BurpAI_v4_WSL import launch_arguments, normalize_request


@unittest.skipUnless(sys.platform.startswith('linux') and os.path.isfile('/usr/bin/bwrap') and os.getuid() != 0,
                     'Requires Linux, bubblewrap and a non-root user.')
class LinuxSandboxTests(unittest.TestCase):
    def operation(self, op, **args):
        return runner.run(normalize_request(op,args,allow_network=True))

    def test_streamed_probe_exits_with_control_pipe_open(self):
        with open(runner.__file__, 'rb') as handle:
            helper = handle.read()
        bootstrap = launch_arguments('Fixture', '', len(helper))[-1]
        process = subprocess.Popen([sys.executable, '-I', '-u', '-c', bootstrap],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            process.stdin.write(helper + b'{"operation":"probe"}\n')
            process.stdin.flush()
            process.wait(timeout=30)
            output, errors = process.stdout.read(), process.stderr.read()
            self.assertEqual(0, process.returncode, errors.decode('utf-8', 'replace'))
            result = json.loads(output)
            self.assertTrue(result['ok'], result)
            self.assertEqual(1, result['protocol'])
            self.assertNotIn(b'Fatal Python error', errors)
        finally:
            if process.poll() is None:
                process.kill(); process.wait(timeout=5)
            for stream in (process.stdin, process.stdout, process.stderr):
                stream.close()

    def test_default_network_shares_host_namespace(self):
        result = self.operation('exec', command='readlink /proc/self/ns/net')
        self.assertTrue(result['ok'], result)
        self.assertTrue(result['network'])
        self.assertEqual(os.readlink('/proc/self/ns/net'), result['stdout'].strip())

    def test_mounts_and_files(self):
        self.assertTrue(self.operation('probe')['ok'])
        name='bridge-check-'+uuid.uuid4().hex+'.py'
        self.assertTrue(self.operation('write_file',path=name,content='print("unicode: \u03bb")\n')['ok'])
        self.assertFalse(self.operation('write_file',path=name,content='overwrite')['ok'])
        result=self.operation('exec',command='python3 '+name)
        self.assertTrue(result['ok'],result)
        self.assertIn('unicode: \u03bb',result['stdout'])
        self.assertTrue(self.operation('read_file',path=name)['ok'])
        self.assertTrue(self.operation('list_files')['ok'])
        result=self.operation('exec',command="touch /usr/.burpai-no-write; test ! -e /mnt/c && test ! -e /init")
        self.assertIn('Read-only',result['stderr'])
        self.assertEqual(0,result['exit_code'])
        self.assertIn('python3',str(self.operation('list_tools',query='python3')))

    def test_symlinks_special_files_and_unicode(self):
        name='bridge-check-'+uuid.uuid4().hex
        self.assertTrue(self.operation('exec',command='ln -s /usr '+name+'; mkfifo '+name+'-fifo')['ok'])
        self.assertFalse(self.operation('read_file',path=name+'/bin/env')['ok'])
        self.assertFalse(self.operation('write_file',path=name+'/x',content='x')['ok'])
        self.assertFalse(self.operation('read_file',path=name+'-fifo')['ok'])
        self.assertTrue(self.operation('write_file',path=name+'-\u03bb.txt',content='\u03bb\u00f3\u017a')['ok'])

    def test_deadline_output_cap_and_child_cleanup(self):
        result=self.operation('exec',command='sleep 30',timeout=1)
        self.assertTrue(result['timed_out'],result)
        result=self.operation('exec',command='yes bounded',max_output=1024)
        self.assertTrue(result['truncated'],result)
        self.assertLessEqual(len(result['stdout'].encode('utf-8')),1024)
        name='bridge-check-'+uuid.uuid4().hex
        result=self.operation('exec',command='(sleep 2; touch '+name+') & wait',timeout=1)
        self.assertTrue(result['timed_out'],result)
        time.sleep(2)
        self.assertFalse(self.operation('read_file',path=name)['ok'])

    def test_control_pipe_eof_cancels_command(self):
        args=normalize_request('exec',{'command':'sleep 30','timeout':10})
        reader, writer = os.pipe()
        os.close(writer)
        with os.fdopen(reader, 'rb') as control:
            result=runner.run(args,control)
        self.assertTrue(result['cancelled'],result)

    def test_offline_network_namespace(self):
        # /sys is deliberately absent; use /proc/net/dev instead.
        result=self.operation('exec',command="cat /proc/net/dev",network=False)
        self.assertTrue(result['ok'],result)
        devices=[line.split(':')[0].strip() for line in result['stdout'].splitlines() if ':' in line]
        self.assertEqual(['lo'],devices)


if __name__=='__main__': unittest.main(verbosity=2)

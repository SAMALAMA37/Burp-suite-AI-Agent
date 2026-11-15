"""Portable tests of the Linux sandbox command, without requiring WSL access."""
import os
import sys
import unittest
from unittest.mock import patch
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import burpai_wsl_runner as runner


class SandboxConfigurationTests(unittest.TestCase):
    def build(self, network):
        # Model a merged-usr Linux filesystem and two conventional tool folders.
        import posixpath
        paths = set(runner.SYSTEM_TREES + runner.CONFIG_TREES + runner.CONFIG_FILES +
                    ('/home/test/.local/bin','/home/test/.local/lib','/home/test/go'))
        with patch.object(runner.os.path,'lexists',side_effect=lambda p:p in paths), \
             patch.object(runner.os.path,'exists',side_effect=lambda p:p in paths), \
             patch.object(runner.os.path,'isdir',side_effect=lambda p:p in paths), \
             patch.object(runner.os.path,'islink',side_effect=lambda p:p in ('/bin','/sbin')), \
             patch.object(runner.os,'readlink',side_effect=lambda p:'usr'+p), \
             patch.object(runner.os.path,'realpath',side_effect=lambda p:p), \
             patch.object(runner.os.path,'join',side_effect=posixpath.join):
            return runner.sandbox_arguments('/home/test/.burpai-wsl/workspace','/home/test',network)

    def test_offline_isolation_and_exact_writable_mount(self):
        argv=self.build(False)
        for flag in ('--unshare-user','--unshare-pid','--unshare-net','--unshare-ipc','--unshare-uts',
                     '--die-with-parent','--new-session','--clearenv'):
            self.assertIn(flag,argv)
        self.assertEqual(1,argv.count('--bind'))
        offset=argv.index('--bind')
        self.assertEqual(['/home/test/.burpai-wsl/workspace','/workspace'],argv[offset+1:offset+3])
        mounts=[argv[i+1:i+3] for i,x in enumerate(argv) if x=='--ro-bind']
        self.assertIn(['/usr','/usr'],mounts)
        self.assertIn(['/home/test/.local/lib','/home/test/.local/lib'],mounts)
        for forbidden in ('/','/home/test','/mnt','/run','/etc/shadow'):
            self.assertFalse(any(m[0]==forbidden for m in mounts))
        self.assertNotIn('WSL_INTEROP',argv)
        self.assertIn('/home/test/.local/bin',argv[argv.index('PATH')+1])

    def test_network_grant_preserves_other_isolation(self):
        offline=self.build(False); network=self.build(True)
        offline.remove('--unshare-net')
        self.assertEqual(offline,network)

    def test_embedded_file_program_compiles(self):
        compile(runner.FILE_PROGRAM,'<sandbox file operations>','exec')


if __name__=='__main__': unittest.main()

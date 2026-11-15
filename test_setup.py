"""Setup regression checks use temporary files and synthetic service responses."""
import contextlib
import io
import json
from pathlib import Path, PurePosixPath
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import setup_burpai as setup


class SetupTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.root_patch = patch.object(setup, 'ROOT', self.root)
        self.root_patch.start()
        self.addCleanup(self.root_patch.stop)
        self.output = io.StringIO()
        redirect = contextlib.redirect_stdout(self.output)
        redirect.__enter__()
        self.addCleanup(redirect.__exit__, None, None, None)

    def install_files(self):
        for name in setup.EXTENSION_FILES + setup.IMPORT_FILES + setup.HUB_FILES:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('# fixture', encoding='utf-8')
        with zipfile.ZipFile(self.root / setup.JYTHON, 'w') as archive:
            archive.writestr('org/python/util/jython.class', b'fixture')

    def main(self, *args):
        with patch.object(sys, 'argv', ['setup_burpai.py'] + list(args)):
            return setup.main()

    def test_default_setup_does_not_install_embeddings(self):
        fake_hub = types.ModuleType('launch_hub')
        with patch.object(setup, 'in_wsl', return_value=False), \
             patch.object(setup, 'ensure_files', return_value=self.root / setup.JYTHON), \
             patch.object(setup, 'ensure_server') as server, \
             patch.object(setup, 'ensure_model') as model, \
             patch.object(setup, 'configure') as configure, \
             patch.object(fake_hub, 'launch', create=True) as launch, \
             patch.dict(sys.modules, {'launch_hub': fake_hub}), \
             patch.object(sys, 'path', list(sys.path)):
            self.assertEqual(0, self.main())
        server.assert_not_called()
        model.assert_not_called()
        configure.assert_not_called()
        launch.assert_called_once_with(connect=True)

    def test_optional_embeddings_run_all_setup_steps(self):
        with patch.object(setup, 'in_wsl', return_value=False), \
             patch.object(setup, 'ensure_files', return_value=self.root / setup.JYTHON), \
             patch.object(setup, 'ensure_server') as server, \
             patch.object(setup, 'ensure_model') as model, \
             patch.object(setup, 'configure') as configure:
            self.assertEqual(0, self.main('--no-hub', '--with-embeddings'))
        for operation in (server, model, configure):
            operation.assert_called_once_with()

    def test_check_is_read_only_and_requires_the_wsl_runner(self):
        self.install_files()
        runner = self.root / 'burpai_wsl_runner.py'
        runner.write_text('# fixture', encoding='utf-8')
        before = {str(path.relative_to(self.root)): path.read_bytes()
                  for path in self.root.rglob('*') if path.is_file()}
        with patch.object(setup, 'in_wsl', return_value=False), \
             patch.object(setup, 'ensure_files') as ensure, \
             patch.object(setup, 'api') as api:
            self.assertEqual(0, self.main('--check', '--files-only'))
            after = {str(path.relative_to(self.root)): path.read_bytes()
                     for path in self.root.rglob('*') if path.is_file()}
            self.assertEqual(before, after)
            runner.unlink()
            self.assertEqual(1, self.main('--check', '--files-only'))
        ensure.assert_not_called()
        api.assert_not_called()

    def test_current_update_archive_restores_a_missing_runner(self):
        with zipfile.ZipFile(self.root / 'BurpAI_v4_5_WSL_Bridge_Update.zip', 'w') as archive:
            archive.writestr('burpai_wsl_runner.py', '# runner fixture')
        with zipfile.ZipFile(self.root / setup.JYTHON, 'w') as archive:
            archive.writestr('org/python/util/jython.class', b'fixture')
        with patch.object(setup, 'download') as download:
            setup.ensure_files(('burpai_wsl_runner.py',))
        self.assertEqual('# runner fixture', (self.root / 'burpai_wsl_runner.py').read_text())
        download.assert_not_called()

    def test_invalid_jar_is_rejected(self):
        with zipfile.ZipFile(self.root / setup.JYTHON, 'w') as archive:
            archive.writestr('other.txt', 'fixture')
        self.assertFalse(setup.check_files(()))
        with self.assertRaisesRegex(RuntimeError, 'Invalid Jython JAR'):
            setup.ensure_files(())

    def test_archives_fill_only_missing_files_in_version_order(self):
        self.install_files()
        helper = self.root / 'burpai_wsl_runner.py'
        extension = self.root / 'BurpAI_v4_Extension.py'
        hub = self.root / 'provider_hub' / 'launch_hub.py'
        helper.unlink()
        hub.unlink()
        with zipfile.ZipFile(self.root / 'BurpAI_v4_5_WSL_Bridge_Update.zip', 'w') as archive:
            archive.writestr(helper.name, '# current runner')
            archive.writestr(extension.name, '# should not overwrite')
            archive.writestr('../outside.py', '# should not extract')
        with zipfile.ZipFile(self.root / 'BurpAI_v4_5_Workbench.zip', 'w') as archive:
            archive.writestr(helper.name, '# old runner')
            archive.writestr('provider_hub/launch_hub.py', '# hub fixture')
        setup.ensure_files((helper.name, extension.name, 'provider_hub/launch_hub.py'))
        self.assertEqual('# current runner', helper.read_text())
        self.assertEqual('# fixture', extension.read_text())
        self.assertEqual('# hub fixture', hub.read_text())
        self.assertFalse((self.root.parent / 'outside.py').exists())

    def test_invalid_settings_are_not_overwritten(self):
        path = self.root / '.burpai_config.json'
        for content in ('[1, 2]', '{invalid'):
            with self.subTest(content=content):
                path.write_text(content, encoding='utf-8')
                with patch.object(setup.Path, 'home', return_value=self.root), \
                     self.assertRaises((RuntimeError, ValueError)):
                    setup.configure()
                self.assertEqual(content, path.read_text())

    def test_configure_preserves_existing_settings_and_backs_up(self):
        path = self.root / '.burpai_config.json'
        content = {'provider': 'hub', 'embedding_model': 'existing-model',
                   'embedding_base_url': 'https://example.invalid/v1', 'local_api_key': 'synthetic'}
        path.write_text(json.dumps(content), encoding='utf-8')
        original = path.read_bytes()
        with patch.object(setup.Path, 'home', return_value=self.root):
            setup.configure()
        saved = json.loads(path.read_text(encoding='utf-8'))
        for key, value in content.items():
            self.assertEqual(value, saved[key])
        backups = list(self.root.glob('.burpai_config.json.setup-backup-*'))
        self.assertEqual(1, len(backups))
        self.assertEqual(original, backups[0].read_bytes())

    def test_model_download_is_only_used_when_missing(self):
        for installed in (True, False):
            with self.subTest(installed=installed), \
                 patch.object(setup, 'model_installed', return_value=installed), \
                 patch.object(setup, 'pull_model') as pull, \
                 patch.object(setup, 'api', return_value={'embeddings': [[0.1, 0.2]]}):
                setup.ensure_model()
                self.assertEqual(0 if installed else 1, pull.call_count)

    def test_truncated_model_download_is_reported(self):
        response = io.BytesIO(b'{"status":"downloading","completed":10}\n')
        with patch.object(setup.OPENER, 'open', return_value=response):
            with self.assertRaisesRegex(RuntimeError, 'before reporting success'):
                setup.pull_model('fixture')

    def test_wsl_flags_choose_windows_only_for_services(self):
        for flags, handoff in (([], True), (['--check'], True),
                               (['--no-hub', '--with-embeddings'], True),
                               (['--files-only', '--check'], False),
                               (['--no-hub', '--check'], False)):
            with self.subTest(flags=flags), patch.object(setup, 'in_wsl', return_value=True), \
                 patch.object(setup, 'windows_setup', return_value=0) as windows, \
                 patch.object(setup, 'check_files', return_value=True):
                self.assertEqual(0, self.main(*flags))
                self.assertEqual(1 if handoff else 0, windows.call_count)
                if handoff:
                    windows.assert_called_once_with(flags)

    def test_windows_handoff_preserves_paths_flags_and_failure_code(self):
        script = r'C:\Project With Spaces\setup_burpai.py'
        python = '/mnt/c/Users/Test User/Programs/Python/Python311/python.exe'
        def capture(args, **kwargs):
            if args[0] == 'wslpath':
                return script if args[1] == '-w' else '/mnt/c/Users/Test User'
            if args[0] == 'powershell.exe':
                return r'C:\Users\Test User'
            if args[0] == python:
                return 'True\r\n'
            raise AssertionError(args)
        with patch.object(setup.shutil, 'which', side_effect=lambda name: name), \
             patch.object(setup.Path, 'glob', return_value=[PurePosixPath(python)]), \
             patch.object(setup.subprocess, 'check_output', side_effect=capture), \
             patch.object(setup.subprocess, 'run', return_value=subprocess.CompletedProcess([], 7)) as run:
            self.assertEqual(7, setup.windows_setup(['--check', '--no-hub']))
        run.assert_called_once_with([python, script, '--check', '--no-hub'])

    def test_windows_handoff_missing_interop_has_actionable_error(self):
        with patch.object(setup.shutil, 'which', return_value=None):
            with self.assertRaisesRegex(RuntimeError, 'Windows PowerShell'):
                setup.windows_setup([])


if __name__ == '__main__':
    unittest.main()

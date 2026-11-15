# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import io
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from BurpAI_v4_LocalTools import (FixtureWorkspace, MAX_FIXTURE_BYTES, distro_names,
                                  inventory_arguments, inventory_names, normalize_checks,
                                  parse_json, save_report)


class FixtureTests(unittest.TestCase):
    def test_assertions_distinguish_missing_null_boolean_and_number(self):
        workspace = FixtureWorkspace()
        fixture = workspace.load(b'{"ok":true,"status":200,"body":{"a/b":[null]}}')
        report = workspace.run(fixture['fixture_id'], [
            {'path': '/ok', 'op': 'equals', 'expected': 1},
            {'path': '/status', 'op': 'equals', 'expected': 200},
            {'path': '/body/a~1b/0', 'op': 'exists'},
            {'path': '/body/a~1b/0', 'op': 'type_is', 'expected': 'null'},
            {'path': '/body/a~1b/1', 'op': 'missing'},
        ])
        self.assertEqual(4, report['passed'])
        self.assertEqual('assertion_failed', report['outcomes'][0]['reason'])
        self.assertNotIn('document', report)

    def test_invalid_load_keeps_previous_selection_and_clear_revokes_it(self):
        workspace = FixtureWorkspace()
        fixture = workspace.load(b'{"status":200}')
        with self.assertRaises(ValueError):
            workspace.load(b'{"status":200,"status":500}')
        self.assertEqual(fixture, workspace.info())
        workspace.clear()
        with self.assertRaises(ValueError):
            workspace.run(fixture['fixture_id'], [{'path': '/status', 'op': 'exists'}])

    def test_plans_are_data_and_json_inputs_are_bounded(self):
        for check in ({'path': '/status', 'op': 'exec', 'expected': 'echo hello'},
                      {'path': '/status', 'op': 'exists', 'command': 'echo hello'},
                      {'path': '../fixture.json', 'op': 'exists'},
                      {'path': '/~2', 'op': 'exists'}):
            with self.assertRaises(ValueError):
                normalize_checks([check])
        for raw in (b'[' * 41 + b'0' + b']' * 41, b'1e999', b'1' * 129,
                    b' ' * (MAX_FIXTURE_BYTES + 1)):
            with self.assertRaises(ValueError):
                parse_json(raw, MAX_FIXTURE_BYTES)
        self.assertEqual({'text': '[{}]'}, parse_json(b'{"text":"[{}]"}', 100))

    def test_report_creation_cannot_overwrite_existing_file(self):
        directory = tempfile.mkdtemp(prefix='burpai-report-')
        try:
            path = os.path.join(directory, 'report.json')
            save_report(path, {'total': 1})
            with self.assertRaises(OSError):
                save_report(path, {'total': 2})
            with io.open(path, 'rb') as handle:
                self.assertEqual({'total': 1}, parse_json(handle.read(), 100))
        finally:
            shutil.rmtree(directory)


class CatalogTests(unittest.TestCase):
    def test_wsl_names_and_fixed_inventory_query(self):
        output = '\ufeffUbuntu\r\nKali (Work)\r\nUbuntu\r\n'.encode('utf-16-le')
        self.assertEqual(['Kali (Work)', 'Ubuntu'], distro_names(output))
        self.assertEqual(['awk', 'grep'], inventory_names(b'grep\nawk\ngrep\na/b\n'))
        args = inventory_arguments('Kali (Work)')
        self.assertEqual(['--distribution', 'Kali (Work)', '--exec', '/usr/bin/find'], args[:4])
        self.assertNotIn('-exec', args)
        with self.assertRaises(ValueError):
            inventory_arguments('--exec')


if __name__ == '__main__':
    unittest.main()

# -*- coding: utf-8 -*-
"""Persistence, map structure and executable-content boundaries. No network."""
from __future__ import unicode_literals
import base64
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from BurpAI_v4_Documents import DocumentLibrary, parse_outline, MAX_MARKDOWN_BYTES


class DocumentTests(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix='burpai-documents-')
        self.library = DocumentLibrary(self.root)

    def tearDown(self):
        shutil.rmtree(self.root)

    def test_unicode_persistence_and_new_revision_preserve_previous_files(self):
        first = self.library.save('Notatki: za\u017c\u00f3\u0142\u0107', '# Wst\u0119p\n\n**Unicode works.**', tags=['research'])
        reloaded = DocumentLibrary(self.root)
        self.assertIn('Wst\u0119p', reloaded.read(first['id'])['markdown'])
        second = reloaded.save('Updated note', '# Updated\n\n- [x] Read', document_id=first['id'])
        self.assertEqual(first['id'], second['id'])
        self.assertEqual(2, second['revision'])
        self.assertEqual(['research'], second['tags'])
        self.assertNotEqual(first['markdown_path'], second['markdown_path'])
        self.assertTrue(os.path.isfile(first['markdown_path']))
        self.assertEqual(1, reloaded.list()['total'])
        self.assertEqual('Updated note', reloaded.read(first['id'])['title'])

    def test_map_parentage_and_node_count(self):
        tree, count = parse_outline('Root', '# Root\n\n- A\n  - A1\n    - A2\n- B\n  - B1')
        self.assertEqual(6, count)
        self.assertEqual(['A', 'B'], [node['label'] for node in tree['children']])
        self.assertEqual('A2', tree['children'][0]['children'][0]['children'][0]['label'])
        saved = self.library.save('Root', '- A\n  - A1\n- B', kind='mind_map')
        self.assertEqual('mind_map', self.library.read(saved['id'])['kind'])
        indented, count = parse_outline('Root', '# Root\n  - A\n    - A1\n  - B')
        self.assertEqual(4, count)
        self.assertEqual('A1', indented['children'][0]['children'][0]['label'])

    def test_paginated_reads_reconstruct_exact_document_and_identify_changes(self):
        saved = self.library.save('Long note', '# Note\n' + '\u017c\u00f3\u0142\u0107 \n' * 5000)
        complete = self.library.read(saved['id'])['markdown']
        offset = 0
        pages = []
        digest = None
        while True:
            page = self.library.read(saved['id'], offset, 4000)
            self.assertEqual(offset, page['offset'])
            self.assertEqual(len(complete), page['total_chars'])
            self.assertLessEqual(len(page['markdown']), 4000)
            digest = digest or page['content_sha256']
            self.assertEqual(digest, page['content_sha256'])
            pages.append(page['markdown'])
            if not page['more']:
                self.assertIsNone(page['next_offset'])
                break
            self.assertGreater(page['next_offset'], offset)
            offset = page['next_offset']
        self.assertEqual(complete, ''.join(pages))
        self.assertEqual('', self.library.read(saved['id'], len(complete) + 10, 4000)['markdown'])
        self.assertEqual(12000, len(self.library.read(saved['id'], -100, 999999)['markdown']))
        with open(saved['markdown_path'], 'wb') as handle:
            handle.write(b'# Edited externally\n')
        self.assertNotEqual(digest, self.library.read(saved['id'], 0, 4000)['content_sha256'])

    def test_heading_supplies_title_when_model_omits_separate_argument(self):
        saved = self.library.save('', '# Picnic notes\n\n## Plan\n- A short checklist')
        self.assertEqual('Picnic notes', saved['title'])
        with self.assertRaises(ValueError): self.library.save('', 'No heading or title')

    def test_invalid_outline_cannot_replace_working_document(self):
        saved = self.library.save('Map', '- A\n  - B', kind='mind_map')
        for bad in ['Text without bullets', '    - Code block', '- A\n   - Odd indent', '- A\n    - Skip', '# Only a title', '- ' + 'x' * 181]:
            with self.assertRaises(ValueError):
                self.library.save('Map', bad, kind='mind_map', document_id=saved['id'])
        self.assertEqual(1, self.library.read(saved['id'])['revision'])
        with self.assertRaises(ValueError): parse_outline('Root', '\n'.join('- node' for _ in range(250)))
        with self.assertRaises(ValueError): parse_outline('Root', '\n'.join('  ' * i + '- node' for i in range(11)))

    def test_html_contains_inert_data_and_exact_script_hashes(self):
        hostile = '</script><script>alert("bad")</script>\n\n[bad](javascript:alert(1))\n<img src="https://example.test/pixel" onerror="alert(2)">'
        saved = self.library.save('<Unsafe & title>', hostile)
        with open(saved['viewer_path'], 'rb') as handle: html = handle.read().decode('utf-8')
        self.assertIn('&lt;Unsafe &amp; title&gt;', html)
        payload = re.search(r'<script id="document-data" type="application/json">(.*?)</script>', html, re.S).group(1)
        self.assertNotIn('<', payload)
        self.assertEqual(hostile + '\n', json.loads(payload)['markdown'])
        scripts = re.findall(r'<script>(.*?)</script>', html, re.S)
        self.assertEqual(2, len(scripts))
        for script in scripts:
            digest = base64.b64encode(hashlib.sha256(script.encode('utf-8')).digest()).decode('ascii')
            self.assertIn('sha256-' + digest, html)
        self.assertIn("connect-src 'none'", html)
        self.assertNotRegex(html, r'<script[^>]+src=') if hasattr(self, 'assertNotRegex') else self.assertFalse(re.search(r'<script[^>]+src=', html))

    def test_paths_ids_and_limits(self):
        saved = self.library.save('../../title', '# Safe file')
        self.assertEqual(os.path.realpath(self.root), os.path.realpath(os.path.dirname(saved['markdown_path'])))
        for identifier in ['../../secret', 'catalog.json', 'doc-0000000000000000']:
            with self.assertRaises(ValueError): self.library.read(identifier)
        with self.assertRaises(ValueError): self.library.save('large', 'x' * (MAX_MARKDOWN_BYTES + 1))
        with self.assertRaises(ValueError): self.library.save('bad', 'body', tags=['x' * 41])
        with self.assertRaises(ValueError): self.library.save('bad', 'body', document_id='../bad')

    def test_filter_pagination_and_external_markdown_edits(self):
        first = self.library.save('Alpha', '# Old', tags=['focus'])
        self.library.save('Beta', '# Other')
        self.assertEqual(1, self.library.list('focus')['total'])
        page = self.library.list(limit=1)
        self.assertTrue(page['more'])
        self.assertEqual(1, len(self.library.list(limit=1, offset=page['next_offset'])['documents']))
        with open(first['markdown_path'], 'wb') as handle: handle.write('# Edited outside Burp'.encode('utf-8'))
        path = self.library.preview(first['id'])
        with open(path, 'rb') as handle: html = handle.read().decode('utf-8')
        self.assertIn('# Edited outside Burp', html)

    def test_corrupt_catalog_and_missing_assets_preserve_previous_revision(self):
        saved = self.library.save('Keep me', '# Original')
        bad_assets = DocumentLibrary(self.root, assets=os.path.join(self.root, 'missing-assets'))
        with self.assertRaises(IOError): bad_assets.save('Changed', '# New', document_id=saved['id'])
        self.assertEqual(1, self.library.read(saved['id'])['revision'])
        catalog = os.path.join(self.root, 'catalog.json')
        with open(catalog, 'wb') as handle: handle.write(b'broken')
        with self.assertRaises(ValueError): self.library.save('New', '# New')
        self.assertTrue(os.path.isfile(saved['markdown_path']))
        with open(catalog, 'rb') as handle: self.assertEqual(b'broken', handle.read())


if __name__ == '__main__':
    unittest.main()

from __future__ import unicode_literals
import copy
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_burpai_website_integration import extension_namespace, load_function


class ContextBudgetTests(unittest.TestCase):
    def setUp(self):
        namespace = extension_namespace()
        namespace.update(json=json, _json_text=json.dumps, _memory_terms=lambda value: [])
        methods = dict((name, load_function(name, namespace, 'ContextEngine'))
                       for name in ('estimate', '_transactions', 'prepare', '_archived_tool_reference',
                                    '_focused_tool_group'))
        engine = type('Engine', (object,), methods)()
        engine.chars_per_token = 2.8
        engine._js_index = lambda: ''
        engine.ledger = type('Ledger', (object,), {
            'context': lambda self: 'Current mission', 'data': {'goals': ['Inspect source']}})()
        engine.vault = type('Vault', (object,), {
            'search': lambda self, *args, **kw: {'matches': []},
            'overview': lambda self, **kw: {'total_records': 2}})()
        self.engine = engine

    def test_large_recent_results_keep_calls_and_evidence_references(self):
        engine = self.engine
        messages = [{'role': 'user', 'content': 'Inspect source'},
                    {'role': 'assistant', 'tool_calls': [
                        {'id': 'call-1', 'function': {'name': 'website_search_js', 'arguments': '{}'}},
                        {'id': 'call-2', 'function': {'name': 'website_read_lines', 'arguments': '{}'}}]},
                    {'role': 'tool', 'tool_call_id': 'call-1',
                     'content': 'SEARCH RESULT ' + 'x' * 30000 + '\n[Original archived as E:1. Exact retrieval: memory_read.]'},
                    {'role': 'tool', 'tool_call_id': 'call-2',
                     'content': 'SOURCE RESULT ' + 'y' * 30000 + '\n[Original archived as E:2. Exact retrieval: memory_read.]'}]
        original = copy.deepcopy(messages)
        conversation = type('Conversation', (object,), {'get_messages': lambda self: messages})()
        result = engine.prepare('Policy', conversation, [], max_tokens=1000,
                                model_window=6000, requested_working=6000)
        self.assertEqual(['user', 'assistant', 'tool', 'tool'], [m['role'] for m in result[1:]])
        self.assertEqual(['call-1', 'call-2'], [m['tool_call_id'] for m in result if m['role'] == 'tool'])
        self.assertIn('SEARCH RESULT', result[-2]['content'])
        self.assertIn('E:1', result[-2]['content'])
        self.assertIn('E:2', result[-1]['content'])
        self.assertLessEqual(engine.last_report['estimated_prompt_tokens'], engine.last_report['prompt_ceiling'])
        self.assertEqual(original, messages)

    def test_new_turn_references_saved_report_and_memory_page_without_rewriting_user(self):
        engine = self.engine
        doc_id = 'doc-0123456789abcdef'
        markdown = '# Saved report\n' + 'Detailed evidence\n' * 200
        messages = [
            {'role': 'user', 'content': 'Review this source and save a note.'},
            {'role': 'assistant', 'tool_calls': [{'id': 'read-1', 'function': {
                'name': 'memory_read', 'arguments': '{"id":"EV0000001"}'}}]},
            {'role': 'tool', 'name': 'memory_read', 'tool_call_id': 'read-1',
             'content': json.dumps({'ok': True, 'id': 'EV0000001', 'offset': 0,
                                    'text': 'LONG_ORIGINAL_SOURCE' * 200})},
            {'role': 'assistant', 'tool_calls': [{'id': 'save-1', 'function': {
                'name': 'document_save', 'arguments': json.dumps({'kind': 'note', 'markdown': markdown})}}]},
            {'role': 'tool', 'name': 'document_save', 'tool_call_id': 'save-1',
             'content': json.dumps({'ok': True, 'id': doc_id, 'revision': 1}) +
                        '\n[Original archived as EV0000002. Exact retrieval: memory_read.]'},
            {'role': 'user', 'content': 'Read all the notes collected so far and test them yourself'},
        ]
        original = copy.deepcopy(messages)
        conversation = type('Conversation', (object,), {'get_messages': lambda self: messages})()
        normal = engine.prepare('Policy', conversation, [])
        focused = engine.prepare('Policy', conversation, [], focused=True)
        self.assertEqual(original[-1], focused[-1])
        self.assertNotIn('LONG_ORIGINAL_SOURCE', json.dumps(focused))
        self.assertNotIn('Detailed evidence', json.dumps(focused))
        args = json.loads(focused[4]['tool_calls'][0]['function']['arguments'])
        self.assertIn(doc_id, args['markdown'])
        self.assertIn('document_read', args['markdown'])
        self.assertEqual(messages[4], focused[5])
        self.assertLess(engine.estimate(focused), engine.estimate(normal))
        self.assertEqual(original, messages)
        # A failed write must retain the content so it can be recovered/retried.
        messages[4]['content'] = '{"ok":false,"error":"write failed"}'
        failed = engine.prepare('Policy', conversation, [], focused=True)
        self.assertEqual(markdown, json.loads(failed[4]['tool_calls'][0]['function']['arguments'])['markdown'])

    def test_document_page_projection_preserves_continuation_and_exact_text(self):
        namespace = extension_namespace()
        namespace['_json_text'] = json.dumps
        project = load_function('tool_projection', namespace, 'EvidenceVault')
        page = {'ok': True, 'id': 'doc-0123456789abcdef', 'markdown': '\u017c' * 4000,
                'offset': 0, 'more': True, 'next_offset': 4000, 'total_chars': 8000}
        projected = project(None, {'tool': 'document_read', 'id': 'EV0000003'}, page)
        self.assertEqual(page, json.loads(projected.partition('\n[Original archived as ')[0]))
        self.assertIn('EV0000003', projected)

    def test_focused_context_keeps_recent_results_and_references_older_evidence(self):
        engine = self.engine
        engine.vault.search = lambda *args, **kwargs: {
            'matches': [{'summary': 'Archived source [EV0000001]', 'id': 'EV0000001'}]}
        engine.vault.read = lambda *args: {'ok': True, 'text': 'AUTOMATIC_EXCERPT'}
        messages = [{'role': 'user', 'content': 'Inspect source'}]
        for i in range(1, 5):
            call_id = 'call-{}'.format(i)
            content = ('BODY_{} '.format(i) + 'x' * 1600)
            if i != 2:
                content += '\n[Original archived as EV{:07d}. Exact retrieval: memory_read.]'.format(i)
            messages.extend([
                {'role': 'assistant', 'tool_calls': [
                    {'id': call_id, 'function': {'name': 'website_read_lines', 'arguments': '{}'}}]},
                {'role': 'tool', 'tool_call_id': call_id, 'content': content},
            ])
        original = copy.deepcopy(messages)
        conversation = type('Conversation', (object,), {'get_messages': lambda self: messages})()
        normal = engine.prepare('Policy', conversation, [])
        focused = engine.prepare('Policy', conversation, [], focused=True)
        self.assertIn('AUTOMATIC_EXCERPT', normal[0]['content'])
        self.assertNotIn('AUTOMATIC_EXCERPT', focused[0]['content'])
        self.assertIn('EV0000001', focused[0]['content'])
        results = [m for m in focused if m['role'] == 'tool']
        self.assertEqual(['call-1', 'call-2', 'call-3', 'call-4'],
                         [m['tool_call_id'] for m in results])
        self.assertIn('EV0000001', results[0]['content'])
        self.assertNotIn('BODY_1', results[0]['content'])
        self.assertEqual([original[4], original[6], original[8]], results[1:])
        self.assertLess(engine.estimate(focused), engine.estimate(normal))
        self.assertEqual(original, messages)


if __name__ == '__main__':
    unittest.main()

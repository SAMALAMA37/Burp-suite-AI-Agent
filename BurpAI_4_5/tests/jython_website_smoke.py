# -*- coding: utf-8 -*-
"""Load the full extension and construct its actual Swing UI under Jython.

No Burp server, external network, API key or user settings are used.
Run: java -Djava.awt.headless=true -Dpython.cachedir.skip=true -jar
     jython-standalone-2.7.4.jar tests/jython_website_smoke.py
"""
import os
import shutil
import sys
import tempfile
import types

if not sys.platform.startswith('java'):
    raise SystemExit('This smoke test requires Jython.')

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
fake_burp = types.ModuleType('burp')
fake_burp.IBurpExtender = type('IBurpExtender', (object,), {})
fake_burp.ITab = type('ITab', (object,), {})
fake_burp.IExtensionStateListener = type('IExtensionStateListener', (object,), {})
sys.modules['burp'] = fake_burp

from java.io import ByteArrayOutputStream
from java.lang import Runnable
from javax.swing import SwingUtilities, JButton, JLabel
from java.awt import Dimension, RenderingHints
from java.awt.image import BufferedImage
from javax.imageio import ImageIO
from java.io import File
from javax.swing.text import StyleConstants


class Callbacks(object):
    def __init__(self):
        self.out, self.err = ByteArrayOutputStream(), ByteArrayOutputStream()
        self.tabs = []
    def getStdout(self): return self.out
    def getStderr(self): return self.err
    def getHelpers(self): return object()
    def getExtensionFilename(self): return extension_path
    def setExtensionName(self, name): self.name = name
    def addSuiteTab(self, tab): self.tabs.append(tab)
    def registerExtensionStateListener(self, listener): self.listener = listener
    def getProxyHistory(self): return []
    def getSiteMap(self, url): return []
    def isInScope(self, url): return url.getHost() == 'example.test'
    def makeHttpRequest(self, *args): raise AssertionError('Unexpected network call')


temporary = tempfile.mkdtemp(prefix='burpai-jython-smoke-', dir=os.path.dirname(__file__))
temporary = os.path.realpath(temporary)
original_expanduser = os.path.expanduser
os.path.expanduser = lambda path: temporary if path == '~' else original_expanduser(path)

try:
    extension_path = os.environ.get('BURPAI_TEST_EXTENSION', os.path.join(ROOT, 'BurpAI_v4_Extension.py'))
    if '--burp-loader' in sys.argv:
        from org.python.util import PythonInterpreter
        extension = types.ModuleType('burpai_burp_loader_test')
        # Exercise the actual Java execfile API from the reported stack trace.
        interpreter = PythonInterpreter(extension.__dict__)
        interpreter.execfile(extension_path)
        assert '__file__' not in extension.__dict__
    else:
        import BurpAI_v4_Extension as extension
        assert extension._WEBSITE_IMPORT_ERROR is None, extension._WEBSITE_IMPORT_ERROR
    callbacks = Callbacks()
    extender = extension.BurpExtender()
    failure = []

    class Build(Runnable):
        def run(self):
            try:
                extender.registerExtenderCallbacks(callbacks)
            except Exception as error:
                failure.append(error)

    SwingUtilities.invokeAndWait(Build())
    if failure: raise failure[0]
    assert extension._WEBSITE_IMPORT_ERROR is None, extension._WEBSITE_IMPORT_ERROR
    assert len(callbacks.tabs) == 1
    def assert_native_labels(component):
        if isinstance(component, JLabel):
            value = unicode(component.getText() or '')
            assert '<html>' not in value.lower(), 'HTML markup in native label: ' + value
            component.putClientProperty('html.disable', True)
        if hasattr(component, 'getComponents'):
            for child in component.getComponents(): assert_native_labels(child)
    assert_native_labels(extender.ui.root)
    names = set(extender.tool_registry.names())
    assert set(('website_collect_js', 'website_search_js', 'website_read_js',
                'website_list_js', 'website_index_js', 'website_read_lines',
                'website_outline', 'website_related_files', 'website_find_references',
                'burp_find_traffic', 'burp_open_repeater', 'burp_workspace_context',
                'website_mind_map', 'website_save_note')).issubset(names)
    assert 'website_build_file_map' not in names
    assert not hasattr(extender.store,'get_js_helper_config')
    assert not hasattr(extender.ui,'website_helper_model')
    assert extender.ui.fallback_cb.isSelected()
    class CheckEmbeddingPresets(Runnable):
        def run(self):
            extender.ui.website_embedding_preset.setSelectedIndex(1)
            assert extender.ui.website_embed_url.getText() == 'https://openrouter.ai/api/v1'
            assert extender.ui.website_embed_model.getText() == 'nvidia/nemotron-3.5-embed-8b:free'
            assert len(extender.ui.website_embed_key.getPassword()) == 0
            extender.ui.website_embedding_preset.setSelectedIndex(0)
            assert extender.ui.website_embed_url.getText() == 'http://127.0.0.1:11434'
            assert extender.ui.website_embed_model.getText() == 'embeddinggemma'
    SwingUtilities.invokeAndWait(CheckEmbeddingPresets())
    # Exercise real persistent note tools and the actual Swing tree renderer.
    note = extender._tool_website_save_note({'url':'https://example.test/',
        'title':'Follow-up','text':'Inspect session refresh next.','kind':'todo'})
    assert note['ok'], note
    mind_map = extender._tool_website_mind_map({'url':'https://example.test/'})
    assert mind_map['notes'][0]['id'] == note['note']['id']
    class ShowMindMap(Runnable):
        def run(self):
            extender._website_present('mind_map',{'url':'https://example.test/'},mind_map,'')
    SwingUtilities.invokeAndWait(ShowMindMap())
    assert extender.ui.website_mind_tree.getModel().getRoot().getChildCount() == 1
    titles = [str(extender.ui.tabs.getTitleAt(i)).strip()
              for i in range(extender.ui.tabs.getTabCount())]
    assert 'Website Analyse' in titles, titles
    assert 'Notes & maps' in titles, titles
    assert set(('document_save','documents_list','document_read','document_open')).issubset(names)
    note_text = '# Project notes\n\n## Next steps\n- [ ] Review the plan' + '\nSupporting observation.' * 350
    saved_document = extender.tool_registry.execute('document_save', {
        'title':'Project notes', 'kind':'note', 'markdown':note_text})
    assert saved_document['ok'] and saved_document['result']['ok'], saved_document
    saved_map = extender.tool_registry.execute('document_save', {
        'title':'Project map', 'kind':'mind_map', 'markdown':'- Research\n  - Questions\n- Delivery\n  - Review'})
    assert saved_map['ok'] and saved_map['result']['ok'], saved_map
    document_id = saved_document['result']['id']
    loaded_document = extender.tool_registry.execute('document_read', {'document_id':document_id})
    assert 'Next steps' in loaded_document['result']['markdown'], loaded_document
    page = loaded_document['result']
    assert len(page['markdown']) == 4000 and page['more'], page
    document_parts = [page['markdown']]
    while page['more']:
        page = extender.tool_registry.execute('document_read', {
            'document_id':document_id, 'offset':page['next_offset']})['result']
        document_parts.append(page['markdown'])
    assert ''.join(document_parts) == note_text + '\n'
    assert extender.documents.read(document_id)['markdown'] == note_text + '\n'
    assert extender.tool_registry.execute('documents_list', {})['result']['total'] == 2
    document_opens = []
    original_document_open = extender._document_open
    extender._document_open = lambda identifier, markdown=False: document_opens.append((identifier, markdown)) or {'ok':True}
    class CheckDocuments(Runnable):
        def run(self):
            extender.ui.refresh_documents(document_id)
            assert extender.ui.document_table.getRowCount() == 2
            assert 'Next steps' in extender.ui.document_source.getText()
            extender.ui.document_buttons['Open preview'].doClick(0)
            extender.ui.document_buttons['Open .md'].doClick(0)
            extender.ui.document_buttons['Ask for a map'].doClick(0)
            assert 'visual mind map' in extender.ui.input_field.getText()
            assert extender.ui.tabs.getSelectedIndex() == 0
    SwingUtilities.invokeAndWait(CheckDocuments())
    assert document_opens == [(document_id,False),(document_id,True)], document_opens
    extender._document_open = original_document_open
    # Starter prompts fill the composer without sending; Enter sends once.
    sent = []
    original_send = extender._send_chat
    extender._send_chat = lambda: sent.append(unicode(extender.ui.input_field.getText()))
    class CheckComposer(Runnable):
        def run(self):
            from javax.swing import KeyStroke
            for starter in extender.ui.agent_starter_buttons:
                starter.doClick(0)
                assert extender.ui.input_field.getText()
            assert sent == []
            extender.ui.input_field.setText('First line\nSecond line')
            extender.ui.input_field.getActionMap().get('burpai-send').actionPerformed(None)
            assert sent == ['First line\nSecond line']
            assert extender.ui.input_field.getInputMap().get(KeyStroke.getKeyStroke('shift ENTER')) == 'insert-break'
            extender.ui.agent_workbench_button.doClick(0)
            assert extender.ui.tabs.getSelectedIndex() == titles.index('Website Analyse')
            extender.ui.input_field.setText('')
    SwingUtilities.invokeAndWait(CheckComposer())
    extender._send_chat = original_send
    assert extender.ui.website_embed_model.getText() == 'embeddinggemma'
    assert str(extender.ui.website_root.getText()).startswith(temporary)
    actions = []
    original_run = extender._website_ui_run
    extender._website_ui_run = lambda action: actions.append(action)
    opened = []
    extender._website_open_selected = lambda: opened.append('selected')
    extender._website_nav_history = lambda direction: opened.append(direction)
    extender._website_repeater_selected = lambda: opened.append('repeater')
    extender._website_continue_source = lambda: opened.append('continue')
    extender._website_next_results = lambda: opened.append('more')
    website_panel = extender.ui.tabs.getComponentAt(titles.index('Website Analyse'))
    class ClickActions(Runnable):
        def run(self):
            def walk(component):
                if isinstance(component, JButton) and str(component.getText()) in (
                        'Collect JS + Index', 'Index Files', 'List Files',
                        'Save Settings', 'Search Files', 'Read Source', 'Read Lines',
                        'Outline', 'Related Files', 'Find References', 'Open Selected',
                        'Back', 'Forward', 'Workspace', 'Traffic', 'Copy to Repeater', 'Continue', 'More Results'):
                    component.doClick(0)
                if hasattr(component, 'getComponents'):
                    for child in component.getComponents(): walk(child)
            walk(website_panel)
            extender.ui.website_query.postActionEvent()
    SwingUtilities.invokeAndWait(ClickActions())
    for action in ('collect', 'index', 'files', 'settings', 'search', 'read',
                   'read_lines', 'outline', 'related', 'references', 'workspace', 'traffic'):
        assert action in actions, (action, actions)
    assert actions.count('search') == 2, actions
    assert sorted(map(str, opened)) == ['-1', '1', 'continue', 'more', 'repeater', 'selected'], opened
    assert not extender.ui.website_results.isCellEditable(0, 0)
    assert not extender.ui.website_source.isEditable()
    extender._website_ui_run = original_run
    if '--render' in sys.argv:
        class Render(Runnable):
            def run(self):
                ui = extender.ui
                ui.website_url.setText('https://demo.example.test')
                ui.website_query.setText('Where is the sign-in session refreshed?')
                ui.website_status.setText('SEMANTIC SEARCH  /  32 files indexed  /  6 source matches')
                site = 'https://demo.example.test'
                rows = [{'file_id': name, 'path': name, 'url': site + '/assets/' + name,
                         'start_line': line, 'end_line': line + 100, 'offset': 900}
                        for name, line in (('session.js', 50), ('auth-client.js', 28), ('api.js', 12), ('storage.js', 83))]
                extender._website_present('search', {'url': site}, {'ok': True, 'mode': 'semantic_hybrid', 'results': rows}, 'Four source matches.')
                ui.website_results.setRowSelectionInterval(0, 0)
                ui.website_start_line.setText('50'); ui.website_end_line.setText('150')
                ui.website_source_title.setText('session.js  /  lines 50-150  /  original source')
                demo_lines = [
                    '  50 | export async function refreshSession(client) {',
                    '  51 |   const session = loadSession();',
                    '  52 |   if (!session || session.expiresAt > Date.now()) {',
                    '  53 |     return session;',
                    '  54 |   }',
                    '  55 |',
                    '  56 |   const response = await client.post("/session/refresh", {',
                    '  57 |     credentials: "include",',
                    '  58 |   });',
                    '  59 |   const nextSession = await response.json();',
                    '  60 |   saveSession(nextSession);',
                    '  61 |   return nextSession;',
                    '  62 | }', '',
                    '  64 | // Follow imports with Related, then locate callers',
                    '  65 | // with Find References. Source is never executed.']
                demo_source = '\n'.join(line.split('|', 1)[1][1:] if '|' in line else line for line in demo_lines)
                extender._website_present('read_lines', {'url': site, 'file_id': 'session.js', 'start_line': 50, 'end_line': 150},
                    {'ok': True, 'path': 'session.js', 'content': demo_source, 'line_start': 50, 'line_end': 65,
                     'offset': 900, 'next_offset': None}, 'Original source range.')
                doc = ui.website_source.getStyledDocument()
                colors = set(StyleConstants.getForeground(doc.getCharacterElement(i).getAttributes()).getRGB()
                             for i in range(doc.getLength()))
                assert len(colors) >= 3, 'Source syntax colors were not applied.'
                # JScrollPane normally attaches the table header on addNotify;
                # explicitly attach it for this headless rendering.
                ui.website_results.getParent().getParent().setColumnHeaderView(ui.website_results.getTableHeader())
                ui.website_workspace_tabs.setSelectedIndex(0)
                ui.website_reader_tabs.setSelectedIndex(0)
                ui.tabs.setSelectedIndex(titles.index('Website Analyse'))
                if '--agent' in sys.argv:
                    ui.tabs.setSelectedIndex(titles.index('Agent'))
                    ui.renderer.clear()
                    ui.renderer.add('user', 'Trace how the session refreshes and show me the relevant source lines.', '14:32:08')
                    ui.renderer.add('assistant', 'I found the refresh flow in `session.js`. It reads the current session, checks its expiry, and calls `/session/refresh`.\n\nThe next step is to read lines 50-150 and follow the imported authentication client.', '14:32:10')
                    ui.renderer.add('tool', 'website_read_lines  /  session.js  /  lines 50-150\nOriginal source retrieved. Follow-up: auth-client.js.', '14:32:11')
                    ui.chat_view.setText(ui.renderer.to_html())
                    ui.input_field.setText('Follow the authentication client and compare it with captured traffic.')
                    ui.set_status('ready', model='Local model', iter_str='3/12')
                if '--documents' in sys.argv:
                    ui.tabs.setSelectedIndex(titles.index('Notes & maps'))
                    ui.refresh_documents(document_id)
                    ui.document_table.getParent().getParent().setColumnHeaderView(ui.document_table.getTableHeader())
                root = ui.root
                width, height = (1300, 900) if '--compact' in sys.argv else (1500, 960)
                root.setSize(Dimension(width, height))
                def layout(component):
                    component.doLayout()
                    if hasattr(component, 'getComponents'):
                        for child in component.getComponents(): layout(child)
                layout(root)
                image = BufferedImage(width, height, BufferedImage.TYPE_INT_RGB)
                graphics = image.createGraphics()
                graphics.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON)
                graphics.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON)
                root.printAll(graphics); graphics.dispose()
                folder = os.path.join(ROOT, 'artifacts')
                if not os.path.isdir(folder): os.makedirs(folder)
                filename = 'burpai_v45_ui_compact.png' if '--compact' in sys.argv else 'burpai_v45_ui.png'
                if '--agent' in sys.argv: filename = 'burpai_v45_agent.png'
                if '--documents' in sys.argv: filename = 'burpai_v45_documents.png'
                ImageIO.write(image, 'png', File(os.path.join(folder, filename)))
        SwingUtilities.invokeAndWait(Render())
    extender.extensionUnloaded()
    print('PASS: full extension import, navigation tools, Swing workbench and button/Enter action wiring on Jython 2.7.')
finally:
    os.path.expanduser = original_expanduser
    # Only delete the newly created, verified test directory.
    tests_root = os.path.realpath(os.path.dirname(__file__))
    if os.path.dirname(temporary) == tests_root and os.path.basename(temporary).startswith('burpai-jython-smoke-'):
        shutil.rmtree(temporary)

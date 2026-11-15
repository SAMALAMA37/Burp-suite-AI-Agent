# -*- coding: utf-8 -*-
"""Exercise actual Swing classes without importing unrelated network adapters."""
from __future__ import unicode_literals
import ast
import io
import os
import sys
import threading
import time
import json
import re
import textwrap

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from BurpAI_v4_Investigation import Investigation, compare_http, plan_metadata
from BurpAI_v4_Lab import LabEngine, observe, discover, origin, digest
import BurpAI_v4_LocalTools as LocalTools
import BurpAI_v4_WSL as WSLTools
from java.lang import Runnable
from java.awt.image import BufferedImage
from javax.imageio import ImageIO
from java.io import File

with io.open(os.path.join(ROOT, 'BurpAI_v4_Extension.py'), encoding='utf-8') as handle:
    source = handle.read()
lines = source.splitlines(True)
tree = ast.parse(source.encode('utf-8'))
namespace = globals()
namespace.update(_text_type=unicode, _string_types=basestring)
eval(compile(source[source.index('from javax.swing import'):source.index('import os, sys')], '<ui imports>', 'exec'), namespace)
for i, node in enumerate(tree.body):
    if getattr(node, 'name', '') in ('_safe_text','_bounded_int','SettingsStore','Theme','HtmlRenderer','BurpUi'):
        end = tree.body[i+1].lineno - 1 if i+1 < len(tree.body) else len(lines)
        eval(compile(''.join(lines[node.lineno-1:end]).encode('utf-8'), '<actual Swing classes>', 'exec'), namespace)
container=next(n for n in tree.body if getattr(n,'name','')=='BurpExtender')
for i,node in enumerate(container.body):
    if getattr(node,'name','') in ('_lab_card','_lab_card_action','_tool_local_catalog',
                                   '_tool_local_fixture_info','_tool_local_fixture_draft'):
        end=container.body[i+1].lineno-1
        eval(compile(textwrap.dedent(''.join(lines[node.lineno-1:end])).encode('utf-8'),'<actual card handler>','exec'),namespace)


class Ledger(object):
    def __init__(self): self.data, self.lock = {'mission_id':'fixture'}, threading.RLock()
    def _persist(self): pass


class Extender(object):
    def __init__(self):
        self.agent_running, self.stop_agent_flag, self._pause_requested = True, False, False
        self._chat_worker_active = True
        class Store(SettingsStore):
            def __init__(self):
                self.data={'provider':'local','website_last_url':'https://example.test'}
            def _save(self): pass
            def get_active_api_key(self): return ''
        self.store = Store()
        self._v3_jobs_running=False; self.kill_switch=False
        class Stub(object): pass
        self.client=Stub(); self.js_kb=Stub(); self.documents=Stub()
        self.js_kb.to_pretty_text=lambda:'No saved JavaScript yet.'
        self.documents.list=lambda *args,**kwargs:{'documents':[],'total':0,'more':False,'library_path':'Fixture notes'}
        self.actions = []
        self.investigation = Investigation(Ledger())
        self.investigation.start(5)
        self.lab=LabEngine(self.investigation.ledger)
        self.wsl_bridge=WSLTools.WSLBridge(transport=lambda distro,user,request,stopped:
            {'ok':True,'sandbox':'bubblewrap','host_workspace':'/home/test/.burpai-wsl/workspace'})
    def _safe_ui(self, fn): fn()
    def _log_debug(self, message): raise AssertionError(message)
    def _toggle_agent_pause(self):
        self.actions.append('pause'); self._pause_requested = not self._pause_requested
        self.ui.set_status('paused' if self._pause_requested else 'running')
    def _summarize_agent(self): self.actions.append('summary')
    def _save_investigation_report(self): self.actions.append('save')
    def _refresh_investigation(self): self.ui.refresh_investigation(self.investigation.snapshot())
    def _lab_card(self,identifier): return _lab_card(self,identifier)
    def _lab_card_action(self,link): return _lab_card_action(self,link)
    def _send_chat(self,prompt=None,**kwargs): self.actions.append(('prompt',prompt,kwargs))
    def _append_chat(self,*args): self.actions.append(args)
    def __getattr__(self, name): return lambda:self.actions.append(name)


failures = []
class Check(Runnable):
    def run(self):
        try:
            extender = Extender()
            ui = BurpUi(extender)
            extender.ui = ui
            lab_index=ui.tabs.indexOfTab('  Testing lab  ')
            investigation_index=ui.tabs.indexOfTab('  Investigation  ')
            assert len(ui.nav_buttons)==17
            local_index=ui.tabs.indexOfTab('  Local Tools  ')
            ui.nav_buttons[local_index].doClick(0)
            assert ui.tabs.getSelectedIndex()==local_index
            assert ui.local_tabs.getTitleAt(0)=='WSL terminal'
            assert not ui.terminal_run.isEnabled() and ui.terminal_network.isSelected()
            original_output = ui.terminal_output.getText()
            ui._terminal_connect()
            assert 'select a WSL distribution' in ui.terminal_status.getText()
            assert original_output == ui.terminal_output.getText()
            ui._terminal_present('failed probe', {'ok':False,'sandbox':'bubblewrap','error':'fixture failure'})
            assert 'Sandbox ready.' not in ui.terminal_output.getText()[len(original_output):]
            assert extender.wsl_bridge.connect('Fixture distro')['ok']
            ui._terminal_present('printf hello', {'ok':True,'exit_code':0,'stdout':'hello','duration_ms':20})
            assert 'hello' in ui.terminal_output.getText() and 'exit 0' in ui.terminal_status.getText()
            ui.input_field.setText('Preserve this draft.')
            ui._terminal_ask()
            assert ui.input_field.getText().startswith('Preserve this draft.\n\nUse the connected WSL')
            ui._terminal_disconnect()
            assert not extender.wsl_bridge.status()['connected']
            ui.tabs.setSelectedIndex(local_index)
            assert not ui.local_run.isEnabled()
            ui.local_catalog=('Fixture distro', ('awk', 'grep', 'sed'))
            ui.wsl_filter.setText('gr')
            assert ui.wsl_results.getText()=='grep'
            assert _tool_local_catalog(extender, {'query':'gr'})['names']==['grep']
            metadata=ui.local_workspace.load(b'{"status":200,"ok":true}')
            assert _tool_local_fixture_info(extender,{})['fixture_id']==metadata['fixture_id']
            checks=[{'path':'/status','op':'equals','expected':200}, {'path':'/ok','op':'type_is','expected':'number'}]
            draft=_tool_local_fixture_draft(extender, {'fixture_id':metadata['fixture_id'],'checks':checks})
            assert draft['ok'] and ui.local_use_draft.isEnabled() and ui.local_report is None
            ui.local_plan.setText('')
            ui.local_use_draft.doClick(0)
            ui.local_run.setEnabled(True)
            ui.local_run.doClick(0)
            assert '1 of 2 checks passed' in ui.local_output.getText() and ui.local_export.isEnabled()
            assert 'fixture_id' in ui.local_report
            ui._clear_local_fixture()
            assert not ui.local_export.isEnabled() and ui.local_workspace.info() is None
            ui.nav_buttons[lab_index].doClick(0)
            assert ui.tabs.getSelectedIndex()==lab_index
            assert ui.nav_buttons[lab_index].getForeground()==Theme.BLUE
            closed=[]; ui._command_panel(lambda:closed.append(True))
            ui.command_search.setText('traffic')
            assert ui.command_results.getModel().getElementAt(0)=='HTTP History'
            ui.command_search.getActionMap().get('open').actionPerformed(None)
            assert closed and ui.tabs.getSelectedIndex()==8
            ui.command_search.setText('no-such-page')
            before=ui.tabs.getSelectedIndex()
            ui.command_search.getActionMap().get('open').actionPerformed(None)
            assert ui.tabs.getSelectedIndex()==before
            ui._focus_composer(); assert ui.tabs.getSelectedIndex()==0
            ui.input_field.setText('A draft worth keeping.')
            ui.agent_starter_buttons[1].doClick(0)
            assert ui.input_field.getText().startswith('A draft worth keeping.\n\nSearch')
            ui.input_field.getActionMap().get('burpai-undo').actionPerformed(None)
            assert ui.input_field.getText()=='A draft worth keeping.'
            ui.input_field.getActionMap().get('burpai-redo').actionPerformed(None)
            assert 'Search the saved' in ui.input_field.getText()
            ui.input_field.setText(''); assert not ui.agent_send_button.isEnabled()
            before=len(extender.actions); ui.input_field.getActionMap().get('burpai-send').actionPerformed(None)
            assert len(extender.actions)==before
            extender.actions=[]
            ui.set_status('running')
            ui.agent_pause_button.doClick(0)
            assert ui.agent_pause_button.getText() == 'Resume'
            ui.agent_pause_button.doClick(0)
            assert ui.agent_pause_button.getText() == 'Pause'
            ui.agent_summary_button.doClick(0)
            ui.investigation_buttons['Save checkpoint'].doClick(0)
            assert extender.actions == ['pause','pause','summary','save'], extender.actions
            tests = [{'id':'T-fixture','title':'Check object access across two captured roles',
                'hypothesis':'The response may differ by role','status':'testing','priority':1,
                'target':'https://example.test','category':'Authorization','evidence_ids':['EV0000001'],
                'baseline':'Captured authorized response','check':'Compare another captured role',
                'next_step':'Capture the complete second response','depends_on':[]}]
            extender.investigation.ledger.data['test_plan'] = tests
            extender.investigation.event('progress','Baseline captured; comparing the second role',
                                         evidence_id='EV0000001')
            extender._refresh_investigation()
            assert ui.investigation_table.getRowCount() == 1
            assert 'EV0000001' in ui.investigation_detail.getText()
            assert 'Authorization' in ui.investigation_timeline.getText()
            ui.input_field.setText('Keep this draft.')
            ui.investigation_buttons['Focus selected'].doClick(0)
            assert ui.input_field.getText().startswith('Keep this draft.\nFocus on saved test T-fixture')
            assert ui.tabs.getSelectedIndex() == 0
            req={'url':'https://example.test/api/items/42?page=1','method':'GET','headers':{'Cookie':'fixture-secret'},'body':''}
            selected={'history_index':1,'request_sha256':digest('request'),'url_sha256':digest(req['url'])}
            observed={'status':200,'body':'{"items":[]}','body_complete':True}
            mapped=discover([observe(req,observed,selected)],origin(req['url']))
            extender.lab.ingest(mapped,'EV0000001')
            lead=next(l for l in mapped['leads'] if l['kind']=='parameter_contract')
            exp=extender.lab.prepare(req,selected,'parameter_boundaries','page',lead_id=lead['id'])
            ui.refresh_lab(extender.lab.snapshot(include_routes=True))
            assert ui.lab_table.getRowCount()==len(mapped['leads'])+1
            assert ui.lab_routes_table.getRowCount()==1
            ui.lab_filter.setText('page')
            assert ui.lab_table.getRowCount()==1 and ui.lab_rows[0]['id']==lead['id']
            ui.lab_filter.setText('nothing matches this')
            assert ui.lab_table.getRowCount()==0 and not ui.lab_buttons['Show card in chat'].isEnabled()
            assert 'No matching discoveries' in ui.lab_detail.getText()
            ui.lab_filter.getActionMap().get('clear-filter').actionPerformed(None)
            ui.lab_kind.setSelectedIndex(2)
            assert len(ui.lab_rows)==1 and ui.lab_rows[0]['id']==exp['id']
            ui.lab_kind.setSelectedIndex(0)
            card=extender._lab_card(lead['id'])
            ui.renderer.add_lab_card(card)
            ui.chat_view.setText(ui.renderer.to_html())
            assert 'burpai-lab:'+lead['id']+':challenge' in ui.renderer.to_html()
            from javax.swing.event import HyperlinkEvent
            event=HyperlinkEvent(ui.chat_view,HyperlinkEvent.EventType.ACTIVATED,None,'burpai-lab:'+lead['id']+':challenge')
            for listener in ui.chat_view.getHyperlinkListeners(): listener.hyperlinkUpdate(event)
            assert extender.actions[-1][0]=='prompt' and 'Challenge discovery' in extender.actions[-1][1]
            assert extender.actions[-1][2]['retain_mission']
            before=len(extender.actions)
            extender._lab_card_action('javascript:alert(1)')
            assert len(extender.actions)==before
            evil=HtmlRenderer(); evil.add_lab_card({'id':lead['id'],'title':'<script>bad()</script>','sections':[('Evidence','<img src=x>')]})
            assert '<script>' not in evil.to_html() and '<img src=' not in evil.to_html()
            sent=[]
            def send(value): sent.append(value); return dict(observed,ok=True,url=req['url'])
            result=extender.lab.run(exp['id'],send,lambda *args:'EV0000002',lambda:True,approved=True)
            assert result['experiment']['state']=='completed' and len(sent)==5
            assert 'fixture-secret' not in json.dumps(extender.lab.snapshot())
            completed=HtmlRenderer(); completed.add_lab_card(extender._lab_card(exp['id']))
            assert ':run' not in completed.to_html() and 'COMPLETED' in completed.to_html()
            ui.refresh_lab(extender.lab.snapshot(include_routes=True))
            ui.renderer.add('user','Investigate object access using the captured traffic.')
            ui.renderer.add('assistant','The authorized baseline is saved. I am comparing the second captured role and checking whether the response is stable.')
            ui.renderer.add('tool','Complete HTTP response saved. Evidence: EV0000001.')
            ui.chat_view.setText(ui.renderer.to_html())
            ui.set_status('running', model='Fixture model', iter_str='3/12')
            ui.investigation_table.getParent().getParent().setColumnHeaderView(ui.investigation_table.getTableHeader())
            ui.lab_table.getParent().getParent().setColumnHeaderView(ui.lab_table.getTableHeader())
            for index, filename in ((0,'burpai_v45_investigation_agent.png'),(investigation_index,'burpai_v45_investigation_board.png'),(lab_index,'burpai_v45_testing_lab.png'),(1,'burpai_v45_source_polished.png'),(local_index,'burpai_v45_wsl_terminal.png')):
                ui.tabs.setSelectedIndex(index)
                root = ui.root
                root.setSize(Dimension(1440,960))
                def layout(component):
                    component.doLayout()
                    if hasattr(component,'getComponents'):
                        for child in component.getComponents(): layout(child)
                layout(root)
                if index==0:
                    from javax.swing.text.html import HTML
                    from java.awt.event import MouseEvent
                    links=ui.chat_view.getDocument().getIterator(HTML.Tag.A)
                    assert links.isValid()
                    rectangle=ui.chat_view.modelToView(links.getStartOffset()+2)
                    before=len(extender.actions)
                    click=MouseEvent(ui.chat_view,MouseEvent.MOUSE_CLICKED,0,0,rectangle.x+2,rectangle.y+2,1,False,MouseEvent.BUTTON1)
                    for listener in ui.chat_view.getMouseListeners(): listener.mouseClicked(click)
                    assert len(extender.actions)>before, 'Native HTML link did not activate'
                image = BufferedImage(1440,960,BufferedImage.TYPE_INT_RGB)
                graphics = image.createGraphics()
                graphics.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING,RenderingHints.VALUE_TEXT_ANTIALIAS_ON)
                root.printAll(graphics); graphics.dispose()
                ImageIO.write(image,'png',File(os.path.join(ROOT,'artifacts',filename)))
            ui.tabs.setSelectedIndex(lab_index); root.setSize(Dimension(1040,760)); layout(root)
            assert ui.lab_table.getWidth()>200 and ui.lab_detail.getWidth()>200
            image=BufferedImage(1040,760,BufferedImage.TYPE_INT_RGB); graphics=image.createGraphics()
            graphics.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING,RenderingHints.VALUE_TEXT_ANTIALIAS_ON)
            root.printAll(graphics); graphics.dispose()
            ImageIO.write(image,'png',File(os.path.join(ROOT,'artifacts','burpai_v45_compact_lab.png')))
            ui.tabs.setSelectedIndex(1); layout(root)
            image=BufferedImage(1040,760,BufferedImage.TYPE_INT_RGB); graphics=image.createGraphics()
            graphics.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING,RenderingHints.VALUE_TEXT_ANTIALIAS_ON)
            root.printAll(graphics); graphics.dispose()
            ImageIO.write(image,'png',File(os.path.join(ROOT,'artifacts','burpai_v45_compact_source.png')))
            ui.tabs.setSelectedIndex(0); layout(root)
            assert ui.agent_send_button.getWidth()>70
            image=BufferedImage(1040,760,BufferedImage.TYPE_INT_RGB); graphics=image.createGraphics()
            graphics.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING,RenderingHints.VALUE_TEXT_ANTIALIAS_ON)
            root.printAll(graphics); graphics.dispose()
            ImageIO.write(image,'png',File(os.path.join(ROOT,'artifacts','burpai_v45_compact_chat.png')))
            ui.renderer.clear(); ui.chat_view.setText(ui.renderer.to_html()); ui.input_field.setText('')
            extender.agent_running=False; ui.set_status('ready'); ui.tabs.setSelectedIndex(0)
            root.setSize(Dimension(1440,960)); layout(root)
            assert not ui.agent_pause_button.isVisible()
            image=BufferedImage(1440,960,BufferedImage.TYPE_INT_RGB); graphics=image.createGraphics()
            graphics.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING,RenderingHints.VALUE_TEXT_ANTIALIAS_ON)
            root.printAll(graphics); graphics.dispose()
            ImageIO.write(image,'png',File(os.path.join(ROOT,'artifacts','burpai_v45_welcome.png')))
            ui._chat_updated(False); ui._chat_updated(False)
            assert ui.agent_latest_button.isVisible() and ui.agent_unread==2
            ui.agent_latest_button.doClick(0)
            assert not ui.agent_latest_button.isVisible() and ui.agent_unread==0
            ui._toast('Saved fixture'); assert ui.toast_bar.isVisible()
            ui._toast('Saved again'); assert ui.toast_label.getText()=='Saved again'
            ui.toast_timer.stop(); ui.toast_bar.setVisible(False)
            # Exercise the actual pure comparison engine on Jython too.
            baseline = {'url':'https://example.test/','status':200,'body':'{"ok":false}', 'body_complete':True}
            candidate = dict(baseline,body='{"ok":true}')
            assert compare_http(baseline,candidate)['changed_json_paths'] == ['/ok']
            assert plan_metadata(tests[0], {'priority':2},tests)['priority'] == 2
        except Exception as exc:
            import traceback
            traceback.print_exc(); failures.append(exc)

SwingUtilities.invokeAndWait(Check())
if failures: raise failures[0]
print('PASS: all 17 Swing pages, local tool catalog and fixture checks, navigation, quick switch, filtering, undo/redo, run states, native card clicks, responsive layouts, and toasts.')

# -*- coding: utf-8 -*-
from __future__ import unicode_literals
import json
import os
import sys
import threading
import unittest
import ast
import io
import textwrap

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import BurpAI_v4_WSL as bridge
# Avoid loading unrelated Jython socket/Netty classes for these offline checks.
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
with io.open(os.path.join(ROOT,'BurpAI_v4_Extension.py'),encoding='utf-8') as handle:
    SOURCE = handle.read()
TREE = ast.parse(SOURCE.encode('utf-8'))
LINES = SOURCE.splitlines(True)
def load_function(name, namespace, owner):
    container = next(node for node in TREE.body if getattr(node,'name','') == owner)
    nodes = container.body
    for index,node in enumerate(nodes):
        if getattr(node,'name','') == name:
            end = nodes[index+1].lineno-1 if index+1 < len(nodes) else len(LINES)
            code = textwrap.dedent(''.join(LINES[node.lineno-1:end]))
            eval(compile(code.encode('utf-8'),'<WSL adapter test>','exec'),namespace)
            return namespace[name]
    raise AssertionError(name)


class ValidationTests(unittest.TestCase):
    def test_workspace_traversal_is_rejected_and_linux_paths_work(self):
        for value in ('../x', 'a/../../etc', '/etc/passwd', '/workspace/../etc', 'a\\b', 'x\x00y'):
            with self.assertRaises(ValueError): bridge.workspace_path(value)
        self.assertEqual('proof/test.py', bridge.workspace_path('/workspace/proof/test.py'))
        self.assertEqual('.', bridge.workspace_path('/workspace', True))
        with self.assertRaises(ValueError): bridge.workspace_path('.')

    def test_network_permissions_and_input_limits(self):
        for args in ({'command':'echo x','network':True}, {'command':''},
                     {'command':'x\x00y'}, {'command':'x','timeout':301},
                     {'command':'x','timeout':True}, {'command':'x','network':'false'},
                     {'command':'x','max_output':999999}, {'command':'x','unexpected':True},
                     {'command':'x'*32769}):
            with self.assertRaises(ValueError): bridge.normalize_request('exec', args)
        valid = bridge.normalize_request('exec', {'command':"printf '%s' 'a;$(echo b)'"})
        self.assertFalse(valid['network'])
        self.assertEqual(60, valid['timeout'])
        self.assertTrue(bridge.normalize_request('exec', {'command':'x','network':True}, True)['network'])
        self.assertTrue(bridge.normalize_request('exec', {'command':'x'}, True)['network'])
        self.assertFalse(bridge.normalize_request('exec', {'command':'x','network':False}, True)['network'])
        with self.assertRaises(ValueError):
            bridge.normalize_request('write_file', {'path':'a','content':'x'*(bridge.MAX_FILE+1)})
        with self.assertRaises(ValueError):
            bridge.normalize_request('write_file', {'path':'a','content':'x','overwrite':'true'})
        with self.assertRaises(ValueError):
            bridge.normalize_request('read_file', {'path':'a','offset':-1})

    def test_windows_launch_never_includes_the_command_or_a_shell(self):
        args = bridge.launch_arguments('Kali (Work)', 'tester', 123)
        self.assertEqual(['--distribution','Kali (Work)','--user','tester','--exec','/usr/bin/python3'], args[:6])
        self.assertIn('read(123)', args[-1])
        self.assertNotIn('bash', args)
        for distro,user in (('--exec',''),('Kali\nUbuntu',''),('Kali','--root'),('Kali','a;id')):
            with self.assertRaises(ValueError): bridge.launch_arguments(distro,user,100)


class SessionTests(unittest.TestCase):
    def setUp(self):
        self.calls = []
        def transport(distro,user,args,stopped):
            self.calls.append((distro,user,args))
            return {'ok':True,'stdout':'fixture','sandbox':'bubblewrap'}
        self.session = bridge.WSLBridge(transport)

    def test_disconnected_failure_probe_and_pinned_configuration(self):
        self.assertFalse(self.session.request('exec', {'command':'pwd'})['ok'])
        self.assertEqual([], self.calls)
        self.assertTrue(self.session.connect('Kali', 'tester', network=False)['ok'])
        self.assertFalse(self.session.request('exec', {'command':'curl x','network':True})['ok'])
        self.assertEqual(1, len(self.calls))
        self.assertTrue(self.session.request('exec', {'command':'pwd'})['ok'])
        self.assertEqual('Kali',self.calls[-1][0])
        self.session.disconnect()
        self.assertFalse(self.session.status()['connected'])

    def test_network_defaults_to_connection_and_can_be_disabled(self):
        self.assertTrue(self.session.connect('Kali')['ok'])
        self.assertTrue(self.session.status()['network_allowed'])
        self.assertTrue(self.session.request('exec', {'command':'pwd'})['ok'])
        self.assertTrue(self.calls[-1][2]['network'])
        self.assertTrue(self.session.request('exec', {'command':'pwd', 'network':False})['ok'])
        self.assertFalse(self.calls[-1][2]['network'])
        self.assertTrue(self.session.connect('Kali', network=False)['ok'])
        self.assertTrue(self.session.request('exec', {'command':'pwd'})['ok'])
        self.assertFalse(self.calls[-1][2]['network'])

    def test_failed_sandbox_probe_never_enables_execution(self):
        self.session.transport = lambda *args:{'ok':False,'error':'bwrap unavailable'}
        self.assertFalse(self.session.connect('Kali')['ok'])
        self.assertFalse(self.session.status()['connected'])

    def test_stop_is_latched_and_busy_operations_cannot_overlap(self):
        self.session.connect('Kali')
        entered, release = threading.Event(), threading.Event()
        result = []
        def transport(distro,user,args,stopped):
            entered.set(); release.wait(5)
            return {'ok':True, 'saw_stop':stopped()}
        self.session.transport = transport
        worker = threading.Thread(target=lambda:result.append(self.session.request('exec',{'command':'sleep 3'})))
        worker.start()
        try:
            self.assertTrue(entered.wait(5))
            self.assertFalse(self.session.request('exec',{'command':'pwd'})['ok'])
            self.session.cancel()
        finally:
            release.set(); worker.join(5)
        self.assertFalse(worker.is_alive())
        self.assertTrue(result[0]['cancelled'])
        self.assertTrue(result[0]['saw_stop'])
        self.assertTrue(self.session.status()['connected'])
        self.assertFalse(self.session.status()['running'])

    def test_disconnect_during_probe_cannot_reconnect_on_late_success(self):
        entered, release = threading.Event(), threading.Event()
        def transport(*args): entered.set(); release.wait(5); return {'ok':True}
        self.session.transport = transport
        result = []
        worker = threading.Thread(target=lambda:result.append(self.session.connect('Kali')))
        worker.start()
        try:
            self.assertTrue(entered.wait(5)); self.session.disconnect()
        finally:
            release.set(); worker.join(5)
        self.assertFalse(self.session.status()['connected'])
        self.assertFalse(result[0]['ok'])

    def test_external_cancellation_prevents_transport_and_releases_lock(self):
        self.session.connect('Kali')
        result = self.session.request('exec', {'command':'pwd'}, cancelled=lambda:True)
        self.assertTrue(result['cancelled'])
        self.assertEqual(1,len(self.calls))
        self.assertTrue(self.session.request('exec', {'command':'pwd'})['ok'])


class AdapterTests(unittest.TestCase):
    def setUp(self):
        namespace = {'_safe_text':bridge.text_type}
        methods = dict((name,load_function(name,namespace,'BurpExtender')) for name in
                       ('_tool_wsl_operation','_tool_wsl_exec','extensionUnloaded'))
        self.agent = type('Agent',(object,),methods)()
        self.agent.kill_switch = self.agent.stop_agent_flag = False
        self.agent._website_in_scope = lambda url:url=='https://example.test/'
        self.agent._safe_ui = lambda callback:callback()
        self.outputs, self.calls = [], []
        self.agent.ui = type('UI',(object,),{'_terminal_present':lambda _,label,result:self.outputs.append(result),
                                           'hide_decision_prompt':lambda _:None})()
        def transport(distro,user,args,stop): self.calls.append(args); return {'ok':True}
        self.agent.wsl_bridge = bridge.WSLBridge(transport)
        self.agent.wsl_bridge.connect('Kali',network=True)
        self.calls[:] = []

    def test_supplied_network_target_requires_scope_and_is_not_sent_to_linux(self):
        self.assertFalse(self.agent._tool_wsl_exec({'command':'curl x','network':True,
                                                  'target_url':'https://other.test/'})['ok'])
        self.assertEqual([],self.calls)
        self.assertTrue(self.agent._tool_wsl_exec({'command':'curl x','network':True,'target_url':'https://example.test/'})['ok'])
        self.assertNotIn('target_url',self.calls[0])
        self.assertEqual('https://example.test/',self.outputs[-1]['target_url'])
        self.assertEqual(2,len(self.outputs))

    def test_general_internet_needs_no_test_target(self):
        def unexpected_scope_check(url):
            raise AssertionError('General web access should not require a test target.')
        self.agent._website_in_scope = unexpected_scope_check
        for target in (None, '', '   '):
            arguments = {'command':'curl -I --max-time 15 https://example.com'}
            if target is not None: arguments['target_url'] = target
            result = self.agent._tool_wsl_exec(arguments)
            self.assertTrue(result['ok'])
            self.assertEqual('',result['target_url'])
            self.assertTrue(self.calls[-1]['network'])
            self.assertNotIn('target_url',self.calls[-1])
        self.assertEqual(3,len(self.calls))
        self.assertEqual(3,len(self.outputs))

    def test_kill_stop_and_unload_revoke_execution(self):
        self.agent.kill_switch=True
        self.assertTrue(self.agent._tool_wsl_exec({'command':'pwd'})['cancelled'])
        self.agent.kill_switch=False; self.agent.stop_agent_flag=True
        self.assertTrue(self.agent._tool_wsl_operation('write_file',{'path':'x','content':'x'})['cancelled'])
        self.assertEqual([],self.calls)
        self.agent.extensionUnloaded()
        self.assertFalse(self.agent.wsl_bridge.status()['connected'])

    def test_default_network_rechecks_scope_and_offline_is_explicit(self):
        self.assertFalse(self.agent._tool_wsl_exec({'command':'curl x','target_url':'https://other.test/'})['ok'])
        self.assertEqual([], self.calls)
        self.assertTrue(self.agent._tool_wsl_exec({'command':'curl x','target_url':'https://example.test/'})['ok'])
        self.assertTrue(self.calls[-1]['network'])
        self.assertNotIn('target_url', self.calls[-1])
        self.assertTrue(self.agent._tool_wsl_exec({'command':'pwd','network':False})['ok'])
        self.assertFalse(self.calls[-1]['network'])
        self.agent.wsl_bridge.connect('Kali', network=False)
        self.assertTrue(self.agent._tool_wsl_exec({'command':'pwd'})['ok'])
        self.assertFalse(self.calls[-1]['network'])

    def test_general_internet_cannot_override_offline_connection(self):
        self.agent.wsl_bridge.connect('Kali', network=False)
        self.calls[:] = []
        result = self.agent._tool_wsl_exec({'command':'curl https://example.com','network':True})
        self.assertFalse(result['ok'])
        self.assertIn('Network access is off',result['error'])
        self.assertEqual([],self.calls)

    def test_general_internet_requires_connection_and_respects_stop(self):
        self.agent.stop_agent_flag=True
        self.assertTrue(self.agent._tool_wsl_exec({'command':'curl https://example.com','network':True})['cancelled'])
        self.agent.stop_agent_flag=False
        self.agent.wsl_bridge.disconnect()
        self.assertFalse(self.agent._tool_wsl_exec({'command':'curl https://example.com','network':True})['ok'])
        self.assertEqual([],self.calls)


if __name__ == '__main__': unittest.main()

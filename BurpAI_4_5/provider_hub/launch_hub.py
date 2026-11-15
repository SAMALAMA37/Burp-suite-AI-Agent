"""Start the local hub once, optionally connect Burp, and open its dashboard."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import webbrowser
from urllib.request import build_opener, ProxyHandler
from llm_hub import Hub, ROOT

def running(port):
    try:
        with build_opener(ProxyHandler({})).open('http://127.0.0.1:%d/health'%port,timeout=2) as response:
            return json.load(response).get('service')=='BurpAI Connection Hub'
    except Exception: return False

def launch(port=8765,open_browser=True,connect=False):
    hub=Hub(port=port)
    if not running(port):
        log=ROOT/'.state'/'hub.log'
        flags=subprocess.CREATE_NO_WINDOW if os.name=='nt' else 0
        with log.open('ab') as output:
            process=subprocess.Popen([sys.executable,str(ROOT/'llm_hub.py'),'--port',str(port)],
                cwd=str(ROOT),stdin=subprocess.DEVNULL,stdout=output,stderr=output,
                creationflags=flags,start_new_session=os.name!='nt')
        for _ in range(60):
            if running(port): break
            if process.poll() is not None: raise RuntimeError('Hub could not start. See provider_hub/.state/hub.log.')
            time.sleep(.2)
        else: raise RuntimeError('Hub startup timed out. Check provider_hub/.state/hub.log.')
    if connect: hub.connect_burp()
    if open_browser: webbrowser.open('http://127.0.0.1:%d/#token=%s'%(port,hub.token))
    print('Connection Hub is running at http://127.0.0.1:%d'%port)

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port',type=int,default=8765)
    parser.add_argument('--no-browser',action='store_true')
    parser.add_argument('--connect-burp',action='store_true')
    args=parser.parse_args()
    launch(args.port,not args.no_browser,args.connect_burp)

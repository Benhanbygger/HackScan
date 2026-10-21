"""Isolated end-to-end checks against the real PHP web entry point. No external scans."""
import http.cookiejar
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import build_opener, HTTPCookieProcessor

source = Path(__file__).resolve().parents[1]
php = os.environ.get('HACKSCAN_PHP', '/workspace/.tools/php/php')
checks = 0

def check(condition, name):
    global checks
    assert condition, name
    checks += 1
    print('PASS:', name)

with tempfile.TemporaryDirectory(prefix='hackscan-web-') as tmp:
    root = Path(tmp)
    shutil.copytree(source/'httpdocs', root/'httpdocs')
    shutil.copytree(source/'hackscan-private', root/'hackscan-private', ignore=shutil.ignore_patterns('data', 'setup-key.txt'))
    with socket.socket() as s:
        s.bind(('127.0.0.1',0)); port = s.getsockname()[1]
    base = f'http://127.0.0.1:{port}'
    jar = http.cookiejar.CookieJar(); client = build_opener(HTTPCookieProcessor(jar))
    def call(path='/hackscan/index.php', values=None, headers=None):
        from urllib.request import Request
        req = Request(base+path, data=urlencode(values).encode() if values is not None else None, headers=headers or {})
        try:
            with client.open(req, timeout=10) as r: return r.status, r.read().decode(), dict(r.headers)
        except HTTPError as e: return e.code, e.read().decode(), dict(e.headers)
    def csrf(body):
        match = re.search(r'(?:name="csrf" value|data-csrf)="([a-f0-9]+)"', body)
        assert match, 'CSRF token is present'
        return match.group(1)
    proc = subprocess.Popen([php,'-S',f'127.0.0.1:{port}','-t',str(root/'httpdocs')], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(60):
            try: code,body,headers = call(); break
            except OSError: time.sleep(.1)
        else: raise AssertionError('PHP server did not start')
        token = csrf(body)
        check(code==200 and 'Opret din adgang' in body,'setup page works before account creation')
        check(call('/hackscan/index.php?api=state')[0]==401,'unauthenticated API denied')
        check(call('/hackscan-private/core.php')[0]==404,'private application files outside web root')
        check(call('/hackscan/index.php', {'password':'invalid'})[0]==403,'missing CSRF rejected')
        key = secrets.token_urlsafe(32); password = secrets.token_urlsafe(24)
        (root/'hackscan-private'/'setup-key.txt').write_text(key)
        _,body,_=call(values={'csrf':token,'setup_key':key,'password':'short','confirm':'short'})
        check('14–72' in body,'short initial password rejected')
        code,body,headers=call(values={'csrf':token,'setup_key':key,'password':password,'confirm':password})
        check(code==200 and 'data-csrf' in body,'account creation logs in with new session')
        check(not (root/'hackscan-private'/'setup-key.txt').exists(),'setup key removed after initialization')
        token2=csrf(body)
        check(token!=token2,'session CSRF rotates after authentication')
        cookie=next(c for c in jar if c.name=='hackscan_session')
        check('HttpOnly' in cookie._rest and cookie._rest.get('SameSite')=='Strict','session cookie restricts browser access and cross-site use')
        check("frame-ancestors 'none'" in headers.get('Content-Security-Policy',''),'response has restrictive content policy')
        check(call('/hackscan/index.php?api=start',{})[0]==403,'scan start requires CSRF')
        check(call('/hackscan/index.php?api=start',{'limit':'0','start_char':'m'}, {'X-CSRF-Token':token2})[0]==400,'invalid scan limit rejected by HTTP API')
        check(call('/hackscan/index.php?api=start',{'limit':'75','start_char':'ab'}, {'X-CSRF-Token':token2})[0]==400,'invalid start character rejected by HTTP API')
        code,body,_=call('/hackscan/index.php?api=start',{'limit':'75','start_char':'M'}, {'X-CSRF-Token':token2})
        check(code==200,'authenticated scan start accepted')
        check(call('/hackscan/index.php?api=start',{}, {'X-CSRF-Token':token2})[0]==409,'duplicate scan start rejected')
        _,statebody,_=call('/hackscan/index.php?api=state')
        import json
        state=json.loads(statebody)
        check(state['state']['target']==75 and state['state']['start_char']=='m','chosen scan count and start persist through HTTP requests')
        check(set(state['groups'])=={'all','review','ok','errors'},'state API serves all four dashboard panels together')
        database=root/'hackscan-private/data/hackscan.sqlite3'
        with sqlite3.connect(database) as db:
            stored=db.execute("SELECT value FROM settings WHERE name='password_hash'").fetchone()[0]
            check(stored!=password and stored.startswith('$2y$'),'only password hash persisted')
            db.execute("INSERT INTO results(domain,current_url,status) VALUES('example.dk','https://other.dk/','pending')")
        code,_,_=call('/hackscan/index.php?api=stop',{}, {'X-CSRF-Token':token2})
        code2,body,_=call('/hackscan/index.php?api=state')
        check(code==200 and '"running":false' in body and 'cancelled' in body,'stop persists state and cancels queued domains')
        code,body,headers=call('/hackscan/index.php?api=export')
        check(code==200 and 'example.dk' in body and 'text/csv' in headers['Content-Type'],'authenticated CSV contains saved results')
        worker=subprocess.run([php,str(root/'hackscan-private/worker.php')],capture_output=True)
        check(worker.returncode==0,'scheduled PHP worker can resume a stopped installation harmlessly')
        check(call('/hackscan-private/data/hackscan.sqlite3')[0]==404,'database inaccessible over HTTP')
        call('/hackscan/index.php?api=logout',{}, {'X-CSRF-Token':token2})
        check(call('/hackscan/index.php?api=state')[0]==401,'logout revokes API access')
        _,body,_=call(); token3=csrf(body)
        for _ in range(10): call(values={'csrf':token3,'password':'wrong-password'})
        check(call(values={'csrf':token3,'password':'wrong-password'})[0]==429,'repeated failed logins are rate-limited')
        with sqlite3.connect(database) as db: db.execute('DELETE FROM attempts')
        code,body,_=call(values={'csrf':token3,'password':password})
        check(code==200 and 'data-csrf' in body,'saved credentials work after logout and re-login')
        print(f'\n{checks} web integration checks passed.')
    finally:
        proc.terminate(); proc.wait(timeout=5)

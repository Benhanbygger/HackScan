"""Exercise the actual 0.3.1 -> current archive upgrade without contacting external sites."""
from pathlib import Path
import tempfile, subprocess, socket, secrets, http.cookiejar, time, re, sqlite3, json, zipfile, os
from urllib.request import build_opener, HTTPCookieProcessor, Request
from urllib.error import HTTPError
from urllib.parse import urlencode
repo=Path(__file__).resolve().parents[2]
php=os.environ.get('HACKSCAN_PHP','/workspace/.tools/php/php')
baseline='1635bffa6489203a439da467ed7130f98f74253f'
count=0

def check(value,label):
 global count
 assert value,label
 count+=1; print('PASS:',label)

with tempfile.TemporaryDirectory(prefix='hackscan-upgrade-') as tmp:
 root=Path(tmp)
 for name in ['hackscan-private/app.php','hackscan-private/core.php','hackscan-private/worker.php','httpdocs/hackscan/index.php','httpdocs/hackscan/app.js','httpdocs/hackscan/style.css']:
  p=root/name;p.parent.mkdir(parents=True,exist_ok=True)
  p.write_bytes(subprocess.check_output(['git','show',baseline+':php/'+name],cwd=repo))
 key=secrets.token_urlsafe(32);password=secrets.token_urlsafe(24)
 (root/'hackscan-private/setup-key.txt').write_text(key)
 with socket.socket() as sock:sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
 process=subprocess.Popen([php,'-S',f'127.0.0.1:{port}','-t',str(root/'httpdocs')],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
 client=build_opener(HTTPCookieProcessor(http.cookiejar.CookieJar()))
 url=f'http://127.0.0.1:{port}/hackscan/index.php'
 def call(query='',data=None):
  req=Request(url+query,data=urlencode(data).encode() if data is not None else None)
  try:
   with client.open(req,timeout=5) as response:return response.status,response.read().decode()
  except HTTPError as e:return e.code,e.read().decode()
 try:
  for _ in range(60):
   try:code,body=call();break
   except OSError:time.sleep(.1)
  token=re.search(r'name="csrf" value="([a-f0-9]+)"',body)[1]
  code,body=call(data={'csrf':token,'setup_key':key,'password':password,'confirm':password})
  check(code==200 and 'id="app"' in body,'baseline 0.3.1 account created with isolated test password')
  database=root/'hackscan-private/data/hackscan.sqlite3'
  with sqlite3.connect(database) as db:
   old_hash=db.execute("SELECT value FROM settings WHERE name='password_hash'").fetchone()[0]
   db.execute("INSERT INTO results(domain,current_url,status,detail) VALUES('legacy.dk','https://legacy.dk/','http_error','HTTP 404')")
  package=repo/'dist/HackScan-Opdatering-0.5.0.zip'
  with zipfile.ZipFile(package) as archive:
   assert not any('data/' in n or 'setup-key' in n for n in archive.namelist())
   archive.extractall(root)
  check(call('?api=state')[0]==401,'old shared-login session must reauthenticate after account migration')
  code,body=call();token=re.search(r'name="csrf" value="([a-f0-9]+)"',body)[1]
  check('name="username"' in body and 'Opret din adgang' not in body,'upgrade requires login rather than new setup key')
  code,body=call(data={'csrf':token,'username':'admin','password':password})
  check(code==200 and 'data-can-scan="1"' in body,'existing password works for migrated administrator')
  code,body=call('?api=state');state=json.loads(body)
  check(state['groups']['all']['total']==1 and state['groups']['all']['rows'][0]['domain']=='legacy.dk','historical domain survives actual archive extraction')
  check(state['groups']['errors']['rows'][0]['http_code']==404,'historical exact HTTP status migrated without inventing redirect codes')
  check(state['groups']['all']['rows'][0]['security_grade'] is None,'old redirect-only results are not assigned artificial security grades')
  with sqlite3.connect(database) as db:
   user=db.execute('SELECT username,password_hash,role FROM users').fetchone()
   check(user==('admin',old_hash,'admin'),'legacy password hash preserved in named administrator account')
  code,body=call('?admin=users')
  check(code==200 and 'id="create-user"' in body,'new administration and helper files work after upload')
  code,body=call('?domain=legacy.dk')
  check(code==200 and 'Endnu ingen sikkerhedsvurdering' in body,'legacy detail page explains missing security assessment')
  check(not (root/'hackscan-private/setup-key.txt').exists(),'upgrade does not create or require a new setup secret')
  print(f'\n{count} archive upgrade checks passed.')
 finally:
  process.terminate();process.wait(timeout=5)

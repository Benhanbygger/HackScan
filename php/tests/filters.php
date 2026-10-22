<?php
declare(strict_types=1);
require dirname(__DIR__).'/hackscan-private/core.php';
$n=0;function check(bool $ok,string $name):void{global $n;if(!$ok)throw new RuntimeException('FAIL: '.$name);$n++;echo 'PASS: '.$name."\n";}
function rejects(callable $fn,string $name):void{try{$fn();}catch(Throwable){check(true,$name);return;}check(false,$name);}
check(count(hs_ns_providers())===10,'all ten requested providers available');
check(hs_ns_match([['target'=>'NS1.ONE.COM.']],['one.com']),'case and trailing dot normalized');
check(hs_ns_match([['target'=>'ns.simply.com']],['one.com','simply.com']),'multiple providers use OR');
check(!hs_ns_match([['target'=>'one.com.evil.dk'],['target'=>'notone.com']],['one.com']),'substring spoof and sibling names rejected');
rejects(fn()=>hs_ns_options(['not-allowed.dk']),'unknown providers rejected');rejects(fn()=>hs_ns_options('one.com'),'non-array filter rejected');
$db=hs_db(':memory:');$db->exec("INSERT INTO domains VALUES('a.dk'),('b.dk'),('c.dk'),('d.dk'),('e.dk'),('f.dk')");hs_set($db,'catalog_timestamp',(string)time());
hs_start($db,2,'b',['one.com','simply.com']);
$http=0;$dns=0;$fetch=function()use(&$http){$http++;throw new RuntimeException('No HTTP expected');};
hs_tick($db,$fetch);
check(hs_get($db,'phase')==='ns_filter' && (int)$db->query('SELECT COUNT(*) FROM ns_candidates')->fetchColumn()===5,'catalog filters all candidates from chosen start rather than only first target');
$resolver=function($domain)use(&$dns){$dns++;return match($domain){'b.dk'=>[['target'=>'one.com.attacker.dk']],'c.dk'=>false,'d.dk'=>[['target'=>'ns1.one.com']],'e.dk'=>[['target'=>'ns.simply.com']],default=>[['target'=>'other.dk']]};};
hs_tick($db,$fetch,$resolver);check($dns===1 && $http===0,'one NS lookup per tick and no HTTP for rejected candidates');
for($i=0;$i<4;$i++)hs_tick($db,$fetch,$resolver);
check($db->query('SELECT domain FROM results ORDER BY domain')->fetchAll(PDO::FETCH_COLUMN)===['d.dk','e.dk'],'only matching domains reach HTTP queue and target counts matches');
check(hs_get($db,'ns_errors')==='1' && hs_get($db,'ns_checked')==='4','DNS failures counted separately and processing continues');
check(hs_get($db,'phase')==='scan' && hs_get($db,'ns_done')==='1','scan transitions to HTTP after matching target');
hs_start($db,8,'f',['gigahost.dk']);hs_tick($db,$fetch);hs_tick($db,$fetch,fn()=>[]);hs_tick($db,$fetch);
check(str_contains(hs_get($db,'notice'),'Kandidatlisten er opbrugt') && hs_get($db,'ns_matched')==='0','insufficient matches and empty DNS responses disclosed');
hs_tick($db,$fetch);check(hs_get($db,'running')==='0' && $http===0,'zero match scan finishes without contacting nonmatching sites');
check(hs_manual_domain(' https://WWW.Example.dk/ ')==='example.dk','manual scheme/www/trailing slash normalized');
foreach(['http://127.0.0.1','localhost','site.local','https://user:pass@example.dk','https://example.dk/path','https://example.dk?x=1','https://example.dk:443/','https://example.dk/#a','a.dk b.dk'] as $bad)rejects(fn()=>hs_manual_domain($bad),'invalid manual input rejected: '.$bad);
hs_start_manual($db,'manual.dk');
check(hs_get($db,'phase')==='scan' && hs_ns_selected($db)===[] && hs_get($db,'target')==='1','manual scan bypasses discovery and old NS filters');
check($db->query("SELECT current_url FROM results WHERE domain='manual.dk'")->fetchColumn()==='https://manual.dk/','manual domain queued for normal protected fetch');
// A clean report is hidden; unknown assessment and registered risks are retained.
$db=hs_db(':memory:');
$db->exec("INSERT INTO results(domain,current_url,status) VALUES('clean.dk','https://clean.dk/','ok'),('risk.dk','https://risk.dk/','ok'),('unknown.dk','https://unknown.dk/','ok'),('error.dk','https://error.dk/','error'),('redirect.dk','https://other.dk/','review')");
$q=$db->prepare('INSERT INTO reports(domain,report,score,grade,findings) VALUES(?,?,?,?,?)');$q->execute(['clean.dk','{}',100,'A',0]);$q->execute(['risk.dk','{}',95,'A',1]);
$visible=hs_groups($db,'',['issues_only'=>'1']);
check($visible['all']['total']===4 && !in_array('clean.dk',array_column($visible['all']['rows'],'domain'),true),'only assessed no-finding domain hidden by issues filter');
check($visible['ok']['total']===2,'same-domain risks and unassessed rows stay visible');
check(hs_groups($db,'',['issues_only'=>'0'])['all']['total']===5,'show clean restores full result list');
check(hs_groups($db,'clean',['issues_only'=>'1'])['all']['total']===0,'search uses same issue filter');
check((int)$db->query('SELECT COUNT(*) FROM results')->fetchColumn()===5,'filter does not delete stored results');
// Existing reports receive a findings count without SQLite JSON functions.
$legacy=new PDO('sqlite::memory:');$legacy->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE,PDO::FETCH_ASSOC);
$legacy->exec("CREATE TABLE reports(domain TEXT PRIMARY KEY,report TEXT,score INTEGER,grade TEXT,assessed_at TEXT);INSERT INTO reports VALUES('old.dk','{\"controls\":{\"hsts\":{\"state\":\"finding\"}}}',95,'A','old')");hs_security_schema($legacy);
check((int)$legacy->query('SELECT findings FROM reports')->fetchColumn()===1,'legacy finding reports migrated without misclassification');
$doh=['code'=>200,'truncated'=>false,'body'=>json_encode(['Status'=>0,'Question'=>[['name'=>'one.dk.','type'=>2]],'Answer'=>[['name'=>'one.dk.','type'=>2,'data'=>'ns.one.com.']]])];
check(hs_ns_match(hs_ns_doh('one.dk',fn()=>$doh),['one.com']),'valid HTTPS DNS response supplies provider match');
check(hs_ns_doh('other.dk',fn()=>$doh)===false,'HTTPS DNS response for wrong question rejected');
$db=hs_db(':memory:');hs_start($db,1,'0',['one.com']);hs_set($db,'phase','ns_filter');$db->exec("INSERT INTO ns_candidates VALUES('one.dk')");hs_set($db,'ns_retry_domain','one.dk');
hs_tick($db,fn()=>$doh);
check(hs_get($db,'ns_matched')==='1' && hs_get($db,'ns_retry_domain')==='','pending HTTPS DNS fallback takes one step and clears retry state');
$db=hs_db(':memory:');hs_start($db,1,'0',['one.com']);hs_set($db,'phase','discovery');hs_set($db,'indexes',json_encode(['https://index.commoncrawl.org/CC-MAIN-2026-01-index']));
$db->exec("INSERT INTO results(domain,current_url,status) VALUES('old.dk','https://old.dk/','ok')");
hs_tick($db,function($url,$limit,$consumer){$consumer(json_encode(['url'=>'https://old.dk/'])."\n".json_encode(['url'=>'https://new.dk/'])."\n");return ['code'=>200,'body'=>'','truncated'=>false];});
check((int)$db->query('SELECT COUNT(*) FROM ns_candidates')->fetchColumn()===2 && $db->query("SELECT status FROM results WHERE domain='old.dk'")->fetchColumn()==='ok','Common Crawl filter candidates do not overwrite historical unmatched results');
hs_tick($db,fn()=>['code'=>200,'body'=>'','truncated'=>false,'empty'=>true]);
hs_tick($db,fn()=>throw new RuntimeException('unexpected HTTP'),fn()=>[['target'=>'ns.one.com']]);
check(hs_get($db,'ns_matched')==='1','partial Common Crawl candidate pool passes through NS filter');
echo "\n$n filter checks passed.\n";

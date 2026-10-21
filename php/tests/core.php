<?php
declare(strict_types=1);
require dirname(__DIR__).'/hackscan-private/core.php';
$passed=0;
function check(bool $condition,string $message): void { global $passed; if (!$condition) throw new RuntimeException('FAIL: '.$message); $passed++; echo "PASS: $message\n"; }
function rejects(callable $fn,string $message): void { try { $fn(); } catch (Throwable) { check(true,$message); return; } check(false,$message); }
function response(int $code=200,?string $location=null,string $body=''): array { return ['code'=>$code,'location'=>$location,'body'=>$body,'truncated'=>false]; }
foreach (['127.0.0.1','10.0.0.1','169.254.169.254','100.64.0.1','192.0.2.1','224.0.0.1','::1','::ffff:127.0.0.1','2001:db8::1','fc00::1'] as $ip) check(!hs_public_ip($ip),'private/reserved IP rejected: '.$ip);
check(hs_public_ip('1.1.1.1') && hs_public_ip('2606:4700:4700::1111'),'public IPv4 and IPv6 accepted');
foreach (['file:///etc/passwd','http://localhost/','http://127.0.0.1/','https://user:pass@example.dk/','https://example.dk:22/',"https://example.dk/\r\nHost: evil.dk",'https://example.dk\\@evil.dk/'] as $url) rejects(fn()=>hs_url($url),'unsafe URL rejected');
check(hs_join('https://example.dk/a/b','../c?x=1')==='https://example.dk/c?x=1','relative path redirect resolved');
check(hs_join('https://example.dk/a/b','//other.dk/')==='https://other.dk/','scheme-relative redirect resolved');
check(hs_join('https://example.dk/a/b','?next=1')==='https://example.dk/a/b?next=1','query-only redirect resolved');
check(hs_outcome('example.dk','https://www.example.dk/',200)==='ok','www is same domain');
check(hs_outcome('example.dk','http://example.dk/',200)==='ok','HTTP and HTTPS considered same domain');
check(hs_outcome('example.dk','https://other.dk/',200)==='review','cross-domain redirect flagged');
check(hs_outcome('example.dk','https://example.dk/',503)==='http_error','HTTP error distinguished from normal response');
check(hs_extract_domain(['url'=>'https://www.example.dk/'])==='example.dk','homepage discovery normalizes www');
check(hs_extract_domain(['url'=>'https://example.dk/article'])===null && hs_extract_domain(['url'=>'https://example.com/'])===null,'discovery excludes non-homepage and non-Danish domains');
$db=hs_db(':memory:'); hs_start($db,2);
$indexes=[['cdx-api'=>'https://index.commoncrawl.org/CC-MAIN-2026-43-index'],['cdx-api'=>'https://index.commoncrawl.org/CC-MAIN-2026-39-index']];
hs_tick($db,fn()=>response(200,null,json_encode($indexes)));
check(hs_get($db,'phase')==='discovery','metadata stage advances to discovery');
hs_tick($db,function($url,$limit,$consumer) {
    $stream=json_encode(['url'=>'https://www.example.dk/'])."\n".json_encode(['url'=>'https://other.dk/'])."\n";
    // Deliberately split a JSON line across network chunks.
    $consumer(substr($stream,0,10)); $consumer(substr($stream,10)); return response();
});
check((int)$db->query('SELECT COUNT(*) FROM results')->fetchColumn()===2,'streamed discovery stores distinct homepage queue');
check(hs_get($db,'next_page')==='1','subsequent scan advances index page');
hs_tick($db,fn()=>response(302,'https://destination.dk/'));
$row=$db->query("SELECT * FROM results WHERE domain='example.dk'")->fetch();
check($row['status']==='pending' && $row['current_url']==='https://destination.dk/' && (int)$row['hops']===1,'redirect persists next hop for a later request');
hs_tick($db,fn()=>response());
$row=$db->query("SELECT * FROM results WHERE domain='example.dk'")->fetch();
check($row['status']==='review','resumed redirect becomes review result');
hs_tick($db,fn()=>response(503)); hs_tick($db,fn()=>response());
check(hs_get($db,'running')==='0' && hs_get($db,'checked')==='2','scan completes with correct checked count');
// Index fallback must happen on a separate request, within hosting time limits.
hs_start($db); hs_set($db,'phase','discovery'); hs_set($db,'indexes',json_encode(array_column($indexes,'cdx-api')));
for ($retry=0;$retry<3;$retry++) { hs_set($db,'retry_after','0'); hs_tick($db,fn()=>response(504)); }
check(hs_get($db,'index_attempt')==='1' && hs_get($db,'running')==='1','504 switches to previous index without abandoning scan');
// A certificate failure must never silently downgrade to plaintext HTTP.
$db=hs_db(':memory:'); hs_set($db,'running','1'); hs_set($db,'phase','scan');
$db->exec("INSERT INTO results(domain,current_url,status) VALUES('example.dk','https://example.dk/','pending')");
$calls=0;
hs_tick($db,function() use (&$calls) { $calls++; throw new HSNetworkError('Certificate validation failed',CURLE_PEER_FAILED_VERIFICATION); });
check($calls===1 && $db->query('SELECT status FROM results')->fetchColumn()==='error','TLS verification failure is reported without HTTP downgrade');
$db->exec("UPDATE results SET status='pending'");
$calls=0;
hs_tick($db,function() use (&$calls) { $calls++; if ($calls===1) throw new HSNetworkError('Connection refused',CURLE_COULDNT_CONNECT); return response(); });
check($calls===2 && $db->query('SELECT current_url FROM results')->fetchColumn()==='http://example.dk/','connection refusal allows HTTP-only homepage check');
$db->exec("UPDATE results SET status='pending',current_url='https://example.dk/',chain='[]',hops=0");
hs_tick($db,fn()=>response(301,'/'));
check($db->query('SELECT status FROM results')->fetchColumn()==='error','redirect loop is reported');
$db->exec("UPDATE results SET status='pending',current_url='https://other.dk/',chain='[]',hops=1");
hs_tick($db,fn()=>throw new RuntimeException('Destination unreachable'));
check($db->query('SELECT status FROM results')->fetchColumn()==='review','observed cross-domain hop retained when destination fails');
// Scan input validation must happen before existing results or options are changed.
foreach ([0,-1,10001,'2.5','abc'] as $invalid) rejects(fn()=>hs_options($invalid,'a'),'invalid scan count rejected');
foreach (['ab','*','../','æ',''] as $invalid) rejects(fn()=>hs_options(50,$invalid),'invalid start character rejected');
check(hs_extract_domain(['url'=>'https://sub.example.dk/'])===null,'discovery uses primary .dk domains for alphabetic positioning');
check(hs_options('125','M')===[125,'m'],'count and uppercase start are normalized');
$db=hs_db(':memory:'); hs_start($db,3,'m');
hs_tick($db,fn()=>response(200,null,json_encode($indexes)));
check(hs_get($db,'phase')==='inventory','letter start requires index positioning');
hs_tick($db,fn()=>response(200,null,json_encode(['pages'=>4])));
// Pages start with a, f, n, z. Target m lies in the f block before n.
$starts=['dk,a)/','dk,f)/','dk,n)/','dk,z)/'];
for ($i=0;$i<8 && hs_get($db,'phase')==='seek';$i++) {
    hs_tick($db,function($url) use ($starts) { parse_str(parse_url($url,PHP_URL_QUERY),$q); check(($q['limit']??null)==='1','seek reads at most the first CDX record'); return response(200,null,json_encode(['urlkey'=>$starts[(int)$q['page']]])."\n"); });
}
check(hs_get($db,'next_page')==='1','letter seek selects predecessor page containing requested start');
$feed=function(array $urls) { return function($url,$limit,$consumer) use ($urls) { foreach ($urls as $u) if (!$consumer(json_encode(['url'=>$u])."\n")) break; return response(); }; };
hs_tick($db,$feed(['https://f.dk/','https://m.dk/','https://n.dk/']));
check(hs_get($db,'phase')==='discovery' && (int)$db->query('SELECT COUNT(*) FROM results')->fetchColumn()===2,'prefix filter skips earlier names and continues across pages for count');
hs_tick($db,$feed(['https://m.dk/','https://p.dk/','https://q.dk/']));
check(hs_get($db,'phase')==='scan' && (int)$db->query('SELECT COUNT(*) FROM results')->fetchColumn()===3,'requested count enforced with duplicate domains across pages');
check($db->query("SELECT COUNT(*) FROM results WHERE domain='f.dk'")->fetchColumn()==0,'domains earlier than selected start are not queued');
$db=hs_db(':memory:'); hs_start($db,100); hs_set($db,'phase','discovery'); hs_set($db,'indexes',json_encode(array_column($indexes,'cdx-api')));
hs_tick($db,$feed(['https://a.dk/','https://b.dk/']));
for ($retry=0;$retry<3;$retry++) { hs_set($db,'retry_after','0'); hs_tick($db,fn()=>response(504)); }
check(hs_get($db,'phase')==='scan' && str_contains(hs_get($db,'notice'),'2 af 100'),'partial discovery is preserved and shortfall explained');
// Each result group paginates independently; search is literal and parameterized.
$db=hs_db(':memory:');
$q=$db->prepare('INSERT INTO results(domain,current_url,status,detail) VALUES(?,?,?,?)');
for ($i=0;$i<20;$i++) $q->execute(["test$i.dk","https://test$i.dk/",$i<10?'review':($i<15?'ok':'error'),$i===0?'100% literal':'ordinary']);
$groups=hs_groups($db,'',['page_all'=>1,'page_review'=>1]);
check(count($groups['all']['rows'])===8 && count($groups['review']['rows'])===2 && $groups['ok']['total']===5 && $groups['errors']['total']===5,'four groups return independently paginated results');
check(hs_groups($db,'100%')['all']['total']===1,'search treats percent as literal text');
check(hs_groups($db,"' OR 1=1 --")['all']['total']===0,'search resists SQL injection');
check(hs_groups($db,'',['page_all'=>999])['all']['page']===2,'out-of-range pagination clamps to last page');
echo "\n$passed checks passed.\n";

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
$db=hs_db(':memory:'); hs_start($db);
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
hs_tick($db,fn()=>response(504));
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
echo "\n$passed checks passed.\n";

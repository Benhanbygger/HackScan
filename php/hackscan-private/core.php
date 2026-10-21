<?php
declare(strict_types=1);

const HS_VERSION = '0.3.0';
class HSNetworkError extends RuntimeException {}

function hs_db(string $path): PDO {
    $db = new PDO('sqlite:' . $path, null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC]);
    $db->exec('PRAGMA busy_timeout=2000');
    $db->exec('CREATE TABLE IF NOT EXISTS settings (name TEXT PRIMARY KEY, value TEXT NOT NULL)');
    $db->exec('CREATE TABLE IF NOT EXISTS results (domain TEXT PRIMARY KEY, current_url TEXT NOT NULL, status TEXT NOT NULL, detail TEXT NOT NULL DEFAULT \'\', hops INTEGER NOT NULL DEFAULT 0, chain TEXT NOT NULL DEFAULT \'[]\', checked_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)');
    $db->exec('CREATE TABLE IF NOT EXISTS attempts (at INTEGER NOT NULL)');
    return $db;
}
function hs_get(PDO $db, string $key, string $default = ''): string {
    $q=$db->prepare('SELECT value FROM settings WHERE name=?'); $q->execute([$key]);
    $v=$q->fetchColumn(); return $v===false ? $default : (string)$v;
}
function hs_set(PDO $db, string $key, string $value): void {
    $db->prepare('INSERT OR REPLACE INTO settings(name,value) VALUES(?,?)')->execute([$key,$value]);
}
function hs_host(string $host): string { return preg_replace('/^www\./i', '', strtolower(rtrim($host,'.'))); }
function hs_in_range(string $ip, string $cidr): bool {
    [$network,$bits]=explode('/',$cidr); $a=inet_pton($ip); $b=inet_pton($network);
    if ($a===false || $b===false || strlen($a)!==strlen($b)) return false;
    $bytes=intdiv((int)$bits,8); $rest=(int)$bits%8;
    return substr($a,0,$bytes)===substr($b,0,$bytes) && (!$rest || ((ord($a[$bytes]) ^ ord($b[$bytes])) & (255 << (8-$rest)))===0);
}
function hs_public_ip(string $ip): bool {
    if (!filter_var($ip,FILTER_VALIDATE_IP,FILTER_FLAG_NO_PRIV_RANGE|FILTER_FLAG_NO_RES_RANGE)) return false;
    foreach (['0.0.0.0/8','100.64.0.0/10','192.0.0.0/24','192.0.2.0/24','198.18.0.0/15','198.51.100.0/24','203.0.113.0/24','224.0.0.0/4','240.0.0.0/4','::/96','::ffff:0:0/96','64:ff9b::/96','64:ff9b:1::/48','100::/64','2001::/23','2001:db8::/32','2002::/16','fc00::/7','fe80::/10','ff00::/8'] as $range) {
        if (hs_in_range($ip,$range)) return false;
    }
    return true;
}
function hs_url(string $url): array {
    if (strlen($url)>4096 || preg_match('/[\x00-\x20\x7f\\\\]/',$url)) throw new RuntimeException('Ugyldig adresse');
    $p=parse_url($url);
    if (!$p || !in_array(strtolower($p['scheme']??''),['http','https'],true) || empty($p['host']) || isset($p['user']) || isset($p['pass'])) throw new RuntimeException('Kun offentlige HTTP/HTTPS-adresser tillades');
    $p['scheme']=strtolower($p['scheme']); $p['host']=strtolower(rtrim($p['host'],'.'));
    if (!preg_match('/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/D',$p['host'])) throw new RuntimeException('Ugyldigt offentligt værtsnavn');
    $p['port']=$p['port']??($p['scheme']==='https'?443:80);
    if (!in_array($p['port'],[80,443],true)) throw new RuntimeException('Kun port 80 og 443 tillades');
    return $p;
}
function hs_resolve(string $host): string {
    $records=dns_get_record($host,DNS_A|DNS_AAAA);
    if (!$records) throw new RuntimeException('DNS-opslag gav ingen adresser');
    $ips=[];
    foreach ($records as $r) { $ip=$r['ip']??$r['ipv6']??null; if ($ip!==null) $ips[]=$ip; }
    if (!$ips) throw new RuntimeException('DNS-opslag gav ingen adresser');
    foreach ($ips as $ip) if (!hs_public_ip($ip)) throw new RuntimeException('Privat eller reserveret destinationsadresse afvist');
    usort($ips,fn($a,$b)=>substr_count($a,':')<=>substr_count($b,':'));
    return $ips[0];
}
function hs_fetch(string $url, int $limit=65536, ?callable $consumer=null): array {
    $p=hs_url($url); $ip=hs_resolve($p['host']);
    $target=str_contains($ip,':')?'['.$ip.']':$ip;
    $ch=curl_init($url); $body=''; $location=null; $bytes=0; $stopped=false;
    curl_setopt_array($ch,[
        CURLOPT_FOLLOWLOCATION=>false, CURLOPT_CONNECTTIMEOUT=>4, CURLOPT_TIMEOUT=>($p['host']==='index.commoncrawl.org'?20:12),
        CURLOPT_SSL_VERIFYPEER=>true, CURLOPT_SSL_VERIFYHOST=>2,
        CURLOPT_PROTOCOLS=>CURLPROTO_HTTP|CURLPROTO_HTTPS,
        CURLOPT_USERAGENT=>'HackScan/'.HS_VERSION.' (passive homepage redirect check)',
        CURLOPT_HTTPHEADER=>['Accept: application/json, text/html;q=0.9, */*;q=0.5'],
        CURLOPT_CONNECT_TO=>[$p['host'].':'.$p['port'].':'.$target.':'.$p['port']],
        CURLOPT_HEADERFUNCTION=>function($ch,$line) use (&$location) {
            if (str_starts_with($line,'HTTP/')) $location=null;
            if (stripos($line,'Location:')===0) $location=trim(substr($line,9));
            return strlen($line);
        },
        CURLOPT_WRITEFUNCTION=>function($ch,$chunk) use (&$body,&$bytes,&$stopped,$limit,$consumer) {
            $bytes+=strlen($chunk);
            if ($bytes>$limit) { $stopped=true; return 0; }
            if ($consumer!==null) {
                if (!$consumer($chunk)) { $stopped=true; return 0; }
            } else $body.=$chunk;
            return strlen($chunk);
        }
    ]);
    $ok=curl_exec($ch); $error=curl_error($ch); $errno=curl_errno($ch); $code=(int)curl_getinfo($ch,CURLINFO_HTTP_CODE); curl_close($ch);
    if ($ok===false && !($stopped && $errno===CURLE_WRITE_ERROR)) throw new HSNetworkError('Netværksfejl: '.$error,$errno);
    return ['code'=>$code,'location'=>$location,'body'=>$body,'truncated'=>$stopped,'empty'=>$bytes===0];
}
function hs_join(string $base,string $target): string {
    $target=trim($target);
    if ($target==='') throw new RuntimeException('Tom viderestilling');
    if (preg_match('/^[a-z][a-z0-9+.-]*:/i',$target)) return $target;
    $p=parse_url($base); $origin=$p['scheme'].'://'.$p['host'].(isset($p['port'])?':'.$p['port']:'');
    if (str_starts_with($target,'//')) return $p['scheme'].':'.$target;
    if ($target[0]==='#') return preg_replace('/#.*$/','',$base).$target;
    if ($target[0]==='?') return $origin.($p['path']??'/').$target;
    $path=$target[0]==='/'?$target:substr($p['path']??'/',0,strrpos($p['path']??'/','/')+1).$target;
    [$pathOnly,$suffix]=array_pad(preg_split('/(?=[?#])/',$path,2),2,'');
    $parts=[];
    foreach (explode('/',$pathOnly) as $part) { if ($part==='..') array_pop($parts); elseif ($part!=='.' && $part!=='') $parts[]=$part; }
    return $origin.'/'.implode('/',$parts).(str_ends_with($pathOnly,'/') && $parts?'/':'').$suffix;
}
function hs_outcome(string $domain,string $url,int $code): string {
    return hs_host(parse_url($url,PHP_URL_HOST)??'')!==hs_host($domain)?'review':($code>=400?'http_error':'ok');
}
function hs_options(mixed $limit=50, mixed $start='0'): array {
    $number=filter_var($limit,FILTER_VALIDATE_INT);
    if ($number===false || $number<1 || $number>10000) throw new InvalidArgumentException('Vælg mellem 1 og 10.000 domæner.');
    if (!is_string($start) || !preg_match('/^[0-9a-z]$/D',strtolower($start))) throw new InvalidArgumentException('Vælg ét starttegn: 0–9 eller A–Z.');
    return [$number,strtolower($start)];
}
function hs_start(PDO $db, mixed $limit=50, mixed $start='0'): void {
    [$limit,$start]=hs_options($limit,$start);
    hs_set($db,'target',(string)$limit); hs_set($db,'start_char',$start);
    hs_set($db,'next_page','0'); hs_set($db,'seek_steps','0'); hs_set($db,'discovery_pages','0'); hs_set($db,'retry_count','0'); hs_set($db,'retry_after','0');
    $db->exec("DELETE FROM results WHERE status='pending'");
    hs_set($db,'phase','metadata'); hs_set($db,'error',''); hs_set($db,'checked','0');
    hs_set($db,'index_attempt','0'); hs_set($db,'notice',''); hs_set($db,'running','1');
}
function hs_discover_response(array $response): array {
    if ($response['code']!==200 || $response['truncated']) throw new RuntimeException('Indeksoversigt kunne ikke hentes (HTTP '.$response['code'].')');
    $indexes=json_decode($response['body'],true,32,JSON_THROW_ON_ERROR); $out=[];
    foreach (array_slice($indexes,0,2) as $i) {
        if (!preg_match('~^https://index\.commoncrawl\.org/CC-MAIN-[0-9-]+-index$~D',$i['cdx-api']??'')) continue;
        $out[]=$i['cdx-api'];
    }
    if (!$out) throw new RuntimeException('Ingen gyldige Common Crawl-indekser');
    return $out;
}
function hs_extract_domain(array $record): ?string {
    $p=parse_url($record['url']??''); $host=hs_host($p['host']??'');
    if (!preg_match('/^[a-z0-9-]+\.dk$/D',$host) || !in_array($p['path']??'',['','/'],true) || !empty($p['query'])) return null;
    try { hs_url('https://'.$host.'/'); } catch (Throwable) { return null; }
    return $host;
}
function hs_tick(PDO $db, ?callable $fetch=null): void {
    if (hs_get($db,'running')!=='1') return;
    $fetch??=fn($url,$limit=65536,$consumer=null)=>hs_fetch($url,$limit,$consumer);
    $phase=hs_get($db,'phase');
    if (in_array($phase,['metadata','inventory','seek','discovery'],true)) {
        if ((int)hs_get($db,'retry_after','0')>time()) return;
        try { hs_discovery_tick($db,$fetch,$phase); hs_set($db,'retry_count','0'); hs_set($db,'retry_after','0'); if (str_starts_with(hs_get($db,'notice'),'Common Crawl svarer langsomt.')) hs_set($db,'notice',''); }
        catch (Throwable $e) {
            if ($db->inTransaction()) $db->rollBack();
            $retry=(int)hs_get($db,'retry_count','0');
            $transient=($e instanceof HSNetworkError && in_array($e->getCode(),[CURLE_OPERATION_TIMEDOUT,CURLE_COULDNT_CONNECT,CURLE_RECV_ERROR],true)) || preg_match('/HTTP (429|500|502|503|504)/',$e->getMessage());
            if ($transient && $retry<2) {
                hs_set($db,'retry_count',(string)($retry+1)); hs_set($db,'retry_after',(string)(time()+(2 << $retry)));
                hs_set($db,'notice','Common Crawl svarer langsomt. Prøver igen om lidt (forsøg '.($retry+2).' af 3).'); return;
            }
            hs_set($db,'retry_count','0'); hs_set($db,'retry_after','0');
            $selected=(int)$db->query("SELECT COUNT(*) FROM results WHERE status='pending'")->fetchColumn();
            $indexes=json_decode(hs_get($db,'indexes','[]'),true); $attempt=(int)hs_get($db,'index_attempt','0');
            if ($phase!=='metadata' && $selected===0 && $attempt+1<count($indexes)) {
                hs_set($db,'index_attempt',(string)($attempt+1)); hs_set($db,'next_page','0'); hs_set($db,'seek_steps','0');
                hs_set($db,'phase',hs_get($db,'start_char','0')==='0'?'discovery':'inventory');
                hs_set($db,'notice','Indekset svarede ikke som forventet; prøver det foregående.');
            } elseif ($selected>0) {
                hs_set($db,'phase','scan'); hs_set($db,'notice',"Fandt $selected af ".hs_get($db,'target','50').' ønskede domæner. Søgningen stoppede: '.substr($e->getMessage(),0,180));
            } else throw $e;
        }
        return;
    }
    $row=$db->query("SELECT * FROM results WHERE status='pending' ORDER BY domain LIMIT 1")->fetch();
    if (!$row) { hs_set($db,'running','0'); hs_set($db,'phase','done'); return; }
    $url=$row['current_url']; $status='pending'; $detail=''; $hops=(int)$row['hops']; $chain=json_decode($row['chain'],true);
    try {
        try { $r=$fetch($url,16384); }
        catch (Throwable $e) {
            if ($hops===0 && str_starts_with($url,'https://') && $e instanceof HSNetworkError && in_array($e->getCode(),[CURLE_COULDNT_CONNECT,CURLE_OPERATION_TIMEDOUT],true)) {
                $url='http://'.$row['domain'].'/'; $r=$fetch($url,16384);
            } else throw $e;
        }
        $chain[]=$url;
        if (in_array($r['code'],[301,302,303,307,308],true) && $r['location']!==null) {
            $next=hs_join($url,$r['location']); hs_url($next); $next=preg_replace('/#.*$/','',$next);
            if (in_array($next,$chain,true)) throw new RuntimeException('Viderestillingsløkke');
            if ($hops>=10) throw new RuntimeException('Mere end 10 viderestillinger');
            $url=$next; $hops++; $detail='HTTP '.$r['code'].' → næste hop';
        } else { $status=hs_outcome($row['domain'],$url,$r['code']); $detail='HTTP '.$r['code']; }
    } catch (Throwable $e) {
        $status='error'; $detail=substr($e->getMessage(),0,250);
        if (hs_host(parse_url($url,PHP_URL_HOST)??'')!==hs_host($row['domain'])) { $status='review'; $detail='Andet domæne fundet; slutdestination kunne ikke kontrolleres: '.$detail; }
    }
    $db->prepare('UPDATE results SET current_url=?,status=?,detail=?,hops=?,chain=?,checked_at=CURRENT_TIMESTAMP WHERE domain=?')->execute([$url,$status,$detail,$hops,json_encode($chain),$row['domain']]);
    if ($status!=='pending') hs_set($db,'checked',(string)((int)hs_get($db,'checked','0')+1));
}

// Seek a matching page via its first CDX record (the API's documented limit=1).
// Each browser/cron tick makes at most one index request, including the binary search.
function hs_discovery_tick(PDO $db,callable $fetch,string $phase): void {
    $start=hs_get($db,'start_char','0');
    if ($phase==='metadata') {
        $indexes=hs_discover_response($fetch('https://index.commoncrawl.org/collinfo.json',524288));
        hs_set($db,'indexes',json_encode($indexes)); hs_set($db,'phase',$start==='0'?'discovery':'inventory'); return;
    }
    $indexes=json_decode(hs_get($db,'indexes','[]'),true); $attempt=(int)hs_get($db,'index_attempt','0');
    $endpoint=$indexes[$attempt]??null;
    if (!$endpoint) throw new RuntimeException('Ingen tilgængelige indekser');
    if ($phase==='inventory') {
        $r=$fetch($endpoint.'?'.http_build_query(['url'=>'*.dk','showNumPages'=>'true','pageSize'=>1]),65536);
        $info=json_decode($r['body'],true);
        if ($r['code']!==200 || !is_array($info) || (int)($info['pages']??0)<1) throw new RuntimeException('Kunne ikke læse indeksstørrelsen (HTTP '.$r['code'].')');
        hs_set($db,'seek_low','0'); hs_set($db,'seek_high',(string)(int)$info['pages']); hs_set($db,'phase','seek'); return;
    }
    if ($phase==='seek') {
        $low=(int)hs_get($db,'seek_low'); $high=(int)hs_get($db,'seek_high');
        if ($low>=$high) { hs_set($db,'next_page',(string)max(0,$low-1)); hs_set($db,'phase','discovery'); return; }
        $steps=(int)hs_get($db,'seek_steps');
        if ($steps>=32) throw new RuntimeException('Startposition kunne ikke bestemmes');
        $mid=intdiv($low+$high,2);
        $r=$fetch($endpoint.'?'.http_build_query(['url'=>'*.dk','output'=>'json','pageSize'=>1,'page'=>$mid,'limit'=>1]),131072);
        $line=explode("\n",trim($r['body']))[0]; $json=json_decode($line,true);
        $key=is_array($json)?($json['urlkey']??$json['key']??''):preg_split('/\s+/',$line)[0];
        if ($r['code']!==200 || !is_string($key) || !str_starts_with($key,'dk,')) throw new RuntimeException('Startposition kunne ikke læses (HTTP '.$r['code'].')');
        if (strcmp($key,'dk,'.$start)<=0) $low=$mid+1; else $high=$mid;
        hs_set($db,'seek_low',(string)$low); hs_set($db,'seek_high',(string)$high); hs_set($db,'seek_steps',(string)($steps+1)); return;
    }
    $target=(int)hs_get($db,'target','50'); $selected=(int)$db->query("SELECT COUNT(*) FROM results WHERE status='pending'")->fetchColumn();
    $remaining=$target-$selected;
    if ($remaining<=0) { hs_set($db,'phase','scan'); return; }
    $page=(int)hs_get($db,'next_page','0');
    $pages=(int)hs_get($db,'discovery_pages','0');
    if ($pages>=100) throw new RuntimeException('Søgegrænsen på 100 indekssider er nået');
    $url=$endpoint.'?'.http_build_query(['url'=>'*.dk','output'=>'json','pageSize'=>1,'page'=>$page]);
    $buffer=''; $found=[];
    $exists=$db->prepare("SELECT 1 FROM results WHERE domain=? AND status='pending'");
    $add=function($r) use (&$found,$start,$exists) {
        if (!is_array($r) || ($d=hs_extract_domain($r))===null || strcmp($d[0],$start)<0) return;
        $exists->execute([$d]); if (!$exists->fetchColumn()) $found[$d]=true;
    };
    $consume=function($chunk) use (&$buffer,&$found,$remaining,$add) {
        $buffer.=$chunk; if (strlen($buffer)>1048576) return false;
        while (($pos=strpos($buffer,"\n"))!==false) {
            $line=substr($buffer,0,$pos); $buffer=substr($buffer,$pos+1); $add(json_decode($line,true));
            if (count($found)>=$remaining) return false;
        }
        return true;
    };
    $r=$fetch($url,8000000,$consume);
    if ($r['code']!==200) throw new RuntimeException('Common Crawl-søgning fejlede (HTTP '.$r['code'].')');
    if ($buffer!=='' && count($found)<$remaining) $add(json_decode($buffer,true));
    // A completely empty page means there are no more blocks; a page without
    // matching homepages can still be followed by useful blocks.
    if (!$found && $r['body']==='' && !$r['truncated'] && ($r['empty']??false)) throw new RuntimeException('Ingen flere domæner i indekset');
    $q=$db->prepare("INSERT OR REPLACE INTO results(domain,current_url,status) VALUES(?,?,'pending')");
    $db->beginTransaction();
    foreach (array_slice(array_keys($found),0,$remaining) as $domain) $q->execute([$domain,'https://'.$domain.'/']);
    $selected+=(int)count($found);
    hs_set($db,'next_page',(string)($page+1)); hs_set($db,'discovery_pages',(string)($pages+1));
    hs_set($db,'phase',$selected>=$target?'scan':'discovery'); hs_set($db,'source',$endpoint);
    hs_set($db,'notice',$selected<$target?"Finder domæner: $selected af $target …":'');
    $db->commit();
}

function hs_groups(PDO $db,string $search,array $params=[]): array {
    $groups=[];
    foreach (['all'=>'1=1','review'=>"status='review'",'ok'=>"status='ok'",'errors'=>"status IN ('error','http_error')"] as $key=>$where) {
        $args=[];
        if ($search!=='') {
            $where.=" AND (domain LIKE ? ESCAPE '\\' OR current_url LIKE ? ESCAPE '\\' OR detail LIKE ? ESCAPE '\\')";
            $term='%'.str_replace(['\\','%','_'],['\\\\','\\%','\\_'],$search).'%'; $args=[$term,$term,$term];
        }
        $q=$db->prepare('SELECT COUNT(*) FROM results WHERE '.$where); $q->execute($args); $total=(int)$q->fetchColumn();
        $raw=$params['page_'.$key]??0; $requested=is_scalar($raw)?max(0,min(1000000,(int)$raw)):0;
        $page=min($requested,max(0,(int)ceil($total/8)-1));
        $q=$db->prepare('SELECT * FROM results WHERE '.$where.' ORDER BY checked_at DESC,domain LIMIT 8 OFFSET '.($page*8)); $q->execute($args);
        $groups[$key]=['rows'=>$q->fetchAll(),'total'=>$total,'page'=>$page,'pages'=>(int)ceil($total/8)];
    }
    return $groups;
}

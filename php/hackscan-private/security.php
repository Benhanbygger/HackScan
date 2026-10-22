<?php
declare(strict_types=1);

function hs_security_schema(PDO $db): void {
    $db->exec('CREATE TABLE IF NOT EXISTS reports (domain TEXT PRIMARY KEY, report TEXT NOT NULL, score INTEGER, grade TEXT, assessed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)');
    $db->exec('CREATE INDEX IF NOT EXISTS reports_score ON reports(score)');
    $db->exec('CREATE TABLE IF NOT EXISTS security_jobs (job_key TEXT PRIMARY KEY, kind TEXT NOT NULL, domain TEXT NOT NULL DEFAULT \'\')');
    $db->exec('CREATE TABLE IF NOT EXISTS intel (kind TEXT PRIMARY KEY, payload TEXT NOT NULL DEFAULT \'\', fetched_at INTEGER NOT NULL DEFAULT 0, attempted_at INTEGER NOT NULL DEFAULT 0, error TEXT NOT NULL DEFAULT \'\')');
    $db->exec('CREATE TABLE IF NOT EXISTS security_history (id INTEGER PRIMARY KEY AUTOINCREMENT, domain TEXT NOT NULL, score INTEGER, grade TEXT, snapshot TEXT NOT NULL, assessed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)');
    $db->exec('CREATE INDEX IF NOT EXISTS security_history_domain ON security_history(domain,id)');
}
function hs_controls(): array {
    // [title, class, maximum severity, reason when not performed]
    $risk='risk'; $vuln='vulnerability'; $ioc='indicator';
    return [
        'php_eol'=>['Forældet PHP-version',$risk,'critical','PHP-versionen oplyses ikke pålideligt. En skjult header er ikke bevis på fravær af PHP.'],
        'php_cve'=>['Kendte kritiske PHP-sårbarheder',$vuln,'critical','Kræver verificeret produkt/build og en kilde med berørte versionsintervaller. Headeren alene beviser ikke CVE-anvendelighed eller backport-status.'],
        'wordpress'=>['Forældet WordPress-version',$risk,'high','Kræver offentligt versionsspor og aktuelle officielle versionsdata.'],
        'plugins'=>['Sårbare WordPress-plugins',$vuln,'critical','Plugin-navne fra assets er kun teknologispor. Ingen komplet, verificeret plugin/version/advisory-database er tilsluttet.'],
        'themes'=>['Forældede WordPress-themes',$risk,'high','Theme-spor kan registreres, men versions- og supportdata mangler.'],
        'server'=>['Forældet webserver',$risk,'high','Server-headeren kan være skjult, ændret eller have sikkerhedsrettelser tilbageporteret. Leverandørens supportstatus er ikke verificeret.'],
        'javascript'=>['Forældede JavaScript-biblioteker',$risk,'medium','Kun kendte versionsspor for jQuery og Lodash kan sammenholdes med de medfølgende advisories. Fravær af spor er ikke en bestået kontrol.'],
        'js_cve'=>['Kendte JavaScript-sårbarheder',$vuln,'high','Kræver konkret versionsspor, der matcher et dokumenteret berørt interval. Udnyttelighed testes ikke.'],
        'kev'=>['Kendte aktivt udnyttede CVE’er',$vuln,'critical','CISA KEV kan kun sammenholdes med konkrete CVE-kandidater; ingen generel CPE-identifikation foretages.'],
        'redirect'=>['Viderestilling til andet / mistænkeligt domæne',$ioc,'critical','Et domæneskift alene beviser ikke en mistænkelig destination. Ingen omdømmetjeneste er tilsluttet.'],
        'script_redirect'=>['JavaScript- og meta-refresh-viderestillinger',$ioc,'critical','Kun simple offentlige meta-refresh og bogstavelige JavaScript-adresser genkendes; ingen browserkode afvikles.'],
        'malware'=>['Malware i HTML eller JavaScript',$ioc,'critical','Ingen valideret malware-signaturmotor er tilsluttet. Obfuskering eller eval alene er ikke malwarebevis.'],
        'phishing'=>['Phishing eller falsk login',$ioc,'critical','Loginformularer kan kortlægges, men ejerskab, SSO og brandmisbrug kan ikke afgøres sikkert.'],
        'spam'=>['SEO-spam og skjulte links',$ioc,'high','Kun kombinationer af tydeligt skjulte eksterne links og spamord undersøges; CSS og indholdets legitime formål er ikke fuldt kendt.'],
        'scripts'=>['Mistænkelige eksterne scripts',$ioc,'high','Tredjepartsressourcer kortlægges; skadelig omdømmestatus er ikke kendt.'],
        'threat_lists'=>['Safe Browsing og trusselslister',$ioc,'high','Ingen ekstern trusselsliste/API er konfigureret. Ingen scannede URL’er sendes til en tredjeparts-API.'],
        'content_change'=>['Uventede ændringer på forsiden',$ioc,'high','Kræver en tidligere sammenlignelig scanning. Ændringer kan være legitime og medfører ikke i sig selv pointfradrag.'],
        'iframes'=>['Mistænkelige iframes',$ioc,'high','Kun offentlige indlejringers domæne og eksplicit skjult attribut undersøges.'],
        'webshell'=>['Webshell-signaturer',$ioc,'critical','Intern kontrol: kræver autoriseret filadgang til serveren. Ikke udført på automatisk fundne domæner.'],
        'backups'=>['Offentlige backupfiler',$vuln,'critical','Ekstra stiopslag er ikke aktiveret på andres domæner. Kræver et særskilt autoriseret scanningsomfang.'],
        'config'=>['Eksponerede miljø- og konfigurationsfiler',$vuln,'critical','Ingen hemmelige filer hentes eller sonderes. Kræver særskilt tilladelse og en sikker, afgrænset test.'],
        'git'=>['Offentlige Git-metadata',$vuln,'high','Ingen ekstra repository-stier sonderes på automatisk fundne hjemmesider.'],
        'listing'=>['Directory listing',$risk,'high','Kun en mappeliste i det normalt hentede forsidesvar kan registreres. Ingen mappesøgning foretages.'],
        'errors'=>['PHP-fejl og stack traces',$risk,'medium','Undersøges kun i normalt indlæst HTML, uden at fremprovokere fejl.'],
        'debug'=>['Test- og debugmiljøer',$risk,'high','Ingen subdomæneopdagelse eller test af ekstra debug-stier er aktiveret.'],
        'admin'=>['Eksponerede databaser og administration',$risk,'critical','Ingen portscanning, loginforsøg eller sondering af administrationsstier på andres domæner.'],
        'tls'=>['Ugyldigt eller udløbet TLS-certifikat',$risk,'high','Afhænger af en vellykket verificeret TLS-forbindelse eller en konkret certifikatfejl; lokale tillidsproblemer kan påvirke resultatet.'],
        'https'=>['Manglende HTTPS / nedgradering til HTTP',$risk,'high','HTTPS forsøges først; en timeout alene beviser ikke, at HTTPS mangler.'],
        'old_tls'=>['Forældede TLS-protokoller',$risk,'high','En moderne TLS-forbindelse afslører ikke, om gamle protokoller også accepteres. Ekstra handshake-tests er ikke udført.'],
        'hsts'=>['Manglende HSTS',$risk,'medium','Vurderes på det faktisk hentede HTTPS-svar.'],
        'csp'=>['Manglende CSP',$risk,'medium','Header og HTML-meta undersøges. Tilstedeværelse er ikke en fuld kvalitetstest af politikken.'],
        'frames'=>['Manglende clickjacking-beskyttelse',$risk,'medium','X-Frame-Options eller CSP frame-ancestors undersøges.'],
        'cookies'=>['Usikre cookie-indstillinger',$risk,'medium','Kun serverens Set-Cookie-attributter kontrolleres. Cookieværdier og JavaScript-cookies gemmes ikke.'],
        'mixed'=>['Mixed content',$risk,'medium','Kun eksplicitte HTTP-adresser i HTML-ressourcer på HTTPS-forsider genkendes. Ingen ressourcer afvikles.'],
        'headers'=>['Eksponerede teknologiversioner',$risk,'low','Server og X-Powered-By undersøges; informationsdeling er ikke i sig selv en sårbarhed.'],
        'cors'=>['Potentielt usikker CORS-konfiguration',$risk,'medium','Kun det normale svar undersøges; ingen Origin-injektion eller udnyttelsesforsøg.'],
        'spf'=>['Manglende SPF',$risk,'medium','Offentlig TXT-forespørgsel; tilstedeværelse er ikke fuld validering af SPF-kæde og lookup-grænse.'],
        'dmarc'=>['Manglende DMARC',$risk,'medium','Offentlig TXT-forespørgsel til _dmarc. Ingen falske e-mails sendes.'],
        'dmarc_policy'=>['Svag / overvågende DMARC-politik',$risk,'medium','p=none er overvågning, ikke bevis på en sårbarhed. Skærp kun politikken efter kontrol af legitime afsendere.'],
        'dnssec'=>['Manglende DNSSEC',$risk,'low','En almindelig DNS-forespørgsel kan ikke dokumentere en valideret DNSSEC-kæde. Kontrollen er ikke udført.'],
        'takeover'=>['Potentiel subdomain takeover',$vuln,'high','Kræver DNS- og tjenestespecifikke beviser; ingen subdomænesondering eller overtagelsesforsøg udføres.'],
        'dns_change'=>['Mistænkelige DNS-ændringer',$ioc,'high','Adresser sammenlignes over tid; ændringer alene scores ikke som kompromittering.'],
        'cert_change'=>['Certifikatændringer',$risk,'medium','SHA-256-fingeraftryk sammenlignes over tid. Normal certifikatfornyelse er ikke et sikkerhedsfund.'],
        'hosting_change'=>['Udbyder- eller hosting-skift',$risk,'low','IP-ændringer kan observeres, men ASN-/udbyderdata og ejerskab er ikke verificeret.'],
        'defacement'=>['Mulig defacement',$ioc,'high','Synlig tekst undersøges for et konkret “hacked by”-spor. Artikler og citater kan give samme signal.'],
    ];
}
function hs_new_report(string $domain,string $url): array {
    $controls=[];
    foreach (hs_controls() as $id=>$rule) $controls[$id]=['id'=>$id,'title'=>$rule[0],'class'=>$rule[1],'severity'=>$rule[2],'state'=>'not_tested','confidence'=>'none','evidence'=>$rule[3],'recommendation'=>'','source'=>''];
    return ['version'=>HS_VERSION,'domain'=>$domain,'url'=>$url,'complete'=>false,'http_accessible'=>false,'controls'=>$controls,'snapshot'=>[],'previous'=>null,'technologies'=>[],'resources'=>[],'cves'=>[],'limitations'=>['Kun offentlige svar: ingen udnyttelsesforsøg, loginforsøg, portscanning eller ekstra filstier.','JavaScript afvikles ikke. Fravær af fund er ikke bevis på en sikker hjemmeside.']];
}
function hs_check(array &$report,string $id,string $state,string $evidence,string $recommendation='',string $confidence='high',?string $severity=null,string $source=''): void {
    $c=&$report['controls'][$id]; $c['state']=$state; $c['evidence']=substr($evidence,0,1200); $c['recommendation']=$recommendation; $c['confidence']=in_array($state,['unknown','not_tested'],true)?'none':$confidence; $c['source']=$source;
    if ($severity!==null) $c['severity']=$severity;
}
function hs_safe_url(string $url): string {
    $p=parse_url($url); if (!$p || !isset($p['host'])) return substr(preg_replace('/[?#].*$/','',$url),0,300);
    return substr(($p['scheme']??'https').'://'.$p['host'].($p['path']??'/'),0,300);
}
function hs_attrs(string $tag): array {
    preg_match_all('/([a-zA-Z_:][a-zA-Z0-9_:.-]*)\s*=\s*(?:"([^"]*)"|\x27([^\x27]*)\x27|([^\s>]+))/s',$tag,$m,PREG_SET_ORDER|PREG_UNMATCHED_AS_NULL);
    $a=[]; foreach ($m as $v) $a[strtolower($v[1])]=html_entity_decode($v[2]??$v[3]??$v[4]??'',ENT_QUOTES|ENT_HTML5,'UTF-8');
    return $a;
}
function hs_php_eol(string $version,string $today): ?bool {
    $dates=['5'=>'2019-01-01','7'=>'2022-11-28','8.0'=>'2023-11-26','8.1'=>'2025-12-31','8.2'=>'2026-12-31','8.3'=>'2027-12-31','8.4'=>'2028-12-31','8.5'=>'2029-12-31'];
    $parts=explode('.',$version); $branch=$parts[0].'.'.($parts[1]??'0'); $date=$dates[$branch]??$dates[$parts[0]]??null;
    return $date===null?null:$today>$date;
}
function hs_analyze(string $domain,string $url,array $response,array $chain=[],?array $previous=null): array {
    $r=hs_new_report($domain,hs_safe_url($url)); $r['previous']=$previous;
    $headers=$response['headers']??[]; $code=(int)$response['code'];
    if ($code<200 || $code>=300) { $r['limitations'][]='HTTP '.$code.': HTML-sikkerhedskontroller er ikke vurderet som beståede.'; return $r; }
    $r['http_accessible']=true;
    $https=str_starts_with($url,'https://');
    $get=fn($name)=>implode(', ',$headers[$name]??[]);
    $body=$response['body']; $type=strtolower($get('content-type'));
    $html=str_contains($type,'html') || ($type==='' && preg_match('/<(?:!doctype\s+html|html|head|body)\b/i',substr($body,0,1000)));
    $r['snapshot']['url']=hs_safe_url($url);
    hs_check($r,'https',$https?'pass':'finding',$https?'Det hentede slutmål bruger HTTPS. HTTP til HTTPS-redirect på startadressen er ikke særskilt verificeret.':'Slutmålet leveres over ukrypteret HTTP.','Brug HTTPS på alle sider, og viderestil HTTP til HTTPS.',$https?'high':'medium');
    if ($https) hs_check($r,'tls','pass','cURL accepterede certifikatkæden og værtsnavnet med TLS-verifikation slået til.');
    $tls=$response['tls']??[]; if ($https && $tls) $r['snapshot']['certificate']=$tls;
    $csp=$get('content-security-policy'); $metaCsp='';
    $tags=[]; if ($html) { preg_match_all('/<(?:script|link|iframe|img|form|meta)\b[^>]{0,8192}>/is',$body,$tags); }
    $scripts=[]; $iframes=[]; $mixed=[]; $redirects=[]; $externalForms=[]; $wpVersion=null; $libraries=[]; $pluginNames=[]; $themeNames=[];
    foreach ($tags[0]??[] as $tag) {
        preg_match('/^<([a-z]+)/i',$tag,$tm); $name=strtolower($tm[1]); $a=hs_attrs($tag);
        if ($name==='meta') {
            if (strtolower($a['http-equiv']??'')==='content-security-policy') $metaCsp=$a['content']??'';
            if (strtolower($a['name']??'')==='generator' && preg_match('/^WordPress\s+(\d+\.\d+(?:\.\d+)?)/i',$a['content']??'',$v)) $wpVersion=$v[1];
            if (strtolower($a['http-equiv']??'')==='refresh' && preg_match('/url\s*=\s*[\x27"]?([^\x27"]+)/i',$a['content']??'',$v)) { try {$redirects[]=hs_join($url,trim($v[1]));}catch(Throwable){} }
        }
        $asset=$a['src']??($a['href']??'');
        if ($asset!=='') {
            try {$full=hs_join($url,$asset);}catch(Throwable){continue;}
            $host=parse_url($full,PHP_URL_HOST)??''; $external=$host!=='' && hs_host($host)!==hs_host(parse_url($url,PHP_URL_HOST)??'');
            if ($https && str_starts_with($full,'http://') && in_array($name,['script','iframe','img','link'],true)) $mixed[]=hs_safe_url($full);
            if ($name==='script') $scripts[]=hs_safe_url($full);
            if ($name==='iframe' && $external) $iframes[]=['url'=>hs_safe_url($full),'hidden'=>preg_match('/display\s*:\s*none|visibility\s*:\s*hidden|(?:width|height)\s*:\s*0/i',$a['style']??'')===1 || ($a['width']??'')==='0' || ($a['height']??'')==='0'];
            if (preg_match('~/wp-content/plugins/([a-z0-9_-]+)/~i',$full,$v)) $pluginNames[$v[1]]=true;
            if (preg_match('~/wp-content/themes/([a-z0-9_-]+)/~i',$full,$v)) $themeNames[$v[1]]=true;
            foreach (['jquery','lodash'] as $lib) {
                $version=null;
                if (preg_match('~'.preg_quote($lib,'~').'(?:@|[-/])v?(\d+\.\d+\.\d+)(?:[/.-]|$)~i',$full,$v)) $version=$v[1];
                elseif (preg_match('~'.preg_quote($lib,'~').'(?:\.min)?\.js(?:\?|$)~i',$full) && preg_match('/[?&](?:ver|version)=(\d+\.\d+\.\d+)(?:&|$)/i',$full,$v)) $version=$v[1];
                if ($version!==null) $libraries[$lib]=['version'=>$version,'evidence'=>hs_safe_url($full),'confidence'=>'medium'];
            }
        }
        if ($name==='form' && !empty($a['action'])) {
            try {$action=hs_join($url,$a['action']); if (hs_host(parse_url($action,PHP_URL_HOST)??'')!==hs_host(parse_url($url,PHP_URL_HOST)??'')) $externalForms[]=hs_safe_url($action);}catch(Throwable){}
        }
    }
    if ($metaCsp!=='') hs_check($r,'csp','observed','CSP findes som HTML-meta; direktiver og placering er ikke fuldt valideret.','Foretræk en gennemarbejdet CSP som HTTP-header.','medium');
    else hs_check($r,'csp',$csp!==''?'pass':'finding',$csp!==''?'Content-Security-Policy findes som HTTP-header; styrken er ikke fuldt valideret.':'Ingen Content-Security-Policy-header eller genkendt HTML-meta.','Indfør en testet CSP, gerne først i Report-Only-tilstand.');
    $hsts=$get('strict-transport-security');
    if ($https) hs_check($r,'hsts',preg_match('/max-age\s*=\s*[1-9][0-9]*/i',$hsts)?'pass':'finding',$hsts!==''?'Oplyst HSTS: '.substr($hsts,0,200):'HSTS mangler i det hentede HTTPS-svar.','Aktivér HSTS efter kontrol af HTTPS-dækningen; brug ikke includeSubDomains blindt.');
    else hs_check($r,'hsts','not_applicable','HSTS kan kun accepteres over HTTPS.');
    $xfo=strtoupper(trim($get('x-frame-options')));
    $framed=in_array($xfo,['DENY','SAMEORIGIN'],true) || preg_match("/(?:^|;)\\s*frame-ancestors\\s+(?:'none'|'self')\\s*(?:;|$)/i",$csp);
    hs_check($r,'frames',$framed?'pass':'finding',$framed?'Enforced frame-ancestors eller X-Frame-Options registreret; CSP-kildelisten er ikke fuldt valideret.':'Ingen genkendt enforced frame-ancestors eller X-Frame-Options.','Begræns indlejring med CSP frame-ancestors, hvis siden ikke skal kunne indlejres.');
    $cookieProblems=[]; $cookieCount=0;
    foreach ($headers['set-cookie']??[] as $cookie) {
        $parts=explode(';',$cookie); $cookieName=trim(explode('=',array_shift($parts),2)[0]); $attrs=strtolower(implode(';',$parts)); $missing=[]; $cookieCount++;
        if ($https && !preg_match('/(?:^|;)\s*secure(?:;|$)/',$attrs)) $missing[]='Secure';
        if (!preg_match('/(?:^|;)\s*httponly(?:;|$)/',$attrs)) $missing[]='HttpOnly';
        if (!preg_match('/(?:^|;)\s*samesite\s*=\s*(?:strict|lax|none)(?:;|$)/',$attrs)) $missing[]='SameSite';
        if ($missing) $cookieProblems[]=substr($cookieName,0,70).': '.implode(', ',$missing).' mangler';
    }
    hs_check($r,'cookies',$cookieProblems?'finding':($cookieCount?'pass':'not_applicable'),$cookieProblems?implode('; ',array_slice($cookieProblems,0,8)):($cookieCount?'Attributter fundet på serverens cookies.':'Ingen Set-Cookie observeret; JavaScript-cookies er ikke undersøgt.'),'Vurder cookies efter formål. Sessionscookies bør normalt have Secure og HttpOnly; SameSite skal passe til loginflow.','medium');
    $powered=$get('x-powered-by'); $server=$get('server');
    hs_check($r,'php_eol','unknown','Ingen pålidelig PHP-version oplyst i det observerede svar. Det betyder ikke, at hjemmesiden ikke bruger PHP.');
    if (preg_match('/\bPHP\/(\d+\.\d+(?:\.\d+)?)/i',$powered,$v)) {
        $version=$v[1]; $r['technologies']['php']=['version'=>$version,'confidence'=>'low','source'=>'X-Powered-By'];
        $eol=hs_php_eol($version,gmdate('Y-m-d'));
        hs_check($r,'php_eol',$eol===null?'unknown':($eol?'finding':'observed'),'Headeren oplyser PHP '.$version.'. '.($eol===null?'Supportstatus er ikke kendt.':($eol?'Den officielle branches sikkerhedssupport er udløbet.':'Branchens officielle sikkerhedssupport er ikke udløbet; patchniveau og backports er ikke verificeret.')),'Verificér den faktiske version i hostingpanelet og opgradér til en understøttet, opdateret PHP-version.','low',null,'https://www.php.net/supported-versions.php');
    }
    hs_check($r,'headers',preg_match('/\d+\.\d+/',$powered.' '.$server)?'finding':($powered.$server!==''?'observed':'pass'),$powered.$server!==''?'Offentlige teknologispor: '.substr($powered.' '.$server,0,200):'Ingen Server- eller X-Powered-By-header observeret.','Undlad unødvendige versionsoplysninger; skjulte headers erstatter ikke opdateringer.','high');
    if ($server!=='') $r['technologies']['server']=['signature'=>substr($server,0,150),'confidence'=>'low'];
    $acao=trim($get('access-control-allow-origin')); $acac=strtolower(trim($get('access-control-allow-credentials')));
    if ($acao==='*' && $acac==='true') hs_check($r,'cors','observed','ACAO=* og credentials=true er observeret. Browsere afviser denne kombination for credentialed læsning; dette beviser ikke en dataeksponering.','Begræns origins efter behov, og gennemgå CORS på følsomme API-svar.','medium');
    else hs_check($r,'cors','unknown',$acao!==''?'Oplyst origin: '.substr($acao,0,150).'. Refleksion og følsomme endpoints er ikke testet.':'Ingen CORS-header i det normale forsidesvar. Ingen aktive Origin-tests udført.');
    if (hs_host(parse_url($url,PHP_URL_HOST)??'')!==hs_host($domain)) hs_check($r,'redirect','observed','Forsiden endte på '.hs_safe_url($url).'. Skadelighed eller ejerskifte er ikke afgjort.','Kontrollér at destinationen er tilsigtet, og undersøg en eventuel uventet ændring.','low','high');
    else hs_check($r,'redirect','observed','Intet slutdomæneskift observeret i HTTP-kæden. Domæneomdømme er ikke undersøgt.');
    if (!$html) { foreach (['csp','frames'] as $id) hs_check($r,$id,'not_applicable','Svaret er ikke HTML. Denne HTML-beskyttelse er ikke vurderet.'); $r['limitations'][]='Svaret blev ikke identificeret som HTML; HTML-kontroller er ikke udført.'; return $r; }
    if ($response['truncated']??false) $r['limitations'][]='HTML-svaret blev afkortet ved 256 KB. Fund i resten af dokumentet kan være overset.';
    preg_match('/<title\b[^>]*>(.*?)<\/title>/is',$body,$tm);
    $title=substr(trim(html_entity_decode(strip_tags($tm[1]??''),ENT_QUOTES|ENT_HTML5,'UTF-8')),0,180);
    $visible=preg_replace('~<(script|style|noscript)\b[^>]*>.*?</\1>~is',' ',$body);
    $visible=trim(preg_replace('/\s+/u',' ',html_entity_decode(strip_tags($visible??''),ENT_QUOTES|ENT_HTML5,'UTF-8'))??'');
    $r['snapshot']['title']=$title; $r['snapshot']['text_hash']=hash('sha256',$visible);
    $r['snapshot']['text_length']=strlen($visible); $r['snapshot']['script_hosts']=array_values(array_unique(array_map(fn($u)=>parse_url($u,PHP_URL_HOST),$scripts)));
    $r['resources']=array_slice(array_unique($scripts),0,30);
    $r['technologies']['javascript']=$libraries; $r['technologies']['plugins']=array_keys($pluginNames); $r['technologies']['themes']=array_keys($themeNames);
    if ($wpVersion!==null) $r['technologies']['wordpress']=['version'=>$wpVersion,'confidence'=>'medium','source'=>'HTML generator'];
    preg_match_all('~<script\b[^>]*>(.*?)</script>~is',$body,$inlineBlocks); $inline=implode("\n",$inlineBlocks[1]??[]);
    preg_match_all('~(?:window\.)?location(?:\.href)?\s*=\s*[\x27"]([^\x27"]+)[\x27"]|location\.(?:replace|assign)\(\s*[\x27"]([^\x27"]+)[\x27"]\s*\)~i',$inline,$js,PREG_SET_ORDER);
    foreach ($js as $v) { try {$redirects[]=hs_join($url,$v[1]!==''?$v[1]:($v[2]??''));}catch(Throwable){} }
    $outside=[]; foreach ($redirects as $dest) if (hs_host(parse_url($dest,PHP_URL_HOST)??'')!==hs_host(parse_url($url,PHP_URL_HOST)??'')) $outside[]=hs_safe_url($dest);
    hs_check($r,'script_redirect',$outside?'finding':'unknown',$outside?'Mulig klient-viderestilling til '.implode(', ',array_slice(array_unique($outside),0,3)).'. Koden er ikke afviklet; spor kan være betingede eller inaktive.':'Ingen simpel ekstern klient-viderestilling genkendt; dynamiske scripts og alle betingelser er ikke testet.','Verificér destinationsadressen og fjern uautoriserede redirect-scripts.','low','high');
    hs_check($r,'mixed',!$https?'not_applicable':($mixed?'finding':'pass'),$mixed?'HTTP-ressourcer på HTTPS-side: '.implode(', ',array_slice(array_unique($mixed),0,5)):'Ingen eksplicitte HTTP-ressourcer genkendt i det analyserede HTML-udsnit. Dynamiske ressourcer er ikke med.','Brug HTTPS for alle indlæste ressourcer.');
    $hiddenIframes=array_filter($iframes,fn($v)=>$v['hidden']);
    hs_check($r,'iframes',$hiddenIframes?'finding':'observed',$hiddenIframes?'Eksplicit skjulte eksterne iframes: '.implode(', ',array_column($hiddenIframes,'url')):count($iframes).' eksterne iframes observeret. Omdømme og formål er ikke afgjort.','Kontrollér ejerskab og formål med indlejringer; fjern uautoriserede iframes.','low');
    hs_check($r,'scripts','observed',count($scripts).' scriptressourcer kortlagt; deres omdømme og indhold er ikke verificeret.','Gennemgå leverandører og behov. Begræns scripts med CSP og eventuelt SRI.','medium');
    if ($externalForms && preg_match('/<input\b[^>]*type\s*=\s*[\x27"]?password/i',$body)) hs_check($r,'phishing','observed','Loginformular og formularmål på andet domæne: '.implode(', ',array_slice($externalForms,0,3)).'. Kan være legitim SSO; phishing er ikke fastslået.','Kontrollér at loginudbyderen er autoriseret.','low');
    $hiddenSpam=0;
    preg_match_all('~<a\b([^>]*)>(.*?)</a>~is',$body,$links,PREG_SET_ORDER);
    foreach ($links as $link) {
        $a=hs_attrs($link[1]);
        if (preg_match('/display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0/i',$a['style']??'') && preg_match('/casino|viagra|cialis|payday|slots/i',strip_tags($link[2]))) {
            try {$dest=hs_join($url,$a['href']??''); if (hs_host(parse_url($dest,PHP_URL_HOST)??'')!==hs_host(parse_url($url,PHP_URL_HOST)??'')) $hiddenSpam++;}catch(Throwable){}
        }
    }
    hs_check($r,'spam',$hiddenSpam>=3?'finding':'unknown',$hiddenSpam>=3?$hiddenSpam.' eksplicit skjulte eksterne links med spamrelateret linktekst. Legitimitet er ikke afgjort.':'Ingen stærk kombination af skjulte eksterne links og spamord genkendt. Dette udelukker ikke SEO-spam.','Undersøg de skjulte links og fjern kun uautoriseret indhold.','low');
    hs_check($r,'defacement',preg_match('/\bhacked\s+by\s+[a-z0-9_@-]{2,}/i',$visible,$hit)?'finding':'unknown',isset($hit[0])?'Tekstspor i HTML: '.substr($hit[0],0,120).'. Kan være et citat eller en artikel.':'Intet konkret “hacked by”-spor genkendt i det analyserede tekstudsnit.','Kontrollér forsideændringen og verificér indholdets legitimitet.','low');
    $listing=preg_match('/^Index of\s*\//i',$title) && preg_match('/Parent Directory|<table/i',$body);
    hs_check($r,'listing',$listing?'finding':'observed',$listing?'Forsiden ligner en offentligt tilgængelig mappeliste. Ingen ekstra stier eller filer er undersøgt.':'Forsiden ligner ikke en genkendt mappeliste. Andre mapper er ikke testet.','Slå automatisk mappeliste fra, hvis filerne ikke bevidst skal offentliggøres.','medium');
    $trace=preg_match('/(?:Fatal error|Warning):\s.*?(?:\.php\b|on line\s+\d+)|Traceback \(most recent call last\)|Stack trace:/is',$visible);
    hs_check($r,'errors',$trace?'finding':'pass',$trace?'En genkendt fejl-/stacktrace-markør findes i forsidesvaret. Hele fejlen og eventuelle hemmeligheder gemmes ikke.':'Ingen genkendte fejlmarkører i det analyserede HTML-udsnit.','Slå display_errors fra i produktion, log privat, og ret den underliggende fejl.','medium');
    return $r;
}
function hs_apply_intel(array &$r,PDO $db): void {
    $q=$db->query('SELECT * FROM intel'); $intel=[]; foreach ($q as $row) $intel[$row['kind']]=$row;
    $wp=$r['technologies']['wordpress']['version']??null;
    if ($wp!==null) {
        $data=$intel['wordpress']??null; $latest=$data?json_decode($data['payload'],true):null;
        if ($latest && $data['fetched_at']>time()-604800) {
            $older=version_compare($wp,$latest['version'],'<');
            hs_check($r,'wordpress',$older?'finding':'observed','Offentligt generator-spor: '.$wp.'. Officiel aktuel version: '.$latest['version'].'. Ældre hovedgrene kan have sikkerheds-backports; en CVE er ikke påvist.','Verificér versionen i WordPress og planlæg en kompatibilitetstestet opdatering.','medium',null,'https://api.wordpress.org/core/version-check/1.7/');
        } else hs_check($r,'wordpress','unknown','WordPress-spor '.$wp.' fundet, men aktuelle officielle versionsdata kunne ikke hentes.');
    }
    $libraries=$r['technologies']['javascript']??[]; $cves=[]; $old=[];
    foreach ($libraries as $lib=>$meta) {
        $v=$meta['version'];
        if ($lib==='jquery' && version_compare($v,'1.2','>=') && version_compare($v,'3.5.0','<')) { $old[]='jQuery '.$v; $cves[]='CVE-2020-11022'; }
        if ($lib==='jquery' && version_compare($v,'1.0.3','>=') && version_compare($v,'3.5.0','<')) { $cves[]='CVE-2020-11023'; }
        if ($lib==='lodash' && version_compare($v,'4.0.0','>=') && version_compare($v,'4.17.21','<')) { $old[]='Lodash '.$v; $cves[]='CVE-2021-23337'; }
    }
    $r['cves']=array_values(array_unique($cves));
    if ($old) {
        hs_check($r,'javascript','finding','Versionsspor i assetadresser: '.implode(', ',array_unique($old)).'. Filindhold og faktisk brug er ikke verificeret.','Opdatér biblioteket til en aktuel kompatibel version og gennemgå afhængigheder.','medium');
        hs_check($r,'js_cve','finding','Potentielle versionsmatch: '.implode(', ',$r['cves']).'. Versionsspor kan være cachemarkører; nødvendig programadfærd og udnyttelighed er ikke verificeret.','Verificér den faktisk indlæste biblioteksversion og gennemgå de relevante advisories.','medium','medium','https://nvd.nist.gov/vuln/detail/'.$r['cves'][0]);
    } elseif ($libraries) hs_check($r,'javascript','observed','Genkendte versionsspor matcher ikke de få medfølgende jQuery-/Lodash-intervaller. Andre biblioteker og CVE’er er ikke dækket.');
    $kev=$intel['kev']??null; $data=$kev?json_decode($kev['payload'],true):null;
    if ($r['cves'] && $data && $kev['fetched_at']>time()-604800) {
        $matches=array_values(array_intersect($r['cves'],$data['cves']));
        hs_check($r,'kev',$matches?'finding':'unknown',$matches?'Disse potentielle versionsmatch findes også i CISA KEV: '.implode(', ',$matches).'. Anvendelighed på denne hjemmeside er ikke verificeret.':'De identificerede CVE-kandidater er ikke i den hentede KEV-liste. Det udelukker ikke andre aktivt udnyttede CVE’er.','Prioritér validering og rettelse af et bekræftet KEV-match.','medium',null,'https://www.cisa.gov/known-exploited-vulnerabilities-catalog');
    }
    $r['intel']=[];
    foreach (['wordpress','kev'] as $kind) { $v=$intel[$kind]??[]; $r['intel'][$kind]=['updated_at'=>!empty($v['fetched_at'])?gmdate('Y-m-d H:i:s',$v['fetched_at']).' UTC':null,'error'=>$v['error']??'Ikke hentet endnu']; }
}
function hs_score(array &$r): void {
    $weights=['critical'=>25,'high'=>12,'medium'=>5,'low'=>2]; $confidence=['high'=>1,'medium'=>.6,'low'=>.3,'none'=>0];
    $penalty=0; $headerPenalty=0; $checked=0; $findings=0; $classes=['vulnerability'=>0,'indicator'=>0,'risk'=>0];
    foreach ($r['controls'] as $c) {
        if (in_array($c['state'],['pass','finding','observed','not_applicable'],true)) $checked++;
        if ($c['state']!=='finding') continue;
        $findings++; $classes[$c['class']]++;
        if ($c['id']==='javascript' && ($r['controls']['js_cve']['state']==='finding' || $r['controls']['kev']['state']==='finding')) continue;
        if ($c['id']==='js_cve' && $r['controls']['kev']['state']==='finding') continue;
        $p=$weights[$c['severity']]*($confidence[$c['confidence']]??0)*($c['class']==='risk'?.7:1);
        if (in_array($c['id'],['hsts','csp','frames','cookies','headers'],true)) $headerPenalty+=$p; else $penalty+=$p;
    }
    $penalty+=min(20,$headerPenalty);
    $score=$r['http_accessible']?max(0,100-(int)round($penalty)):null;
    $grade=$score===null?null:($score>=90?'A':($score>=75?'B':($score>=60?'C':($score>=40?'D':($score>=20?'E':'F')))));
    $r['rating']=['score'=>$score,'grade'=>$grade,'provisional'=>true,'checked'=>$checked,'total'=>count($r['controls']),'findings'=>$findings,'classes'=>$classes,'method'=>'Offentlig signalvurdering 1.0: 100 minus vægtede fund. Kritisk 25, høj 12, mellem 5, lav 2; sikkerhed høj 100 %, mellem 60 %, lav 30 %. Risikofaktorer vægtes 70 %. Headergruppen kan højst koste 20 point. Samme JavaScript/CVE/KEV-versionsspor tæller kun med én gang. Ukendte og ikke udførte kontroller er ikke beståede; karakteren er altid foreløbig.'];
}
function hs_report_save(PDO $db,array $r): void {
    hs_apply_intel($r,$db); hs_score($r);
    $db->prepare('INSERT OR REPLACE INTO reports(domain,report,score,grade) VALUES(?,?,?,?)')->execute([$r['domain'],json_encode($r,JSON_INVALID_UTF8_SUBSTITUTE),$r['rating']['score'],$r['rating']['grade']]);
}
function hs_report_get(PDO $db,string $domain): ?array {
    $q=$db->prepare('SELECT report,assessed_at FROM reports WHERE domain=?'); $q->execute([$domain]); $row=$q->fetch();
    if (!$row) return null;
    $r=json_decode($row['report'],true); $r['assessed_at']=$row['assessed_at']; return $r;
}
function hs_security_record(PDO $db,string $domain,string $url,array $response,array $chain): void {
    $old=hs_report_get($db,$domain);
    if (empty($old['snapshot'])) { $q=$db->prepare('SELECT snapshot FROM security_history WHERE domain=? ORDER BY id DESC LIMIT 1'); $q->execute([$domain]); $prior=$q->fetchColumn(); if ($prior!==false) $old=['snapshot'=>json_decode($prior,true)]; }
    $r=hs_analyze($domain,$url,$response,$chain,$old['snapshot']??null);
    hs_report_save($db,$r);
    if ($r['http_accessible']) {
        foreach (['wordpress','kev'] as $kind) {
            $q=$db->prepare('SELECT attempted_at FROM intel WHERE kind=?'); $q->execute([$kind]);
            if ((int)$q->fetchColumn()<time()-86400) $db->prepare('INSERT OR IGNORE INTO security_jobs(job_key,kind) VALUES(?,?)')->execute(['intel:'.$kind,$kind]);
        }
        $db->prepare('INSERT OR REPLACE INTO security_jobs(job_key,kind,domain) VALUES(?,?,?)')->execute(['dns:'.$domain,'dns',$domain]);
    }
}
function hs_dns(string $name): array {
    $records=@dns_get_record($name,DNS_TXT|DNS_A|DNS_AAAA|DNS_CNAME);
    return ['ok'=>$records!==false,'records'=>$records===false?[]:$records];
}
function hs_dns_report(array &$r,array $root,array $dmarc): void {
    $spf=[]; $addresses=[]; $policy=[]; $alias=false;
    foreach ($root['records'] as $record) {
        $txt=$record['txt']??implode('',$record['entries']??[]);
        if (preg_match('/^v=spf1(?:\s|$)/i',$txt)) $spf[]=$txt;
        if (!empty($record['ip'])) $addresses[]=$record['ip']; if (!empty($record['ipv6'])) $addresses[]=$record['ipv6'];
    }
    foreach ($dmarc['records'] as $record) {
        $txt=$record['txt']??implode('',$record['entries']??[]);
        if (preg_match('/^v=DMARC1\s*;/i',$txt)) $policy[]=$txt;
        if (($record['type']??'')==='CNAME') $alias=true;
    }
    if ($root['ok']) hs_check($r,'spf',$spf?'observed':'finding',$spf?'SPF TXT-record observeret. Hele SPF-kæden, syntaks og DNS-lookup-grænsen er ikke valideret.':'Ingen SPF TXT-record i det offentlige rodopslag.','Opsæt en passende SPF-politik. Domæner uden mail kan have en restriktiv no-mail-politik.','medium');
    else hs_check($r,'spf','unknown','DNS-opslaget fejlede; fravær af SPF er ikke konstateret.');
    if ($dmarc['ok'] && !$alias) {
        hs_check($r,'dmarc',$policy?'observed':'finding',$policy?'DMARC TXT-record observeret.':'Ingen DMARC-record i det offentlige _dmarc-opslag.','Indfør DMARC efter kortlægning af legitime afsendere.','medium');
        if (count($policy)===1 && preg_match('/(?:^|;)\s*p\s*=\s*(none|quarantine|reject)(?:\s*;|\s*$)/i',$policy[0],$v)) hs_check($r,'dmarc_policy',strtolower($v[1])==='none'?'finding':'observed','Oplyst DMARC-politik: p='.strtolower($v[1]).'. Underdomænepolitik og alignment er ikke fuldt valideret.','Brug p=none til overvågning efter behov; planlæg quarantine/reject først efter kontrol af legitime mails.','medium');
    } else hs_check($r,'dmarc','unknown',$alias?'DMARC bruger et CNAME. Aliasets TXT-politik er ikke fulgt.':'DMARC DNS-opslaget fejlede; fravær er ikke konstateret.');
    if ($root['ok'] && $addresses) { sort($addresses); $r['snapshot']['addresses']=array_values(array_unique($addresses)); }
    $old=$r['previous']??null;
    if ($old && !empty($old['addresses']) && !empty($r['snapshot']['addresses'])) hs_check($r,'dns_change','observed',$old['addresses']!==$r['snapshot']['addresses']?'IP-adresserne er ændret siden sidste scanning. Dette kan være normal CDN- eller hostingdrift.':'Ingen ændring af de observerede IP-adresser. Ingen fuld DNS-historik eller ejerskabskontrol.');
    if ($old && isset($old['text_hash'],$r['snapshot']['text_hash'])) hs_check($r,'content_change','observed',$old['text_hash']!==$r['snapshot']['text_hash']?'Forsidens synlige tekstfingeraftryk er ændret. Titlen er nu: '.($r['snapshot']['title']??'').'. Ændringen scores ikke alene som et sikkerhedsfund.':'Samme tekstfingeraftryk som sidste sammenlignelige scanning.');
    if ($old && !empty($old['certificate']['fingerprint']) && !empty($r['snapshot']['certificate']['fingerprint'])) hs_check($r,'cert_change','observed',$old['certificate']['fingerprint']!==$r['snapshot']['certificate']['fingerprint']?'Certifikatets SHA-256-fingeraftryk er ændret. Normal fornyelse er en mulig årsag.':'Samme certifikatfingeraftryk som ved sidste scanning.');
    $r['complete']=true;
}
function hs_security_job(PDO $db,callable $fetch,?callable $dns=null): bool {
    $job=$db->query("SELECT * FROM security_jobs ORDER BY CASE WHEN kind='dns' THEN 1 ELSE 0 END,job_key LIMIT 1")->fetch(); if (!$job) return false;
    try {
        if ($job['kind']==='dns') {
            $r=hs_report_get($db,$job['domain']);
            if ($r) {
                $dns??=fn($name)=>hs_dns($name);
                hs_dns_report($r,$dns($job['domain']),$dns('_dmarc.'.$job['domain']));
                hs_apply_intel($r,$db); hs_score($r); hs_report_save($db,$r);
                $db->prepare('INSERT INTO security_history(domain,score,grade,snapshot) VALUES(?,?,?,?)')->execute([$r['domain'],$r['rating']['score']??null,$r['rating']['grade']??null,json_encode($r['snapshot'])]);
                $db->prepare('DELETE FROM security_history WHERE domain=? AND id NOT IN (SELECT id FROM security_history WHERE domain=? ORDER BY id DESC LIMIT 10)')->execute([$r['domain'],$r['domain']]);
            }
        } else {
            $kind=$job['kind']==='kev_mirror'?'kev':$job['kind']; $url=$job['kind']==='kev_mirror'?'https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json':($kind==='wordpress'?'https://api.wordpress.org/core/version-check/1.7/':'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json');
            $response=$fetch($url,$kind==='wordpress'?524288:8000000);
            if ($response['code']!==200 || $response['truncated']) throw new RuntimeException('Sikkerhedsdata svarede HTTP '.$response['code']);
            $data=json_decode($response['body'],true,64,JSON_THROW_ON_ERROR);
            if ($kind==='wordpress') {
                $version=$data['offers'][0]['current']??null;
                if (!is_string($version) || !preg_match('/^\d+\.\d+(?:\.\d+)?$/D',$version)) throw new RuntimeException('Officielle WordPress-versionsdata kunne ikke valideres');
                $payload=['version'=>$version];
            } else {
                if (!isset($data['vulnerabilities']) || !is_array($data['vulnerabilities'])) throw new RuntimeException('CISA KEV-format kunne ikke valideres');
                $cves=[]; foreach ($data['vulnerabilities'] as $v) if (preg_match('/^CVE-\d{4}-\d{4,}$/D',$v['cveID']??'')) $cves[]=$v['cveID'];
                if (!$cves) throw new RuntimeException('CISA KEV-listen var tom'); $payload=['cves'=>array_values(array_unique($cves))];
            }
            $payload['source']=$url;
            $db->prepare('INSERT OR REPLACE INTO intel(kind,payload,fetched_at,attempted_at,error) VALUES(?,?,?,?,\'\')')->execute([$kind,json_encode($payload),time(),time()]);
        }
    } catch (Throwable $e) {
        if ($job['kind']!=='dns') {
            if ($job['kind']==='kev') $db->prepare('INSERT OR IGNORE INTO security_jobs(job_key,kind) VALUES(?,?)')->execute(['intel:kev_mirror','kev_mirror']);
            $kind=$job['kind']==='kev_mirror'?'kev':$job['kind'];
            $db->prepare('INSERT INTO intel(kind,attempted_at,error) VALUES(?,?,?) ON CONFLICT(kind) DO UPDATE SET attempted_at=excluded.attempted_at,error=excluded.error')->execute([$kind,time(),substr($e->getMessage(),0,250)]);
        } else {
            $r=hs_report_get($db,$job['domain']); if ($r) { $r['limitations'][]='DNS-delen kunne ikke afsluttes; de berørte kontroller er ikke beståede.'; hs_report_save($db,$r); }
        }
    }
    $db->prepare('DELETE FROM security_jobs WHERE job_key=?')->execute([$job['job_key']]); return true;
}
function hs_network_report(PDO $db,string $domain,string $url,Throwable $error): void {
    $r=hs_new_report($domain,hs_safe_url($url));
    $r['limitations'][]='HTTP-svaret kunne ikke sikkerhedsvurderes: '.substr($error->getMessage(),0,200);
    if ($error instanceof HSNetworkError && in_array($error->getCode(),[CURLE_PEER_FAILED_VERIFICATION,CURLE_SSL_CERTPROBLEM],true)) hs_check($r,'tls','finding','TLS-certifikatet kunne ikke verificeres af scanneren. Årsagen kan være certifikatkæde, værtsnavn eller lokal CA-konfiguration.','Kontrollér certifikat, værtsnavn, udløb og certifikatkæde.','medium');
    hs_report_save($db,$r);
}

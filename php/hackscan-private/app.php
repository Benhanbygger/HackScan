<?php
declare(strict_types=1);
ini_set('display_errors','0');
ini_set('log_errors','1');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: no-referrer');
header('Cache-Control: no-store');
header("Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'");
require __DIR__.'/core.php';
require __DIR__.'/details.php';
function h(string $s): string { return htmlspecialchars($s,ENT_QUOTES|ENT_SUBSTITUTE,'UTF-8'); }
function hs_json(array $data,int $status=200): never {
    http_response_code($status); header('Content-Type: application/json; charset=utf-8');
    echo json_encode($data,JSON_INVALID_UTF8_SUBSTITUTE); exit;
}
function hs_page(string $content,string $title='HackScan'): never {
    header('Content-Type: text/html; charset=utf-8');
    echo '<!doctype html><html lang="da"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>'.h($title).'</title><link rel="stylesheet" href="style.css?v=0.5.0"></head><body><main><a class="brand" href="index.php"><svg class="logo" viewBox="0 0 40 40" aria-hidden="true"><rect width="40" height="40" rx="12" fill="currentColor"/><path d="M20 8l11 5v8c0 6-7 10-11 12-4-2-11-6-11-12v-8z" fill="none" stroke="white" stroke-width="2"/><path d="M12 21h5l3-6 3 10 3-4h3" fill="none" stroke="white" stroke-width="2" stroke-linejoin="round"/></svg>HackScan</a>'.$content.'</main></body></html>'; exit;
}
$local=in_array($_SERVER['REMOTE_ADDR']??'', ['127.0.0.1','::1'],true);
$https=(!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS']!=='off');
if (!$https && !$local) { http_response_code(400); hs_page('<section><h1>Brug HTTPS</h1><p>Åbn denne side med https:// før du logger ind.</p></section>'); }
if (PHP_VERSION_ID<80200 || !extension_loaded('curl') || !class_exists('PDO') || !in_array('sqlite',PDO::getAvailableDrivers(),true)) {
    http_response_code(503); hs_page('<section><h1>Serveren mangler en forudsætning</h1><p>Kræver PHP 8.2+, cURL og PDO SQLite. Vælg PHP 8.4 i Plesk.</p></section>');
}
try {
    $data=__DIR__.'/data';
    if (!is_dir($data) && !mkdir($data,0700,true)) throw new RuntimeException('Private data directory unavailable');
    if (!is_dir($data.'/sessions') && !mkdir($data.'/sessions',0700)) throw new RuntimeException('Session directory unavailable');
    $db=hs_db($data.'/hackscan.sqlite3'); @chmod($data.'/hackscan.sqlite3',0600);
    session_save_path($data.'/sessions'); session_name('hackscan_session');
    ini_set('session.use_strict_mode','1');
    session_set_cookie_params(['lifetime'=>0,'path'=>rtrim(dirname($_SERVER['SCRIPT_NAME']),'/').'/','secure'=>$https,'httponly'=>true,'samesite'=>'Strict']);
    session_start();
} catch (Throwable $e) {
    error_log('HackScan initialization: '.$e->getMessage()); http_response_code(503);
    hs_page('<section><h1>Den private mappe kan ikke bruges</h1><p>Kontrollér, at hackscan-private ligger ved siden af httpdocs, og at PHP kan skrive i den. Detaljer findes i Plesks Logs.</p></section>');
}
$_SESSION['csrf']??=bin2hex(random_bytes(32));
$csrf=$_SESSION['csrf']; $post=$_SERVER['REQUEST_METHOD']==='POST';
if ($post && !hash_equals($csrf,(string)($_POST['csrf']??$_SERVER['HTTP_X_CSRF_TOKEN']??''))) {
    if (isset($_GET['api'])) hs_json(['error'=>'Siden er udløbet. Genindlæs og prøv igen.'],403);
    http_response_code(403); hs_page('<section><h1>Siden er udløbet</h1><p>Genindlæs siden og prøv igen.</p></section>');
}
$error=''; $hash=hs_get($db,'password_hash');
$currentUser=hs_current_user($db,$_SESSION);
$needsSetup=(int)$db->query('SELECT COUNT(*) FROM users')->fetchColumn()===0;
if ($needsSetup || !$currentUser) {
    unset($_SESSION['auth']);
    if (isset($_GET['api'])) hs_json(['error'=>'Log ind igen.'],401);
    $setup=$needsSetup;
    if ($post) {
        $db->prepare('DELETE FROM attempts WHERE at<?')->execute([time()-900]);
        $attempts=(int)$db->query('SELECT COUNT(*) FROM attempts')->fetchColumn();
        if ($attempts>=10) { http_response_code(429); $error='For mange forsøg. Vent 15 minutter.'; }
        else {
            $db->prepare('INSERT INTO attempts(at) VALUES(?)')->execute([time()]);
            $password=(string)($_POST['password']??''); $valid=false;
            if ($setup) {
                $keyPath=__DIR__.'/setup-key.txt';
                $key=is_file($keyPath)?trim((string)file_get_contents($keyPath)):'';
                if (strlen($key)<24 || !hash_equals($key,(string)($_POST['setup_key']??''))) $error='Opsætningsnøglen er forkert eller mangler i den private mappe.';
                elseif (strlen($password)<14 || strlen($password)>72) $error='Vælg en adgangskode på 14–72 bytes (brug gerne en lang adgangssætning).';
                elseif ($password!==(string)($_POST['confirm']??'')) $error='Adgangskoderne er ikke ens.';
                else {
                    // Exclusive insert prevents simultaneous first-run requests overwriting an account.
                    $q=$db->prepare('INSERT OR IGNORE INTO settings(name,value) VALUES(\'password_hash\',?)');
                    $q->execute([password_hash($password,PASSWORD_DEFAULT)]);
                    $valid=$q->rowCount()===1;
                    if ($valid) @unlink($keyPath); else $error='Opsætningen er allerede afsluttet. Genindlæs for at logge ind.';
                }
            } else {
                $loginName=is_string($_POST['username']??'admin')?($_POST['username']??'admin'):'';
                $loginUser=hs_user_by_name($db,$loginName);
                $valid=$loginUser && $loginUser['active'] && password_verify($password,$loginUser['password_hash']);
                if (!$valid) $error='Forkert adgangskode.';
            }
            if ($valid) {
                hs_users_schema($db); $loginUser=hs_user_by_name($db,$setup?'admin':$loginName);
                session_regenerate_id(true); $_SESSION['user_id']=(int)$loginUser['id']; $_SESSION['session_version']=(int)$loginUser['session_version']; $_SESSION['auth']=time(); $_SESSION['csrf']=bin2hex(random_bytes(32));
                $db->exec('DELETE FROM attempts'); header('Location: index.php'); exit;
            }
        }
    }
    $content='<section class="login"><p class="eyebrow">PRIVAT DOMÆNEKONTROL</p><h1>'.($setup?'Opret din adgang':'Log ind').'</h1>';
    if ($setup) $content.='<p>Opret først <code>setup-key.txt</code> i <strong>hackscan-private</strong> med en tilfældig nøgle på mindst 24 tegn. Indtast den her. Nøglen slettes efter opsætningen.</p>';
    if ($error!=='') $content.='<p class="error" role="alert">'.h($error).'</p>';
    $content.='<form method="post"><input type="hidden" name="csrf" value="'.h($csrf).'">';
    if ($setup) $content.='<label>Opsætningsnøgle<input name="setup_key" type="password" autocomplete="off" required maxlength="256"></label>';
    if (!$setup) $content.='<label>Brugernavn<input name="username" value="admin" autocomplete="username" required maxlength="50"></label>';
    $content.='<label>'.($setup?'Ny adgangskode':'Adgangskode').'<input name="password" type="password" autocomplete="'.($setup?'new-password':'current-password').'" required maxlength="72"'.($setup?' minlength="14"':'').'></label>';
    if ($setup) $content.='<label>Gentag adgangskode<input name="confirm" type="password" autocomplete="new-password" required maxlength="72"></label>';
    $content.='<button>'.($setup?'Opret adgang':'Log ind').'</button></form></section>';
    hs_page($content);
}
$_SESSION['auth']=time(); session_write_close();
$canScan=$currentUser['role']!=='viewer';
if (isset($_GET['admin'])) { if ($currentUser['role']!=='admin') { http_response_code(403); hs_page('<section class="login"><h1>Adgang nægtet</h1><p>Kun administratorer har adgang.</p></section>'); } hs_admin_page($currentUser,$csrf); }
if (isset($_GET['domain']) && is_string($_GET['domain']) && !isset($_GET['api'])) hs_details_page($db,substr($_GET['domain'],0,253),$csrf,$canScan);
$action=$_GET['api']??'';
if ($action!=='') {
    if (!in_array($action,['state','export','users'],true) && !$post) hs_json(['error'=>'Brug POST'],405);
    if ($action==='clear_results' && $currentUser['role']!=='admin') hs_json(['error'=>'Kun administratorer kan rydde resultater.'],403);
    if ($action==='clear_results' && ($_POST['confirmation']??'')!=='RYD ALLE RESULTATER') hs_json(['error'=>'Bekræft sletningen først.'],400);
    if (!$canScan && in_array($action,['start','manual','stop','tick','reassess'],true)) hs_json(['error'=>'Din konto har kun læseadgang.'],403);
    if (in_array($action,['users','user_create','user_update'],true)) {
        if ($currentUser['role']!=='admin') hs_json(['error'=>'Kun administratorer har adgang.'],403);
        if ($action==='users') hs_json(['users'=>$db->query('SELECT id,username,role,active,created_at FROM users ORDER BY username')->fetchAll(),'audit'=>$db->query('SELECT user_audit.*,a.username AS actor_name,s.username AS subject_name FROM user_audit LEFT JOIN users a ON a.id=user_audit.actor LEFT JOIN users s ON s.id=user_audit.subject ORDER BY user_audit.id DESC LIMIT 25')->fetchAll()]);
        try {
            if ($action==='user_create') { $id=hs_user_create($db,$currentUser,$_POST['username']??null,$_POST['password']??null,$_POST['role']??'user'); hs_json(['ok'=>true,'id'=>$id],201); }
            $id=(int)($_POST['id']??0); hs_user_update($db,$currentUser,$id,$_POST['role']??'',($_POST['active']??'')==='1',is_string($_POST['password']??null)?$_POST['password']:null);
            hs_json(['ok'=>true,'reauthenticate'=>$id===(int)$currentUser['id']]);
        } catch (InvalidArgumentException $e) { hs_json(['error'=>$e->getMessage()],400); } catch (Throwable $e) { error_log('User management: '.$e->getMessage()); hs_json(['error'=>'Brugerændringen kunne ikke gemmes.'],500); }
    }
    if ($action==='logout') {
        session_start(); $_SESSION=[]; session_destroy(); hs_json(['ok'=>true]);
    }
    if ($action==='export') {
        header('Content-Type: text/csv; charset=utf-8'); header('Content-Disposition: attachment; filename="hackscan-resultater.csv"');
        $out=fopen('php://output','w'); fwrite($out,"\xEF\xBB\xBF");
        fputcsv($out,['Domæne','Slutadresse','Status','Detalje','HTTP-kode','Sikkerhedsscore','Karakter (foreløbig)','Kontrolleret UTC'],';', '"','');
        foreach ($db->query('SELECT results.domain,current_url,status,detail,(SELECT code FROM http_results WHERE http_results.domain=results.domain) AS http_code,(SELECT score FROM reports WHERE reports.domain=results.domain) AS security_score,(SELECT grade FROM reports WHERE reports.domain=results.domain) AS security_grade,checked_at FROM results ORDER BY checked_at DESC') as $r) {
            $r['current_url']=hs_safe_url($r['current_url']);
            fputcsv($out,array_map(fn($v)=>preg_match('/^[=+@\-\t\r]/',(string)$v)?"'".$v:$v,array_values($r)),';','"','');
        }
        fclose($out); exit;
    }
    if ($action==='start') {
        try { hs_options($_POST['limit']??50,$_POST['start_char']??'0'); hs_ns_options($_POST['providers']??[]); }
        catch (InvalidArgumentException $e) { hs_json(['error'=>$e->getMessage()],400); }
    }
    if ($action==='manual') { try { $manualDomain=hs_manual_domain($_POST['domain']??null); } catch (InvalidArgumentException $e) { hs_json(['error'=>$e->getMessage()],400); } }
    if (in_array($action,['start','manual','tick','stop','reassess','clear_results'],true)) {
        $lock=fopen($data.'/scan.lock','c');
        if (!$lock || !flock($lock,LOCK_EX|LOCK_NB)) hs_json(['error'=>'En kontrol er i gang. Prøv igen om lidt.'],409);
        try {
            if ($action==='clear_results') {
                hs_clear_results($db,$currentUser);
            } elseif ($action==='manual') {
                if (hs_get($db,'running')==='1') hs_json(['error'=>'Stop eller afslut den aktive scanning først.'],409);
                hs_start_manual($db,$manualDomain);
            } elseif ($action==='start') {
                if (hs_get($db,'running')==='1') hs_json(['error'=>'En scanning er allerede aktiv.'],409);
                hs_start($db,$_POST['limit']??50,$_POST['start_char']??'0',$_POST['providers']??[]);
            } elseif ($action==='reassess') {
                if (hs_get($db,'running')==='1') hs_json(['error'=>'Stop eller afslut den aktive scanning først.'],409);
                $domain=is_string($_POST['domain']??null)?$_POST['domain']:'';
                $q=$db->prepare('SELECT domain FROM results WHERE domain=?'); $q->execute([$domain]);
                if (!$q->fetchColumn()) hs_json(['error'=>'Domænet findes ikke i de gemte resultater.'],404);
                hs_url('https://'.$domain.'/');
                $db->prepare('DELETE FROM http_results WHERE domain=?')->execute([$domain]); $db->prepare('DELETE FROM redirect_hops WHERE domain=?')->execute([$domain]);
                hs_start($db,1,strtolower($domain[0])); hs_set($db,'phase','scan'); hs_set($db,'source','Genkontrol af gemt domæne');
                $db->prepare("INSERT OR REPLACE INTO results(domain,current_url,status) VALUES(?,?,'pending')")->execute([$domain,'https://'.$domain.'/']);
            } elseif ($action==='stop') {
                $db->exec('DELETE FROM security_jobs'); $db->exec('DELETE FROM ns_candidates');
                hs_set($db,'running','0'); hs_set($db,'phase','stopped');
                $db->exec("UPDATE results SET status='cancelled',detail='Scanning stoppet' WHERE status='pending'");
            } else {
                if ((int)hs_get($db,'last_tick','0')>time()-1) hs_json(['ok'=>true]);
                hs_set($db,'last_tick',(string)time()); hs_tick($db);
            }
        } catch (Throwable $e) {
            hs_set($db,'running','0'); hs_set($db,'error',substr($e->getMessage(),0,350));
            hs_set($db,'phase','failed');
        } finally { flock($lock,LOCK_UN); fclose($lock); }
        hs_json(['ok'=>true]);
    }
    if ($action!=='state') hs_json(['error'=>'Ukendt handling'],404);
    $counts=[];
    foreach ($db->query('SELECT status, COUNT(*) AS n FROM results GROUP BY status') as $r) $counts[$r['status']]=(int)$r['n'];
    $search=is_string($_GET['q']??'')?substr($_GET['q']??'',0,200):'';
    $groups=hs_groups($db,$search,$_GET);
    hs_json(['state'=>['ns_providers'=>hs_ns_selected($db),'ns_checked'=>(int)hs_get($db,'ns_checked','0'),'running'=>hs_get($db,'running')==='1','phase'=>hs_get($db,'phase','idle'),'error'=>hs_get($db,'error'),'notice'=>hs_get($db,'notice'),'checked'=>(int)hs_get($db,'checked','0'),'source'=>hs_get($db,'source'),'target'=>(int)hs_get($db,'target','50'),'start_char'=>hs_get($db,'start_char','0'),'pending'=>(int)($counts['pending']??0),'security_pending'=>(int)$db->query('SELECT COUNT(*) FROM security_jobs')->fetchColumn()], 'counts'=>$counts,'groups'=>$groups,'can_scan'=>$canScan,'user'=>['username'=>$currentUser['username'],'role'=>$currentUser['role']],'security'=>$db->query('SELECT COUNT(*) AS assessed, ROUND(AVG(score),1) AS average FROM reports WHERE score IS NOT NULL')->fetch()]);
}
$warning=is_file(__DIR__.'/setup-key.txt')?'<p class="error">Slet setup-key.txt fra hackscan-private. Opsætningen er afsluttet.</p>':'';
$letters='';
foreach (str_split('0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ') as $char) $letters.='<option value="'.strtolower($char).'">'.$char.'</option>';
$adminLink=$currentUser['role']==='admin'?'<a class="nav-link" href="index.php?admin=users"><span>♙</span>Brugere</a>':'';
$providerChoices=''; foreach (hs_ns_providers() as $provider) $providerChoices.='<label><input type="checkbox" name="provider" value="'.h($provider).'">'.h($provider).'</label>';
$panels='';
foreach (['all'=>['Alle domæner','Alle gemte resultater og igangværende kontroller'],'review'=>['Bør undersøges','Viderestillinger til andre domæner'],'ok'=>['Samme domæne','Ingen ændring af domænet'],'errors'=>['Fejl','HTTP-fejl og uafsluttede kontroller']] as $key=>$text) {
    $panels.='<section class="result-panel" id="panel-'.$key.'"><div class="panel-heading"><div><h2><span class="status-dot '.$key.'"></span>'.$text[0].' <span class="count-pill" id="count-'.$key.'">0</span></h2><p>'.$text[1].'</p></div></div><div class="table-wrap"><table><thead><tr><th>Domæne / kontrolleret</th><th>Slutadresse / næste hop</th><th>Resultat / sikkerhed</th><th>HTTP-kode</th></tr></thead><tbody id="rows-'.$key.'"></tbody></table></div><div class="pagination"><span id="range-'.$key.'">Ingen resultater</span><div><button class="icon-button" data-page="'.$key.'" data-direction="-1" aria-label="Forrige side: '.$text[0].'">‹</button><button class="icon-button" data-page="'.$key.'" data-direction="1" aria-label="Næste side: '.$text[0].'">›</button></div></div></section>';
}
hs_page('<div id="app" data-csrf="'.h($csrf).'" data-can-scan="'.($canScan?'1':'0').'"><aside class="sidebar"><p class="nav-caption">OVERBLIK</p><nav><a class="nav-link active" href="#dashboard"><span>▦</span>Dashboard</a><a class="nav-link" href="#new-scan"><span>⌕</span>Ny scanning</a><a class="nav-link" href="#results"><span>▤</span>Resultater</a>'.$adminLink.'</nav><div class="nav-divider"></div><p class="nav-caption">VÆRKTØJER</p><a class="nav-link" href="index.php?api=export"><span>↓</span>Eksportér CSV</a><div class="sidebar-note"><span class="source-icon">DK</span><strong>Det danske web</strong><p>Automatisk domæneopdagelse via offentlige domænelister.</p></div><button id="logout" class="nav-link logout"><span>↪︎</span>Log ud</button></aside><div class="workspace" id="dashboard"><header class="topbar"><div><p class="eyebrow">HACKSCAN / OVERBLIK</p><h1>Dashboard</h1></div><div class="header-tools"><label class="search-box"><span aria-hidden="true">⌕</span><input id="search" type="search" placeholder="Søg i domæner og resultater …" aria-label="Søg i alle gemte resultater" maxlength="200"></label><span class="live-badge" id="live-status">Klar</span></div></header>'.$warning.'<div class="stats"><section class="stat-card"><div class="stat-label"><span class="metric-icon all">▦</span>Alle domæner</div><strong id="total">0</strong><p>Gemte resultater</p><div class="stat-decoration purple" aria-hidden="true"></div></section><section class="stat-card"><div class="stat-label"><span class="metric-icon review">↗︎</span>Bør undersøges</div><strong id="review">0</strong><p>Viderestiller til et andet domæne</p><div class="stat-decoration amber" aria-hidden="true"></div></section><section class="stat-card"><div class="stat-label"><span class="metric-icon ok">✓</span>Samme domæne</div><strong id="same">0</strong><p>HTTP/HTTPS og www ignoreres</p><div class="stat-decoration green" aria-hidden="true"></div></section><section class="stat-card"><div class="stat-label"><span class="metric-icon errors">!</span>Fejl</div><strong id="errors">0</strong><p>Kræver en ny kontrol</p><div class="stat-decoration red" aria-hidden="true"></div></section></div><div class="overview-grid"><section class="scan-panel" id="new-scan"><div class="panel-heading"><div><h2>Start en ny scanning</h2><p>Vælg omfang og startpunkt. Vi finder selv domænerne.</p></div><span class="soft-label">.dk-domæner</span></div><form id="scan-form"><div class="scan-fields"><label>Antal domæner<input id="scan-limit" type="number" min="1" max="10000" step="1" value="50" required><small>Fra 1 til 10.000 pr. scanning</small></label><label>Start ved bogstav eller tal<select id="start-char">'.$letters.'</select><small>Vælg 0–9 eller A–Z. www ignoreres.</small></label><div class="scan-actions"><button id="start" type="submit"><span aria-hidden="true">▷</span> Start scanning</button><button id="stop" type="button" class="secondary" hidden>Stop scanning</button></div></div><fieldset id="ns-filter" class="ns-filter"><legend>Navneservere — valgfrit</legend><p>Ingen valgt = alle udbydere. Flere valg = mindst én navneserver skal matche. Udbyderens navneserverdomæne er ikke nødvendigvis hjemmesidens hostingudbyder. Ved lokale DNS-fejl bruges Google Public DNS via HTTPS som reserve.</p><div class="provider-grid">'.$providerChoices.'</div></fieldset></form><form id="manual-form" class="manual-form"><label>Scan ét domæne<input id="manual-domain" type="text" placeholder="eksempel.dk" maxlength="300" required></label><button id="manual-start" class="button" type="submit">Scan domæne</button><small>Manuel scanning bruger ikke navneserverfilter eller startbogstav.</small></form><div class="scan-status"><span class="pulse-dot" aria-hidden="true"></span><p id="state" role="status">Henter status …</p><strong id="progress-label">0 / 50</strong></div><progress id="progress" max="100" value="0" aria-label="Scanningsfremskridt"></progress><p id="source" class="muted"></p><p id="notice" class="muted"></p><p id="error" class="error" role="alert"></p><p class="scan-hint">Fra det valgte tegn og frem i indekset. Scanningen kører i små portioner, mens siden er åben, eller via en planlagt opgave i Plesk.</p></section><section class="distribution-panel"><div class="panel-heading"><div><h2>Fordeling af resultater</h2><p>Alle gemte domæners seneste kontrol</p></div></div><div class="distribution"><div class="donut-wrap"><svg viewBox="0 0 120 120" class="donut" role="img" aria-label="Fordeling af gemte resultater"><circle class="ring-track" cx="60" cy="60" r="46"/><g transform="rotate(-90 60 60)"><circle id="arc-review" class="ring review" stroke-dasharray="0 289" cx="60" cy="60" r="46"/><circle id="arc-ok" class="ring ok" stroke-dasharray="0 289" cx="60" cy="60" r="46"/><circle id="arc-errors" class="ring errors" stroke-dasharray="0 289" cx="60" cy="60" r="46"/></g><text id="chart-total" x="60" y="59" text-anchor="middle">0</text><text class="donut-caption" x="60" y="74" text-anchor="middle">domæner</text></svg></div><div class="legend"><p><span class="status-dot review"></span>Bør undersøges<strong id="pct-review">0%</strong></p><p><span class="status-dot ok"></span>Samme domæne<strong id="pct-ok">0%</strong></p><p><span class="status-dot errors"></span>Fejl<strong id="pct-errors">0%</strong></p><p><span class="status-dot other"></span>Afventer / stoppet<strong id="pct-other">0%</strong></p></div></div></section></div><div class="section-title" id="results"><div><h2>Scanningsresultater</h2><p>Domænenavnet åbner sikkerhedsrapporten · ↗ åbner hjemmesiden · Tidspunkter i UTC</p></div><a class="button secondary" href="index.php?api=export">↓ Hent CSV</a></div><label class="show-clean"><input id="show-clean" type="checkbox"> Vis også domæner uden registrerede fund</label><p class="muted">Som standard skjules domæner med afsluttet HTTP-kontrol og sikkerhedskarakter uden fund. Manglende vurdering skjules ikke. Ingen fund er ikke en garanti for sikkerhed.</p><p id="security-summary" class="muted">Sikkerhedskarakterer er foreløbige og baseret på udførte offentlige kontroller.</p><div class="results-grid">'.$panels.'</div><footer><strong>En viderestilling er et signal — ikke bevis på hacking.</strong><p>Legitime flytninger kan give samme resultat. Andre underdomæner end www markeres også. Vi følger HTTP-viderestillinger, ikke JavaScript eller meta-refresh. Domænelisterne dækker ikke alle danske hjemmesider. Vi bruger Tranco med en lokalt gemt liste og Common Crawl som reserve. Det valgte antal er et mål; det faktiske antal og eventuelle begrænsninger vises efter søgningen.</p><p>Datakilder: <a href="https://tranco-list.eu/" rel="noreferrer">Tranco</a> og <a href="https://commoncrawl.org/" rel="noreferrer">Common Crawl</a>.</p></footer></div></div><script src="app.js?v=0.5.0" defer></script>');

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
function h(string $s): string { return htmlspecialchars($s,ENT_QUOTES|ENT_SUBSTITUTE,'UTF-8'); }
function hs_json(array $data,int $status=200): never {
    http_response_code($status); header('Content-Type: application/json; charset=utf-8');
    echo json_encode($data,JSON_INVALID_UTF8_SUBSTITUTE); exit;
}
function hs_page(string $content,string $title='HackScan'): never {
    header('Content-Type: text/html; charset=utf-8');
    echo '<!doctype html><html lang="da"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>'.h($title).'</title><link rel="stylesheet" href="style.css"></head><body><main><a class="brand" href="index.php">HackScan<span>DK</span></a>'.$content.'</main></body></html>'; exit;
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
if ($hash==='' || !isset($_SESSION['auth']) || (int)$_SESSION['auth']<time()-43200) {
    unset($_SESSION['auth']);
    if (isset($_GET['api'])) hs_json(['error'=>'Log ind igen.'],401);
    $setup=$hash==='';
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
                $valid=password_verify($password,$hash);
                if (!$valid) $error='Forkert adgangskode.';
            }
            if ($valid) {
                session_regenerate_id(true); $_SESSION['auth']=time(); $_SESSION['csrf']=bin2hex(random_bytes(32));
                $db->exec('DELETE FROM attempts'); header('Location: index.php'); exit;
            }
        }
    }
    $content='<section class="login"><p class="eyebrow">PRIVAT DOMÆNEKONTROL</p><h1>'.($setup?'Opret din adgang':'Log ind').'</h1>';
    if ($setup) $content.='<p>Opret først <code>setup-key.txt</code> i <strong>hackscan-private</strong> med en tilfældig nøgle på mindst 24 tegn. Indtast den her. Nøglen slettes efter opsætningen.</p>';
    if ($error!=='') $content.='<p class="error" role="alert">'.h($error).'</p>';
    $content.='<form method="post"><input type="hidden" name="csrf" value="'.h($csrf).'">';
    if ($setup) $content.='<label>Opsætningsnøgle<input name="setup_key" type="password" autocomplete="off" required maxlength="256"></label>';
    $content.='<label>'.($setup?'Ny adgangskode':'Adgangskode').'<input name="password" type="password" autocomplete="'.($setup?'new-password':'current-password').'" required maxlength="72"'.($setup?' minlength="14"':'').'></label>';
    if ($setup) $content.='<label>Gentag adgangskode<input name="confirm" type="password" autocomplete="new-password" required maxlength="72"></label>';
    $content.='<button>'.($setup?'Opret adgang':'Log ind').'</button></form></section>';
    hs_page($content);
}
$_SESSION['auth']=time(); session_write_close();
$action=$_GET['api']??'';
if ($action!=='') {
    if (!in_array($action,['state','export'],true) && !$post) hs_json(['error'=>'Brug POST'],405);
    if ($action==='logout') {
        session_start(); $_SESSION=[]; session_destroy(); hs_json(['ok'=>true]);
    }
    if ($action==='export') {
        header('Content-Type: text/csv; charset=utf-8'); header('Content-Disposition: attachment; filename="hackscan-resultater.csv"');
        $out=fopen('php://output','w'); fwrite($out,"\xEF\xBB\xBF");
        fputcsv($out,['Domæne','Slutadresse','Status','Detalje','Kontrolleret UTC'],';', '"','');
        foreach ($db->query('SELECT domain,current_url,status,detail,checked_at FROM results ORDER BY checked_at DESC') as $r) {
            fputcsv($out,array_map(fn($v)=>preg_match('/^[=+@\-\t\r]/',(string)$v)?"'".$v:$v,array_values($r)),';','"','');
        }
        fclose($out); exit;
    }
    if (in_array($action,['start','tick','stop'],true)) {
        $lock=fopen($data.'/scan.lock','c');
        if (!$lock || !flock($lock,LOCK_EX|LOCK_NB)) hs_json(['error'=>'En kontrol er i gang. Prøv igen om lidt.'],409);
        try {
            if ($action==='start') {
                if (hs_get($db,'running')==='1') hs_json(['error'=>'En scanning er allerede aktiv.'],409);
                hs_start($db);
            } elseif ($action==='stop') {
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
    hs_json(['state'=>['running'=>hs_get($db,'running')==='1','phase'=>hs_get($db,'phase','idle'),'error'=>hs_get($db,'error'),'notice'=>hs_get($db,'notice'),'checked'=>(int)hs_get($db,'checked','0'),'source'=>hs_get($db,'source')], 'counts'=>$counts, 'results'=>$db->query('SELECT * FROM results ORDER BY checked_at DESC,domain LIMIT 1000')->fetchAll()]);
}
$warning=is_file(__DIR__.'/setup-key.txt')?'<p class="error">Slet setup-key.txt fra hackscan-private. Opsætningen er afsluttet.</p>':'';
hs_page('<div id="app" data-csrf="'.h($csrf).'"><header class="top"><div><p class="eyebrow">AUTOMATISK OPDAGELSE · DANSKE DOMÆNER</p><h1>Hold øje med<br>uventede viderestillinger.</h1><p class="intro">HackScan finder selv .dk-forsider og registrerer, når de ender på et andet domæne.</p></div><button class="secondary" id="logout">Log ud</button></header>'.$warning.'<section class="control"><div><h2>Scan et udsnit af det danske web</h2><p>Op til 50 automatisk fundne domæner pr. scanning.</p><p class="muted">Scanningen kører i små portioner, mens denne side er åben. Den kan også fortsættes via en planlagt opgave i Plesk.</p></div><div class="actions"><button id="start">Start scanning</button><button id="stop" class="secondary" hidden>Stop</button></div><p id="state" role="status">Henter status …</p><p id="notice" class="muted"></p><p id="error" class="error" role="alert"></p></section><div class="stats"><section><strong id="total">0</strong><span>Gemte domæner</span></section><section><strong id="review">0</strong><span>Bør undersøges</span></section><section><strong id="errors">0</strong><span>Kontrolfejl</span></section></div><section class="results"><div class="resulthead"><h2>Resultater</h2><div><label>Vis <select id="filter"><option value="review">Bør undersøges</option><option value="all">Alle</option><option value="ok">Samme domæne</option><option value="errors">Fejl</option></select></label> <a class="button secondary" href="index.php?api=export">Hent CSV</a></div></div><p class="muted">Viser de seneste 1.000 domæner. CSV indeholder alle gemte resultater. Tidspunkter er i UTC.</p><div class="table"><table><thead><tr><th>Domæne</th><th>Slutadresse / næste hop</th><th>Resultat</th><th>Kontrolleret (UTC)</th></tr></thead><tbody id="rows"></tbody></table></div></section><footer><strong>En viderestilling er ikke bevis på hacking.</strong><p>Legitime flytninger kan give samme resultat. HTTP/HTTPS og www ignoreres ved sammenligning; andre underdomæner markeres. Kun HTTP-viderestillinger undersøges — ikke JavaScript eller meta-refresh. Domænerne kommer fra Common Crawl, som ikke dækker alle danske hjemmesider og kan være midlertidigt utilgængeligt. Hver scanning prøver næste indeksside; det garanterer ikke nye domæner.</p></footer></div><script src="app.js" defer></script>');

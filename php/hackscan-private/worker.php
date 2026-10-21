<?php
declare(strict_types=1);
// Optional Plesk scheduled PHP task. Never callable as a web endpoint.
if (PHP_SAPI!=='cli') { http_response_code(404); exit; }
require __DIR__.'/core.php';
$path=__DIR__.'/data';
if (!is_file($path.'/hackscan.sqlite3')) { fwrite(STDERR,"Åbn og opsæt først HackScan i browseren.\n"); exit(1); }
$db=hs_db($path.'/hackscan.sqlite3');
if (hs_get($db,'password_hash')==='') { fwrite(STDERR,"Opsætning mangler.\n"); exit(1); }
$lock=fopen($path.'/scan.lock','c');
if (!$lock || !flock($lock,LOCK_EX|LOCK_NB)) exit;
try {
    // One network operation (occasionally two for HTTP fallback), comfortably below one minute.
    if ((int)hs_get($db,'last_tick','0')<=time()-1) {
        hs_set($db,'last_tick',(string)time()); hs_tick($db);
    }
} catch (Throwable $e) {
    hs_set($db,'running','0'); hs_set($db,'phase','failed'); hs_set($db,'error',substr($e->getMessage(),0,350));
    fwrite(STDERR,$e->getMessage()."\n"); exit(1);
} finally { flock($lock,LOCK_UN); fclose($lock); }

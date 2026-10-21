<?php
declare(strict_types=1);
require dirname(__DIR__).'/hackscan-private/core.php';
$db=hs_db(':memory:'); hs_start($db,(int)($argv[1]??3),$argv[2]??'0');
try {
    hs_tick($db); echo "Discovery stage: ".hs_get($db,'phase')."\n";
    for ($i=0;$i<180 && in_array(hs_get($db,'phase'),['catalog','catalog_queue','metadata','inventory','seek','discovery'],true);$i++) { hs_tick($db); echo 'Discovery stage: '.hs_get($db,'phase')."\n"; sleep(1); }
    if (hs_get($db,'phase')!=='scan') throw new RuntimeException('No domains discovered');
    $total=(int)$db->query('SELECT COUNT(*) FROM results')->fetchColumn(); echo "Automatically discovered domains: $total\n";
    // Validate only three of the automatically discovered domains; avoid a large live scan.
    $db->exec('DELETE FROM results WHERE domain NOT IN (SELECT domain FROM results ORDER BY domain LIMIT 3)');
    for ($i=0;$i<36 && hs_get($db,'running')==='1';$i++) { hs_tick($db); sleep(1); }
    foreach ($db->query('SELECT domain,current_url,status,detail FROM results ORDER BY domain') as $row) echo json_encode($row,JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE)."\n";
    echo 'Completed checks: '.hs_get($db,'checked')."\n";
    if (hs_get($db,'running')==='1') throw new RuntimeException('Scan did not finish');
} catch (Throwable $e) { fwrite(STDERR,$e->getMessage()."\n"); exit(1); }

<?php
declare(strict_types=1);
$entry = dirname(__DIR__, 2) . '/hackscan-private/app.php';
if (!is_file($entry)) {
    http_response_code(503);
    header('Content-Type: text/plain; charset=utf-8');
    exit('Mappen hackscan-private skal ligge ved siden af httpdocs, ikke inde i den. Se uploadvejledningen.');
}
require $entry;

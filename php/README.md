# HackScan PHP

PHP-version til Plesk med PHP 8.2+ (8.4 anbefales), cURL og PDO SQLite. Ingen Composer, Python eller Node kræves på serveren. Se [UPLOAD-VEJLEDNING.md](UPLOAD-VEJLEDNING.md).

`httpdocs/hackscan` er offentlige filer. `hackscan-private` er søskende til `httpdocs`, aldrig en undermappe. Login med adgangskodehash, CSRF, loginbegrænsning, private sessioner, HTTPS og blokeret første opsætning indtil en privat engangsnøgle findes. SQLite og køtilstand overlever genstart. Browser og valgfri CLI-arbejder serialiserer opgaver med en fil-lås.

Scanningen består af små trin: indeksoversigt, en indeksside (op til 50 forskellige .dk-forsider), et redirect-hop pr. trin. Ved fejl i nyeste indeks prøves forrige indeks i et senere trin. Hvert netværkskald har 12 sekunders timeout; HTTP-fallback på forbindelsesfejl kan give to kald i et trin. Ingen TLS-nedgradering ved certifikatfejl. DNS skal være tilgængeligt. PHP cURL bruger miljøets proxy, hvis defineret, og `CURLOPT_CONNECT_TO` fastlåser destinationen til en valideret offentlig IP uden at ændre TLS-værtsnavnet.

## Lokal validering

Med en almindelig PHP-installation:

```sh
php tests/core.php
HACKSCAN_PHP=php python3 tests/web.py
```

`web.py` starter en rigtig PHP-webserver i en midlertidig mappe og kontrollerer opsætning, login, API, CSRF, privat lagring, eksport og logud. Tilfældige testnøgler bliver i den midlertidige mappe og slettes. Ingen adgangskoder udskrives.

På det nuværende Codex-miljø findes en verificeret Debian PHP 8.4-runtime uden for checkoutet:

```sh
cd /workspace/HackScan
/workspace/.tools/php/php php/tests/core.php
python php/tests/web.py
node --check php/httpdocs/hackscan/app.js
```

Valgfri ekstern funktionstest (foretager rigtige forespørgsler til Common Crawl og tre automatisk fundne domæner; fejler ved utilgængelig datakilde):

```sh
/workspace/.tools/php/php php/tests/live.php
```

Ingen runtime-data, engangsnøgler eller konti skal med i uploadpakken. Bevar eksisterende installationsdata ved senere opdateringer. Browserstart og `worker.php` bruger samme database og fil-lås. En inaktiv kørsel uden pending-domæner foretager ingen netværkskald.

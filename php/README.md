# HackScan PHP 0.3.1

PHP-version til Plesk med PHP 8.2+ (8.4 anbefales), cURL og PDO SQLite. Ingen Composer, Python eller Node kræves på serveren. Se [UPLOAD-VEJLEDNING.md](UPLOAD-VEJLEDNING.md) til ny installation og [OPDATERING.md](OPDATERING.md) til eksisterende installationer.

`httpdocs/hackscan` er offentlige filer. `hackscan-private` er søskende til `httpdocs`, aldrig en undermappe. Login med adgangskodehash, CSRF, loginbegrænsning, private sessioner, HTTPS og blokeret første opsætning indtil en privat engangsnøgle findes. SQLite og køtilstand overlever genstart. Browser og valgfri CLI-arbejder serialiserer opgaver med en fil-lås.

Scanningen består af små trin: hentning eller genbrug af en domæneliste, lokal udvælgelse af et brugerdefineret mål på 1–10.000 primære .dk-domæner, og et redirect-hop pr. trin. Common Crawl-opslag er reservevejen. Ved fejl i nyeste indeks prøves forrige indeks i et senere trin. Common Crawl-kald har 20 sekunders timeout, hjemmesidekald har 12 sekunder; HTTP-fallback på forbindelsesfejl kan give to kald i et trin. Ingen TLS-nedgradering ved certifikatfejl. DNS skal være tilgængeligt. PHP cURL bruger miljøets proxy, hvis defineret, og `CURLOPT_CONNECT_TO` fastlåser destinationen til en valideret offentlig IP uden at ændre TLS-værtsnavnet.

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

## Dashboard og tests

Alle fire resultatgrupper har serverbaseret søgning og selvstændig sideinddeling med otte rækker pr. side. Diagrammet viser faktiske seneste statusantal, ikke historik eller estimeret hacking.

For starttegn efter 0 hentes indeksstørrelsen og derefter bestemmes startblokken med binær søgning i sorterede CDX-sider (`limit=1`). Næste browser-/cron-trin henter domæner fra den fundne side. Ingen tidligere domæner end starttegnet bliver køsat. Starttegnet normaliseres til ASCII a–z/0–9; internationale domænenavne ses i deres punycode-form. Hvert trin foretager højst ét Common Crawl-kald.

Browserkontroller på desktop og mobil (kræver udviklingsværktøjet Playwright, aldrig på Plesk-serveren):

```sh
PLAYWRIGHT_BROWSERS_PATH=/workspace/.tools/playwright node php/tests/browser.cjs
```

Testen bruger midlertidige konti og testdata, kontrollerer alle fire paneler, søgning, selvstændig sideinddeling, synlige diagramsegmenter, valg af antal/starttegn og mobil-layout. Den starter ikke en ekstern scanning.

En lille manuel ekstern test med startpunkt M:

```sh
/workspace/.tools/php/php php/tests/live.php 3 m
```

Eksterne tests kan fejle ved Common Crawls HTTP 504 eller timeouts, selv om lokal funktionalitet og serveradgang fungerer.

## Domæneopdagelse i 0.3.1

Primær kilde er nu den offentlige Tranco-liste: `https://tranco-list.eu/download/daily/top-1m.csv.zip`. Scanneren downloader selv listen, verificerer ZIP-arkivets struktur/længde/CRC og udvælger primære .dk-domæner. Ingen URL'er indtastes manuelt. Der er ikke brug for PHP ZipArchive; zlib er nok. Arkivet er begrænset til 12 MB komprimeret og 40 MB udpakket, og gemmes aldrig som eksekverbare filer. Den første live-liste indeholdt 2.402 .dk-domæner; dette er et udsnit af populære websteder, ikke alle .dk-domæner.

Domæner gemmes i den private SQLite-tabel `domains`, sorteres lokalt og vælges fra starttegnet og frem op til brugerens ønskede antal. Cachen genbruges 24 timer; en ældre verificeret cache kan bruges ved opdateringsfejl. Common Crawl er reserve, hvis ingen katalogdata er til rådighed. Inventar- og seek-logikken ovenfor bruges kun i denne reservevej. Datakilde og mangel på nok domæner vises i dashboardet.

Tranco: Victor Le Pochat, Tom Van Goethem, Samaneh Tajalizadehkhoob, Maciej Korczyński og Wouter Joosen, *Tranco: A Research-Oriented Top Sites Ranking Hardened Against Manipulation*, NDSS 2019. Liste og metode: https://tranco-list.eu/. Downloades automatisk på serveren; kataloget er ikke inkluderet i uploadpakken.

Livevalidering af 0.3.1: Tranco-listen blev hentet og verificeret under en PHP-hukommelsesgrænse på 128 MB. Tre automatisk opdagede domæner fra M blev kontrolleret: to normale HTTP 200-resultater og én håndteret forbindelsesfejl. Den fulde 10.000-domænescanning er ikke kørt; listen indeholdt 2.402 .dk-domæner ved hentningen.

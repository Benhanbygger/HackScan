# HackScan til Plesk — upload uden SSH

## 1. Inden upload

- Vælg PHP 8.4 og FPM i Plesk. Standardgrænserne 128 MB og 30 sekunder kan beholdes.
- Din test har allerede bekræftet cURL, PDO SQLite og adgang til Common Crawls indeksoversigt.
- Slet den gamle `hackscan-test.php`, hvis den stadig ligger i `httpdocs`.
- Tag en backup af eksisterende filer, hvis mapperne nedenfor allerede findes. Overskriv ikke en eksisterende installation eller database blindt.

## 2. Upload og udpak

Åbn **Files** i Plesk. Gå til mappen **oven over `httpdocs`** (abonnementets hjemmemappe).

Upload `HackScan-Plesk.zip` og vælg **Extract / Udpak** i denne mappe. Pakken indeholder:

```
abonnementets hjemmemappe/
├── hackscan-private/
│   ├── app.php
│   ├── core.php
│   ├── worker.php
│   └── .htaccess
├── httpdocs/
│   ├── index.html              ← din eksisterende fil; pakken ændrer den ikke
│   └── hackscan/
│       ├── index.php
│       ├── app.js
│       ├── style.css
│       └── .htaccess
└── UPLOAD-VEJLEDNING.md
```

**Vigtigt:** `hackscan-private` skal ligge ved siden af `httpdocs`, aldrig inde i den offentlige mappe. Databasen, adgangskodehash og sessioner oprettes i `hackscan-private/data`. De må ikke kunne hentes via en webadresse.

Hvis du bruger SFTP/FTPS, kan du i stedet pakke ZIP-filen ud på din computer og uploade mapperne til de tilsvarende placeringer. Medtag `.htaccess`-filerne. Du behøver hverken slette `index.html` eller bruge SSH.

Slet ZIP-filen fra serveren efter udpakning. Uploadvejledningen kan også fjernes fra serveren.

## 3. Opret en engangsnøgle

I Plesk **Files**, åbn `hackscan-private` og opret en fil ved navn:

```
setup-key.txt
```

Skriv en tilfældig nøgle på mindst **24 tegn** i filen. Generér den gerne med din passwordmanager. Brug ikke en eksisterende adgangskode. Gem filen, og behold nøglen til næste trin. Send den ikke i chatten.

Nøglen beskytter den første opsætning, så andre ikke kan oprette din konto blot ved at kende webadressen.

## 4. Åbn HackScan og opret adgang

Åbn i browseren:

**https://produktion01.say-it.dk/hackscan/**

- Ved en certifikatadvarsel: stop og få HTTPS-certifikatet på plads via Plesks SSL/TLS-indstillinger.
- Indtast engangsnøglen fra `setup-key.txt`.
- Vælg din egen adgangskode på 14–72 bytes og gentag den. En lang adgangssætning er velegnet.
- Klik **Opret adgang**.

Du bliver logget ind. Engangsnøglen slettes automatisk; hvis programmet viser en advarsel om filen, slet den manuelt i Plesk. Der er ingen standardkonto eller indbygget adgangskode.

## 5. Test første scanning

Vælg et mål på **1–10.000 domæner** og et **starttegn (0–9 eller A–Z)**. Klik **Start scanning**, og lad fanen stå åben. Programmet henter selv en offentlig Tranco-domæneliste, gemmer .dk-domæner privat og vælger fra det valgte tegn og frem og kontrollerer ét trin ad gangen. Startpunktet er et minimum, ikke et krav om samme begyndelsesbogstav for alle resultater.

- **Bør undersøges**: forsiden ender på et andet værtsnavn, eller et sådant hop er set, men slutdestinationen kunne ikke kontrolleres.
- **Samme domæne**: ingen forskel bortset fra HTTP/HTTPS og www.
- **HTTP-fejl** / **Kontrolfejl**: et fejlresultat, ikke et bevis på hacking.
- Alle fire resultatgrupper vises samtidig, hver med sin egen sideinddeling. Søgningen øverst søger i alle gemte resultater.
- **Hent CSV** eksporterer gemte resultater.
- **Stop** afbryder kommende trin. En igangværende HTTP-forespørgsel får først lov at afslutte.

Tranco-listen genbruges i 24 timer. Kan den ikke opdateres, genbruges en ældre verificeret liste; uden en gemt liste forsøges Common Crawl som reserve. Hvis Common Crawl giver timeout eller HTTP 504, forsøges igen med ventetid, før det foregående indeks prøves. Fejler begge, vises fejlen, og du kan prøve igen senere. En vellykket hentning af indeksoversigten garanterer ikke, at selve domænesøgningen altid svarer.

En ny scanning tager udgangspunkt i det valgte starttegn og kan læse flere indekssider, indtil målet er nået eller en grænse/fejl stopper søgningen. Det er et udsnit, ikke en komplet eller garanteret frisk liste over danske hjemmesider. Eksisterende domæner kan blive kontrolleret igen.

## 6. Valgfrit: kør videre uden en åben browser

I Plesk **Scheduled Tasks → Add Task**:

- Vælg **Run a PHP script**.
- Vælg **PHP 8.4**.
- Vælg scriptet `hackscan-private/worker.php` via filvælgeren. Hvis der kræves en absolut sti, brug stien vist i File Manager — den afhænger af abonnementets placering.
- Planlæg det hvert minut (`* * * * *` i crontab-feltet, hvis det vises).
- Kør først **Run Now**, og kontrollér at der ikke kommer en fejl.

Opgaven behandler højst ét trin pr. kørsel og bruger samme lås som browseren. Den fortsætter kun en scanning, du allerede har startet via websiden; den starter ikke nye scanninger af sig selv. Et domæne med flere hop kan derfor tage flere minutter uden browseren.

Hvis dit abonnement ikke tilbyder denne opgavetype, fungerer scanning stadig, mens websiden er åben. Den færdigbyggede kode skal først testes på din Rackhosting-server; den lokale test er ikke en verificering af deres planlagte opgaver.

## Afgrænsning og drift

- Der kontrolleres HTTP 301/302/303/307/308, op til 10 hop. JavaScript og HTML meta-refresh understøttes ikke.
- Andre underdomæner end www bliver også markeret. En viderestilling beviser ikke hacking.
- Kun offentlige IP-adresser og port 80/443 tillades. Destinationen valideres ved hvert hop; TLS-verifikation bevares.
- HTTPS forsøges først. HTTP forsøges kun ved en forbindelsesfejl/timeout på den første HTTPS-adresse, ikke ved en certifikatfejl.
- Databasen ligger i den private mappe. SQLite-filer og sessioner må aldrig flyttes ind i `httpdocs`.
- Hold PHP og Plesk opdateret. Tag backup af `hackscan-private/data/hackscan.sqlite3`. Kopiér ikke en aktiv SQLite-fil under en igangværende skrivning; stop scanninger og brug Plesks backupfunktion.
- Hvis adgangskoden glemmes, skal kontoen nulstilles i den private database; der er ingen offentlig nulstillingsfunktion. Slet ikke databasen uden backup — den indeholder også resultaterne.
- Appen indeholder ingen analysesoftware, skjulte nøgler, tredjepartspakker eller loginoplysninger.

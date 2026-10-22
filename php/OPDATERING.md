# Opdatér HackScan til 0.5.0

## Nyt

- Klik på et domænenavn for en sikkerhedsrapport. Den separate **↗**-genvej åbner hjemmesiden i en ny fane.
- Foreløbig sikkerhedskarakter A–F og 0–100, 45 eksplicitte kontrolposter, evidens, observationssikkerhed og forbedringsforslag i tre klasser: sårbarhed, kompromitteringsindikator og risikofaktor.
- Ukendt / ikke udført er tydeligt og tæller ikke som bestået. Læs [SECURITY.md](SECURITY.md) for præcis dækning og begrænsninger.
- Eksterne redirectmål er røde. Faktiske redirectkoder og HTTP-fejlkoder står i deres egen kolonne med hvid tekst på rød baggrund. WWW/ikke-WWW og HTTP/HTTPS alene tælles ikke som eksterne domæneskift. Gamle redirectkoder kan ikke gættes og kræver en ny kontrol; historiske præcise “HTTP 404”-svar kan genbruges.
- **Brugere** i venstremenuen giver administratorer mulighed for at oprette personlige konti med rollerne administrator, bruger eller læser. Konti kan deaktiveres, roller ændres og adgangskoder nulstilles. Gamle sessioner afsluttes ved ændringer.
- Eksisterende domæneopdagelse med Tranco-cache og Common Crawl-reserve bevares.

## Upload i Plesk

1. Stop scanningen. Luk andre HackScan-faner. Deaktivér en eventuel planlagt PHP-opgave under opdateringen.
2. Tag backup via Plesk. Bevar især `hackscan-private/data`.
3. Åbn GitHub → `dist/HackScan-Opdatering-0.5.0.zip` → **Download raw file**.
4. Upload ZIP-filen i Plesk **Files → Home directory**, hvor `httpdocs` og `hackscan-private` ligger side om side.
5. Vælg **Extract / Udpak**, og tillad overskrivning af programfilerne. Pakken indeholder disse ni program-/assetfiler samt vejledning:

   ```
   hackscan-private/app.php
   hackscan-private/core.php
   hackscan-private/security.php
   hackscan-private/details.php
   hackscan-private/users.php
   httpdocs/hackscan/app.js
   httpdocs/hackscan/detail.js
   httpdocs/hackscan/admin.js
   httpdocs/hackscan/style.css
   ```

6. **Slet ikke data-mappen, databasen eller eksisterende filer manuelt. Opret ingen ny engangsnøgle.** Nye tabeller oprettes automatisk uden at nulstille resultater eller adgangskode.
7. Åbn `https://produktion01.say-it.dk/hackscan/` igen. Log ind med brugernavnet **admin** og din hidtidige adgangskode. Andre brugeradgange oprettes herefter under **Brugere**.
8. Genindlæs hårdt, hvis browseren viser gammelt design. CSS/JS har nye versionsnumre. Hvis PHP stadig kører gammel kode, kontrollér Plesks OPcache-indstilling; upload ikke ukritisk filerne til en anden mappe.
9. Test med et lille antal, fx 1–5 domæner, eller åbn en gammel rapport og klik **Kontrollér domænet igen**. Lad dashboardet stå åbent, indtil de offentlige sikkerheds- og DNS-trin også er afsluttet.
10. Kontrollér, at WWW-normalisering ikke markeres som ekstern redirect; at faktiske HTTP-fejlkoder vises særskilt; og at en ny læserkonto ikke kan starte scanninger eller administrere brugere.
11. Genaktivér eventuel planlagt PHP-opgave og slet ZIP-filen fra serveren.

Alle gamle domæner og resultater bevares, men de får **ikke** automatisk en sikkerhedskarakter uden en ny scanning. En gammel score erstatter ikke en ny vurdering, mens en genkontrol er i gang.

PHP 8.4, cURL, PDO SQLite og zlib er fortsat nok. OpenSSL-funktioner bruges til certifikatfingeraftryk, når de findes; TLS-verifikation i cURL bevares altid. Ingen Composer, Python, browser-runtime eller SSH kræves på Plesk-serveren.

Scanningen kontakter derudover `api.wordpress.org`, `www.cisa.gov` og ved behov den officielle CISA-spejling på `raw.githubusercontent.com`. Kun offentlige sikkerhedsdata hentes; mål-URL'er sendes ikke til disse feeds. Feedfejl gør de afhængige kontroller ukendte og stopper ikke øvrige kontroller.

Der er flere offentlige trin pr. domæne, så en scanning tager længere tid end en ren redirect-kontrol. Et trin foretager højst ét HTTP-opslag (to ved initial HTTP-fallback), eller en afgrænset DNS-del, så PHP ikke skal køre en hel scanning i én forespørgsel.

Brug fuld backup ved en eventuel tilbagerulning. En gammel programversion har ikke de nye adgangsroller og rapporter, selv om tabellerne bevares. Uploadpakken indeholder ingen konti, databaser, nøgler eller virkelige adgangskoder.

## Rettelse i 0.5.0

Netværksfejl håndteres også på PHP/cURL-installationer uden konstanten `CURLE_PEER_FAILED_VERIFICATION`. TLS-verifikation forbliver aktiveret. Rettelsen kræver kun udskiftning af `hackscan-private/security.php`; den samlede opdateringspakke kan også bruges. Bevar eksisterende data. Start en ny scanning efter opdateringen; allerede gemte resultater bevares.

## Ryd alle resultater

Administratorer kan vælge **Brugere → Ryd alle resultater** og bekræfte sletningen. Det stopper scanningen og fjerner alle scanningsresultater, rapporter og historik for alle brugere. Konti, adgangskoder, indstillinger og domæneliste bevares. Sletning kan ikke fortrydes; eksportér eventuelt CSV først.

## Navneserverfiltre, manuel scanning og resultatvisning (0.5.0)

- Vælg udbydere med flueben. Ingen valg betyder alle; flere valg betyder OR. Der matches kun selve udbyderdomænet eller underdomæner heraf, ikke vilkårlige delstrenge.
- NS-opslag foretages ét pr. trin før HTTP-scanningen. Lokale DNS-fejl eller tomme svar prøves én gang via Google Public DNS over HTTPS i et separat trin. Ubrugelige svar fra begge kilder springes over med synlig tæller. Listen søges fra starttegnet, indtil det ønskede antal match er fundet eller kandidaterne er opbrugt. Det kan tage længere tid med snævre filtre.
- Tranco-filteret undersøger alle tilgængelige kandidater fra starttegnet. Common Crawl-reserven undersøger højst 10.000 kandidater (mindst 500, ellers 20 gange målantallet) og fortsat højst 100 indekssider. Et match kan ikke garanteres. NS-domænet er ikke nødvendigvis webhosten, og filtre påvirker ikke historisk gemte resultater.
- Feltet **Scan ét domæne** scanner et offentligt domæne uden automatisk opdagelse, startbogstav eller NS-filter. HTTP/HTTPS og www normaliseres; stier, porte, loginoplysninger, IP-adresser og interne destinationsadresser accepteres ikke. IDN skal skrives som punycode. En igangværende scanning skal stoppes først.
- Domæner uden registrerede fund skjules som standard. **Vis også domæner uden registrerede fund** viser dem igen. Domæner med kontrolfejl eller manglende sikkerhedsvurdering bevares i visningen. Søgning og sidetal bruger filteret; statistik og CSV indeholder fortsat alle gemte resultater. Ingen fund betyder ikke dokumenteret sikkerhed.
- Stop eller rydning annullerer også NS-køen. Eksisterende konti, adgangskoder og resultater bevares under opdatering.

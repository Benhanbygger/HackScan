# Sikkerhedsvurderinger i HackScan 0.4.0

HackScan laver en **foreløbig vurdering af offentlige sikkerhedssignaler**, ikke en fuld penetrationstest, malwaregaranti eller attest for, at et domæne er sikkert. Alle 45 katalogposter har en eksplicit status. Ikke udførte og ukendte kontroller tæller aldrig som beståede.

## De tre klasser

- **Sårbarhed:** et specifikt muligt advisory-/versionsmatch. I denne udgave er det afgrænset til kendte jQuery- og Lodash-intervaller. Rapporten siger tydeligt, at assetsporet og anvendeligheden skal verificeres; der udføres ingen udnyttelse.
- **Kompromitteringsindikator:** en konkret observeret afvigelse, eksempelvis skjulte eksterne links med spamord, et simpelt klient-redirect eller et “hacked by”-tekstspor. Artikler, SSO, legitime flytninger og normal drift kan give lignende signaler. Lav observationssikkerhed fremgår af rapporten.
- **Risikofaktor:** konfiguration eller teknologi, eksempelvis offentligt oplyst PHP uden officiel support, manglende beskyttelsesheaders eller en overvågende DMARC-politik. Dette er ikke automatisk en sårbarhed eller hacking.

Alle kontroller viser potentiel alvor (kritisk/høj/mellem/lav), observationssikkerhed (høj/mellem/lav/ikke fastlagt), evidens, forbedringsforslag og officiel kilde, når relevant.

## Hvad der udføres

Det normale forsidesvar og de allerede fulgte HTTP-redirects analyseres. HTML er begrænset til 256 KB. Ingen eksterne scripts, iframes, formularer eller downloadlinks indlæses eller afvikles. Der testes ikke login, databaser eller ekstra filstier.

- Headers, cookies **uden værdier**, TLS-verifikation, HTTP/HTTPS, HSTS, CSP, clickjacking-headers og offentlige versionsspor.
- Simpel statisk HTML-analyse: eksplicitte HTTP-ressourcer, meta-refresh, bogstavelige inline JavaScript-redirects, skjulte eksterne iframes, afgrænsede spamkombinationer, fejlmarkører og mappeliste på forsiden.
- WordPress-version fra generator-meta, hvis den findes, sammenholdt med den officielle versionsoversigt. Versionssporet er ikke en bekræftet installation; gamle hovedgrene kan få sikkerheds-backports.
- jQuery- og Lodash-versioner fra bestemte assetnavne eller versionsparametre. De få medfølgende dokumenterede intervaller: jQuery CVE-2020-11022 / CVE-2020-11023 og Lodash 4.x før 4.17.21 / CVE-2021-23337. Andre biblioteker og CVE'er er ikke generelt dækket.
- Konkrete CVE-kandidater sammenholdes med CISA KEV. En produktbetegnelse alene bruges aldrig til at erklære en CVE. CISA's officielle GitHub-spejling bruges i et separat trin, hvis det primære feed afviser forbindelsen.
- Offentlige DNS-opslag for SPF og DMARC. Ukendt DNS-svar er ikke lig med manglende record. Ufulgte DMARC-CNAME'er markeres ukendte. SPF-kæde og alignment valideres ikke fuldt.
- Fingeraftryk af tekst, titel, IP-adresser og certifikat sammenlignes med tidligere observationer, hvis de findes. Ændringer alene giver ikke kompromitteringspoint.

## Ikke udført / afgrænset

Webshells kræver intern filadgang. Backupfiler, `.env`, Git-metadata, administrationsstier, debugstier og porte sonderes ikke på automatisk fundne domæner. Der downloades ikke hemmeligheder. Disse kontroller kræver et særskilt autoriseret omfang og er **ikke aktiveret**.

Der er ikke tilsluttet en komplet PHP-CVE-, WordPress-plugin- eller theme-database. Serverheaderen bruges ikke som bevis på en sårbar eller usupporteret distribution. Browser-rendering, dynamiske scripts, JavaScript-cookies, generel malwaredetektion, phishing-omdømme, Google Safe Browsing, DNSSEC-kædevalidering, subdomain takeover, ASN-historik og forsøg på gamle TLS-protokoller er ikke implementeret. Det står i hver relevant katalogpost.

Malware påstås ikke ud fra `eval`, base64 eller obfuskering alene. Et login på et eksternt domæne påstås ikke at være phishing. `Access-Control-Allow-Origin: *` med credentials er ikke automatisk en udnyttelig CORS-fejl, da browsere afviser den kombination.

## Karakter og dækningsgrad

En vurderbar HTTP-forside starter på 100. Fund giver grundfradrag: kritisk 25, høj 12, mellem 5, lav 2. Det ganges med observationssikkerhed (1 / 0,6 / 0,3) og med 0,7 for risikofaktorer. Headergruppen kan højst koste 20. Samme JavaScript-/CVE-/KEV-signal tælles kun én gang i pointfradraget.

Karakterer: A ≥90, B ≥75, C ≥60, D ≥40, E ≥20, F <20. Skalaen er en produktregel, ikke CVSS eller en officiel sikkerhedscertificering. Bogstav, score og **foreløbig** vises sammen med antallet af afgrænsede observationer ud af 45. Et 403/404/500-svar eller en mislykket HTTP-kontrol får ikke automatisk A; vurderingen kan være **ikke vurderbar**.

CVE-versioner fra offentlige signaturespor kan være misvisende eller have backports. Ingen rapport kalder dem bekræftet udnyttelige. En normal viderestilling påvirker ikke sikkerhedsscoren alene.

## Datakilder og privatliv

Officielle kilder: PHP supportoversigt, WordPress API, CISA KEV og `cisagov/kev-data` samt de navngivne NVD-advisories. WordPress- og KEV-data forsøges opdateret dagligt. Manglende data markeres som utilgængelige; ældre end syv dage bruges ikke til nye automatiske versionssammenligninger.

Softwaredata downloades som offentlige lister. Scannede URL'er eller HTML sendes ikke til en ekstern trussels-API. Normale DNS-opslag bruger serverens resolver. HTML, cookieværdier og formularværdier gemmes ikke i sikkerhedsrapporterne. Korte, offentlige metadata og fingeraftryk gemmes privat i SQLite; højst ti historikoversigter pr. domæne.

Et HTTP-svar kan komme fra et andet domæne efter en legitim flytning. Rapporten viser hvilket slutmål HTTP-fundene gælder. DNS-fund gælder det oprindelige domæne.

## Brugere og fælles data

Den eksisterende konto migreres til **admin**, med samme adgangskode. Eksisterende sessioner kræver nyt login. Administratorer opretter brugere, tildeler roller, nulstiller adgangskoder og deaktiverer konti. Adgangskoder hashes; tidligere sessioner afvises efter kontoændringer. Den sidste aktive administrator beskyttes.

Roller: administrator = fuld administration + scanning; bruger = scanning og læsning; læser = rapporter og eksport. Alle konti deler resultater og en fælles scanningskø; dette er ikke en løsning med isolerede kundedata. Der er ingen selvbetjent mailnulstilling eller automatisk udsendelse af adgangskoder. Administrationsændringer logges uden adgangskoder, og højst 1.000 logposter bevares.

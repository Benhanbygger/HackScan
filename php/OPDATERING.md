# Opdatér den eksisterende HackScan til 0.3.1

Denne opdatering bevarer din nuværende konto, adgangskode og database. Du skal **ikke** oprette en ny engangsnøgle eller slette mapper.

## Rettelsen i 0.3.1

Fejlen **Kunne ikke læse indeksstørrelsen (HTTP 504)** kommer fra Common Crawl-opslaget, ikke SSH-indstillingen `/bin/bash`.

Scanneren henter nu automatisk Trancos offentlige top-1-million-liste, udvælger primære `.dk`-domæner, og gemmer dem privat i SQLite. Starttegn og antal vælges fra den gemte, sorterede liste uden opslag efter Common Crawls indeksstørrelse. Den første livehentning indeholdt 2.402 .dk-domæner; tallet kan ændre sig dagligt, og listen dækker ikke alle danske hjemmesider.

Listen genbruges i 24 timer. Ved mislykket opdatering bevares en ældre, valideret liste. Hvis ingen liste findes og Tranco fejler, forsøges Common Crawl som reserve. Ingen ekstern datakilde kan garanteres tilgængelig. M betyder fortsat **M og frem**, ikke kun M-domæner. Ved færre domæner end ønsket vises det faktiske antal.

PHP's almindelige zlib-understøttelse bruges til CSV-arkivet; den valgfrie ZIP-udvidelse kræves ikke. ZIP-struktur, udpakket størrelse og CRC kontrolleres, og arkivet skrives aldrig ud som filer. Parserens målte maksimale hukommelsesforbrug ved live-listen var under 70 MB, inden for serverens 128 MB.

## Dashboardet fra 0.3.0

- Lyst dashboard med venstremenu, lille skjoldlogo ved HackScan-navnet og lilla detaljer.
- Fire resultatgrupper vises samtidig: **Alle domæner**, **Bør undersøges**, **Samme domæne** og **Fejl**. Hver gruppe har sin egen sideinddeling.
- Søgning på tværs af alle gemte resultater. Kort og diagram viser de samlede, faktiske statusantal; søgningen filtrerer tabellerne.
- Vælg **1–10.000 domæner** pr. scanning.
- Vælg **0–9 eller A–Z** som alfabetisk startpunkt. M betyder **fra M og frem**, ikke kun navne, som begynder med M. `www` ignoreres. Nye opslag tager udgangspunkt i primære .dk-domæner; gamle resultater bevares.
- Startposition og antal findes lokalt i Tranco-listen. Hvis Common Crawl bruges som reserve, kræves stadig eksterne indeksopslag.
- Antallet er et mål: ingen opfundne resultater, hvis Common Crawl ikke kan levere nok. Eventuelle mangler eller fejl vises. Højst 100 indekssider undersøges i en scanning.
- Midlertidige netværksfejl får op til to genforsøg med ventetid, før en reservekilde forsøges. Delvist fundne domæner bevares og kontrolleres, også hvis resten af søgningen fejler.

## Upload uden SSH og uden Git-deployment

1. Stop en igangværende scanning, og luk andre faner med HackScan. Hvis du har oprettet en planlagt opgave i Plesk, så deaktivér den under opdateringen.
2. Tag en backup via Plesk. Bevar især `hackscan-private/data`.
3. Hent **HackScan-Opdatering-0.3.1.zip** fra repositoryets `dist`-mappe på GitHub med **Download raw file**.
4. I Plesk **Files**, gå til **Home directory**, hvor `httpdocs` og `hackscan-private` ligger side om side.
5. Upload ZIP-filen og vælg **Extract / Udpak**. Tillad overskrivning af de fire programfiler i pakken:

   ```
   hackscan-private/app.php
   hackscan-private/core.php
   httpdocs/hackscan/app.js
   httpdocs/hackscan/style.css
   ```

6. Slet den uploadede ZIP-fil. Slet ikke databasen, `data`-mappen eller de øvrige mapper.
7. Åbn `https://produktion01.say-it.dk/hackscan/` igen, og genindlæs. Du bruger samme login. CSS og JavaScript har nye versionsnumre, så de gamle filer ikke genbruges fra browserens cache.
8. Test med et lille antal, fx **5**, og et starttegn. Kontrollér det faktiske resultat og eventuelle beskeder om Common Crawl. Aktivér din eventuelle planlagte opgave igen.

Hvis noget går galt, kan de fire gamle programfiler gendannes fra backup. Databasen får en ekstra tabel med opdagede domæner. Eksisterende konti og resultater slettes ikke. Hvis de gamle programfiler gendannes, ignorerer de den ekstra tabel.

Den fulde `HackScan-Plesk.zip` er også opdateret, men til din eksisterende installation er opdateringspakken nok. Den indeholder **ingen** konti, nøgler eller databaser.

Scanneren følger fortsat kun HTTP-viderestillinger. En ændret domæneadresse beviser ikke hacking.

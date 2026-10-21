# Opdatér den eksisterende HackScan til 0.3.0

Denne opdatering bevarer din nuværende konto, adgangskode og database. Du skal **ikke** oprette en ny engangsnøgle eller slette mapper.

## Det nye dashboard

- Lyst dashboard med venstremenu, lille skjoldlogo ved HackScan-navnet og lilla detaljer.
- Fire resultatgrupper vises samtidig: **Alle domæner**, **Bør undersøges**, **Samme domæne** og **Fejl**. Hver gruppe har sin egen sideinddeling.
- Søgning på tværs af alle gemte resultater. Kort og diagram viser de samlede, faktiske statusantal; søgningen filtrerer tabellerne.
- Vælg **1–10.000 domæner** pr. scanning.
- Vælg **0–9 eller A–Z** som alfabetisk startpunkt. M betyder **fra M og frem**, ikke kun navne, som begynder med M. `www` ignoreres. Nye opslag tager udgangspunkt i primære .dk-domæner; gamle resultater bevares.
- For startpunkter efter 0 finder programmet først den relevante indeksside. Det kræver flere opslag og kan tage tid. Ved flere ønskede domæner hentes flere sider.
- Antallet er et mål: ingen opfundne resultater, hvis Common Crawl ikke kan levere nok. Eventuelle mangler eller fejl vises. Højst 100 indekssider undersøges i en scanning.
- Midlertidige netværksfejl får op til to genforsøg med ventetid, før et foregående indeks forsøges. Delvist fundne domæner bevares og kontrolleres, også hvis resten af søgningen fejler.

## Upload uden SSH og uden Git-deployment

1. Stop en igangværende scanning, og luk andre faner med HackScan. Hvis du har oprettet en planlagt opgave i Plesk, så deaktivér den under opdateringen.
2. Tag en backup via Plesk. Bevar især `hackscan-private/data`.
3. Hent **HackScan-Opdatering-0.3.0.zip** fra repositoryets `dist`-mappe på GitHub med **Download raw file**.
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

Hvis noget går galt, kan de fire gamle programfiler gendannes fra backup. Databaseskemaet ændres ikke af denne opdatering.

Den fulde `HackScan-Plesk.zip` er også opdateret, men til din eksisterende installation er opdateringspakken nok. Den indeholder **ingen** konti, nøgler eller databaser.

Scanneren følger fortsat kun HTTP-viderestillinger. En ændret domæneadresse beviser ikke hacking.

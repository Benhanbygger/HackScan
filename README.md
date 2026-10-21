# HackScan — PHP og Python

**Til Plesk/FTP:** Brug PHP-versionen i [php/](php/README.md) og følg [uploadvejledningen](php/UPLOAD-VEJLEDNING.md). Den kræver ikke Python eller SSH.

# Python-prototypen

En første Python-version, der automatisk finder .dk-forsider i Common Crawl og markerer HTTP-viderestillinger til andre værtsnavne. Fund er signaler til manuel undersøgelse, ikke bevis på hacking.

## Start

Python 3.12+; ingen eksterne pakker, nøgler eller installation nødvendig.

```sh
cd /workspace/HackScan
python hackscan.py
```

Serveren lytter på loopback-port 8000. Brug websidens **Start scanning**. Der scannes kun på brugerens initiativ; højst 50 domæner pr. kørsel, sekventielt og med ét sekund mellem domæner. Resultater gemmes i `.local/hackscan.sqlite3`. `PORT` og `HACKSCAN_DB` kan tilsidesætte standarderne. Stop med Ctrl-C. Serveren er til lokal udvikling; kræver autentifikation og yderligere sikring før offentlig drift.

```sh
python -m unittest discover -s tests -v
```

## Afgrænsning

- Domæner opdages via `index.commoncrawl.org`; ingen manuel URL-liste. Datakilden kræver netadgang og kan være langsom/utilgængelig. Kun første side af det nyeste indeks læses; ved fejl forsøges det foregående indeks (maks. 8 MB), så gentagne scanninger kan give samme udsnit.
- HTTP 301, 302, 303, 307 og 308 følges op til ti gange. JavaScript og HTML meta-refresh understøttes ikke endnu.
- HTTP/HTTPS og `www` ignoreres ved sammenligning. Andre værtsnavne, også underdomæner, markeres til undersøgelse.
- HTTPS forsøges først. Hvis den første forbindelse fejler, forsøges HTTP. TLS-certifikater verificeres.
- Private/reserverede destinations-IP'er og andre porte end 80/443 afvises ved hvert hop. Forbindelsen fastlåses til den validerede IP, også via HTTP CONNECT når cloudmiljøet bruger en HTTP-proxy.
- Ingen angreb, loginforsøg eller scanning af undersider. HTTP-fejl og forbindelsesfejl vises særskilt.
- Websiden afvikler eller åbner ikke fundne destinationer automatisk.

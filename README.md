# php2shell-scan

Externe-oppervlak scanner voor **PHP2Shell** (CVE-2026-109618 / CVE-2026-109619), de twee kritieke
RCE-kwetsbaarheden in de PHP-interpreter die op 21 oktober 2026 zijn gepatcht.

Fingerprint je *eigen* publieke hosts op PHP-aanwezigheid en -versie en vergelijk die met de
gefixte releases. Niet-intrusief: alleen gewone HTTP GET-requests, geen exploitpogingen.
Alleen Python 3.8+ standaardbibliotheek, geen dependencies.

## Gebruik

```bash
python3 php2shell_scan.py example.nl www.example.nl 203.0.113.10
python3 php2shell_scan.py -f hosts.txt -o rapport.json --csv rapport.csv
python3 php2shell_scan.py -f hosts.txt --fixed 8.4=8.4.27 --fixed 8.3=8.3.36
```

Zonder schema worden https én http geprobeerd. Exit-code `2` als er iets kwetsbaars is gevonden
(handig in cron/CI), anders `0`.

| Optie | Betekenis |
|---|---|
| `-f FILE` | targets uit bestand, één per regel (`#` = commentaar) |
| `-o FILE` / `--csv FILE` | JSON- / CSV-rapport |
| `--fixed 8.4=8.4.27` | gefixte versie per branch overschrijven (herhaalbaar) |
| `--path /x.php` | extra pad proberen (herhaalbaar) |
| `host@IP` / `--origin IP` | rechtstreeks naar het origin-IP verbinden, met de echte hostnaam in Host/SNI (omzeilt CDN/WAF) |
| `--no-behaviour` | gedragsfingerprints overslaan |
| `--quick` | alleen `/` en `/index.php` |
| `-t`, `-c`, `--delay` | timeout, gelijktijdigheid, pauze tussen requests |
| `--insecure` | TLS-certificaten niet valideren |

## Achter een CDN, WAF of reverse proxy?

Een edge (Cloudflare, Akamai, Sucuri, Imperva, CloudFront, Fastly, Azure Front Door, …) stript meestal
`X-Powered-By` en andere versie-headers. De scanner doet daar drie dingen tegen:

1. **Edge-detectie** – herkent de CDN/WAF aan zijn headers en meldt `GEMASKEERD` in plaats van een
   vals "geen PHP gezien".
2. **Gedragsfingerprints** die een proxy niet verwijdert: PHP's vaste `Expires: Thu, 19 Nov 1981`
   sessieheader, php-fpm's `File not found.` / PHP-CGI's `No input file specified` op een
   niet-bestaand `.php`-pad, verschil in afhandeling tussen `.php` en `.txt`, en de PHP easter egg
   (bewijst PHP < 5.5 = EOL).
3. **Origin direct scannen** – jij kent je eigen origin-IP's. Met `host@IP` verbindt de scanner
   rechtstreeks met de server achter de edge, met de juiste `Host`-header en SNI, en ziet wat de
   proxy anders wegfiltert:

   ```bash
   python3 php2shell_scan.py www.example.nl@203.0.113.10
   python3 php2shell_scan.py -f hosts.txt --origin 203.0.113.10
   ```

   Gebruik `--insecure` als het origin-certificaat niet op de hostnaam past. Werkt dit niet, dan
   accepteert je origin alleen verkeer van de CDN (goed!) en moet je intern met `php -v` kijken.

## Statussen

- `KWETSBAAR` – versie zichtbaar en lager dan de fix
- `KWETSBAAR-EOL` – PHP 5.x / 7.x / 8.0 / 8.1: krijgt geen patch, alleen upgraden helpt
- `WAARSCHIJNLIJK-KWETSBAAR` – alleen de branch (bv. `8.4`) zichtbaar, patchniveau onbekend
- `GEMASKEERD` – achter een CDN/WAF, versie onzichtbaar; scan de origin met `host@IP`
- `GEPATCHT` – versie ≥ gefixte release
- `ONBEKEND` / `GEEN-PHP-GEZIEN` – **niet** hetzelfde als veilig: veel servers verbergen de
  versie (`expose_php=Off`, reverse proxy, WAF). Controleer die hosts intern met `php -v` /
  `php-fpm -v` of vraag het je hoster.

## Gefixte versies

Ingebouwd: 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35. Controleer de officiële nummers op
<https://www.php.net/> en overschrijf zo nodig met `--fixed`.

## Disclaimer

Gebruik dit alleen tegen systemen waarvoor je toestemming hebt. De tool doet uitsluitend
versie-fingerprinting; een "schoon" resultaat is geen garantie dat PHP niet draait of gepatcht is.

## Bronnen

- [PHP security team announcement](https://www.php.net/)
- [CERT-EU advisory 2026-018](https://cert.europa.eu/publications/security-advisories/2026-018/)
- [Patchstack](https://patchstack.com/articles/php-major-vulnerability-alert-10-2026/) ·
  [Huntress](https://www.huntress.com/blog/php2shell-leaked-critical-php-vulnerabilities) ·
  [Sansec](https://sansec.io/research/php2shell)

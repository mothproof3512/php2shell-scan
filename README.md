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
| `--fetch-fixed` | laatste releases per branch live van php.net ophalen en als gefixte versies gebruiken |
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

Ingebouwd: 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 (de bij de release-aankondiging verwachte nummers).
Met `--fetch-fixed` haalt de scanner per branch de laatste release op van de officiële php.net
release-feed en gebruikt die als hij nieuwer is dan de ingebouwde waarde. Meldt php.net nog een
oudere versie (release nog niet uit) of is php.net onbereikbaar, dan blijft de ingebouwde waarde
staan en zie je dat in het rapport. Handmatig overschrijven kan altijd met `--fixed 8.4=8.4.27`.

Let op: Linux-distro's (Debian, Ubuntu, RHEL) backporten fixes vaak zónder het versienummer te
verhogen. Een `KWETSBAAR`-melding op een distro-pakket betekent dus: controleer op de server zelf
met `apt changelog php8.x-fpm | grep CVE-2026-10961` of `rpm -q --changelog php-fpm | grep CVE-2026-10961`.

## Disclaimer

Gebruik dit alleen tegen systemen waarvoor je toestemming hebt. De tool doet uitsluitend
versie-fingerprinting; een "schoon" resultaat is geen garantie dat PHP niet draait of gepatcht is.

## Bronnen

- [PHP security team announcement](https://www.php.net/)
- [CERT-EU advisory 2026-018](https://cert.europa.eu/publications/security-advisories/2026-018/)
- [Patchstack](https://patchstack.com/articles/php-major-vulnerability-alert-10-2026/) ·
  [Huntress](https://www.huntress.com/blog/php2shell-leaked-critical-php-vulnerabilities) ·
  [Sansec](https://sansec.io/research/php2shell)

  ## Workflow voor grotere netwerken.

  ### 1. Webpoorten vinden
```
nmap -iL ips.txt -p 80,443,8080,8443,8000,8008,8081,8888,9443,4443 \
     -PS80,443,8080,8443 --open -n -T4 -oA webservices
```

### 2. Schema afleiden uit poortnummer (onbekende poort: beide proberen)
```
grep "/open/tcp/" webservices.gnmap \
| awk '{ip=$2; for(i=1;i<=NF;i++) if($i ~ /\/open\/tcp\//){split($i,a,"/"); p=a[1];
    if(p==443||p==8443||p==9443||p==4443) print "https://"ip":"p;
    else if(p==80||p==8080||p==8000||p==8008||p==8081||p==8888) print "http://"ip":"p;
    else {print "https://"ip":"p; print "http://"ip":"p}}}' \
| sort -u > hosts_ip.txt
```

### 3. Hostnamen per IP (hosthunter) → scanner-notatie domein@IP
```
awk '/open/ {print $2}' webservices.gnmap | sort -u > live_ips.txt
```

python3 hosthunter.py live_ips.txt -f csv -o hosthunter.csv
####   kolommen: ip, hostnames (komma-gescheiden)
```
awk -F, 'NR>1 && $2!="" {n=split($2,h,";|,"); for(i=1;i<=n;i++){gsub(/ /,"",h[i]); if(h[i]!="") print h[i]"@"$1}}' \
    hosthunter.csv | sort -u > hosts_vhost.txt
```
   let op: pas de kolomnummers aan op jouw hosthunter-versie; check met: head -3 hosthunter.csv

### 4. Aanvullen met eigen bronnen (dit vindt hosthunter niet)
    - DNS-export uit je eigen zones: alle A/AAAA/CNAME → naam@IP
    - SAN-namen uit de certificaten op elk https-endpoint:
```
grep '^https' hosts_ip.txt | while read u; do
  hp=${u#https://}; ip=${hp%%:*}; port=${hp##*:}
  echo | timeout 5 openssl s_client -connect "$ip:$port" 2>/dev/null \
  | openssl x509 -noout -ext subjectAltName 2>/dev/null \
  | grep -o 'DNS:[^,]*' | sed "s/DNS://; s/^\*\.//; s|\$|:$port@$ip|"
done | sed 's/:443@/@/' | sort -u > hosts_san.txt
```

### 5. Samenvoegen: hostnamen met origin-IP + de kale IP's (default vhost)
```cat hosts_vhost.txt hosts_san.txt hosts_ip.txt | sort -u > livehosts.txt```

### 6. PHP2Shell-scan
```
python3 php2shell_scan.py -f livehosts.txt --fetch-fixed --insecure --rps 5 -c 10 \
        -o rapport.json --csv rapport.csv
```

### 7. Triage
    KWETSBAAR / KWETSBAAR-EOL  → direct patchen/upgraden, ook php-fpm/Apache herstarten
    GEMASKEERD / ONBEKEND / GEEN-PHP-GEZIEN → naar de serverkant (stap 8), niet afvinken
    ONBEREIKBAAR op https én http → poort open maar geen HTTP; negeren of handmatig kijken

### 8. Serverkant voor alles wat extern niet eenduidig is (of gewoon voor alles)
    Debian/Ubuntu:  dpkg -l 'php*' ; apt changelog php8.x-fpm | grep -E 'CVE-2026-10961[89]'
    RHEL-familie:   rpm -qa 'php*' ; rpm -q --changelog php-fpm | grep -E 'CVE-2026-10961[89]'
    Herstart:       ps -o lstart= -p $(pgrep -o php-fpm) vergelijken met pakket-installtijd
    Containers:     docker ps + docker exec <c> php -v ; images rebuilden, niet alleen patchen

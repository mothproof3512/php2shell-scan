#!/usr/bin/env python3
"""
php2shell_scan.py — externe-oppervlak scanner voor PHP2Shell
(CVE-2026-109618 / CVE-2026-109619)

Fingerprint je EIGEN publieke hosts op PHP-aanwezigheid en -versie en
vergelijk die met de gepatchte releases. Niet-intrusief: alleen gewone
HTTP GET requests, geen exploit-pogingen.

Gebruik:
    python3 php2shell_scan.py example.com www.example.com 203.0.113.10
    python3 php2shell_scan.py -f hosts.txt -o rapport.json --csv rapport.csv
    python3 php2shell_scan.py -f hosts.txt --fixed 8.4=8.4.27 --fixed 8.3=8.3.36

Achter een CDN/WAF/reverse proxy? Scan de origin direct met host@IP:
    python3 php2shell_scan.py example.com@203.0.113.10
    python3 php2shell_scan.py example.com --origin 203.0.113.10

Alleen Python 3.8+ standaardbibliotheek nodig.
"""

import argparse
import concurrent.futures
import csv
import http.client
import json
import random
import re
import socket
import ssl
import string
import sys
import time
import urllib.parse

# ---------------------------------------------------------------------------
# Gefixte versies. Dit zijn de VERWACHTE nummers op basis van de release-
# aankondiging; controleer ze na de release op https://www.php.net/ en
# overschrijf desnoods met --fixed. Branches die hier niet in staan
# (5.x, 7.x, 8.0, 8.1) zijn end-of-life en krijgen geen officiële patch.
# ---------------------------------------------------------------------------
DEFAULT_FIXED = {
    "8.5": "8.5.12",
    "8.4": "8.4.27",
    "8.3": "8.3.36",
    "8.2": "8.2.35",
}

# Paden die vaak een PHP-versie lekken. Alleen GET, niets wordt geüpload.
PROBE_PATHS = [
    "/",
    "/index.php",
    "/phpinfo.php",
    "/info.php",
    "/php.php",
    "/test.php",
    "/i.php",
    "/pi.php",
]

# PHP easter egg (werkt alleen op PHP < 5.5 → bewijst een EOL-versie)
EASTER_EGG = "/?=PHPE9568F34-D428-11d2-A769-00AA001ACF42"

VERSION_RE = re.compile(r"PHP/?\s*v?(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)
PHPINFO_RE = re.compile(r"PHP Version\s*(?:</[^>]+>\s*)*<[^>]*>?\s*(\d+\.\d+\.\d+)", re.IGNORECASE)
PHPINFO_RE2 = re.compile(r"PHP Version\s+(\d+\.\d+\.\d+)", re.IGNORECASE)

UA = "php2shell-scan/1.2 (eigen-oppervlak controle; CVE-2026-109618/109619)"

# CDN / WAF / reverse-proxy herkenning op basis van response headers
EDGE_SIGNATURES = [
    ("Cloudflare",      lambda h: "cf-ray" in h or "cloudflare" in h.get("server", "").lower()),
    ("Akamai",          lambda h: "akamaighost" in h.get("server", "").lower() or any(k.startswith("x-akamai") for k in h)),
    ("Sucuri WAF",      lambda h: "x-sucuri-id" in h or "sucuri" in h.get("server", "").lower()),
    ("Imperva/Incapsula", lambda h: "x-iinfo" in h or "incap_ses" in h.get("set-cookie", "") or "imperva" in h.get("x-cdn", "").lower()),
    ("AWS CloudFront",  lambda h: "x-amz-cf-id" in h or "cloudfront" in h.get("via", "").lower()),
    ("AWS WAF/ALB",     lambda h: any(k.startswith("x-amzn-waf") for k in h) or "awsalb" in h.get("set-cookie", "").lower()),
    ("Fastly",          lambda h: "x-fastly-request-id" in h or "fastly" in h.get("x-served-by", "").lower()),
    ("Azure Front Door", lambda h: "x-azure-ref" in h),
    ("Google Cloud LB", lambda h: "via" in h and "google" in h["via"].lower()),
    ("F5 BIG-IP",       lambda h: "bigipserver" in h.get("set-cookie", "").lower()),
    ("Varnish cache",   lambda h: "x-varnish" in h or "varnish" in h.get("via", "").lower()),
    ("Reverse proxy (generiek)", lambda h: "via" in h or "x-cache" in h),
]


def parse_version(v):
    parts = v.split(".")
    while len(parts) < 3:
        parts.append("0")
    try:
        return tuple(int(p) for p in parts[:3])
    except ValueError:
        return None


def branch_of(v):
    return ".".join(v.split(".")[:2])


def classify(version, fixed_map):
    """Geeft (status, toelichting)."""
    if not version:
        return "ONBEKEND", "PHP gezien maar geen versie zichtbaar — handmatig controleren (php -v / hoster)"
    br = branch_of(version)
    pv = parse_version(version)
    if br not in fixed_map:
        return "KWETSBAAR-EOL", f"PHP {version} is end-of-life; geen officiële patch — upgrade naar een ondersteunde branch"
    fv = parse_version(fixed_map[br])
    if pv is None or fv is None:
        return "ONBEKEND", f"Kon versie {version} niet vergelijken"
    if len(version.split(".")) < 3:
        return "WAARSCHIJNLIJK-KWETSBAAR", f"Alleen branch {version} zichtbaar; patch-niveau onbekend (fix = {fixed_map[br]})"
    if pv < fv:
        return "KWETSBAAR", f"PHP {version} < gefixte {fixed_map[br]}"
    return "GEPATCHT", f"PHP {version} >= {fixed_map[br]}"


# ---------------------------------------------------------------------------
# HTTP-laag: eigen http.client-verbinding zodat we desgewenst rechtstreeks
# naar een origin-IP kunnen verbinden met de echte hostnaam in Host/SNI.
# ---------------------------------------------------------------------------
def make_ssl_context(insecure):
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def fetch(base, path, timeout, insecure, origin_ip=None, max_bytes=200_000, max_redirects=3):
    """GET base+path. Retourneert (status, headers_dict, body_str) of raise OSError."""
    u = urllib.parse.urlsplit(base)
    scheme, host = u.scheme, u.hostname
    port = u.port or (443 if scheme == "https" else 80)
    connect_to = origin_ip or host
    ctx = make_ssl_context(insecure)

    for _ in range(max_redirects + 1):
        sock = socket.create_connection((connect_to, port), timeout=timeout)
        if scheme == "https":
            sock = ctx.wrap_socket(sock, server_hostname=host)
        conn = http.client.HTTPConnection(host, port, timeout=timeout)
        conn.sock = sock
        try:
            hdrs = {
                "Host": host if port in (80, 443) else f"{host}:{port}",
                "User-Agent": UA,
                "Accept": "*/*",
                "Connection": "close",
            }
            conn.request("GET", path, headers=hdrs)
            resp = conn.getresponse()
            headers = {k.lower(): v for k, v in resp.getheaders()}
            cookies = [v for k, v in resp.getheaders() if k.lower() == "set-cookie"]
            headers["set-cookie"] = "; ".join(cookies)
            body = resp.read(max_bytes).decode("utf-8", "replace")
            status = resp.status
        finally:
            conn.close()

        loc = headers.get("location")
        if status in (301, 302, 303, 307, 308) and loc:
            nu = urllib.parse.urlsplit(urllib.parse.urljoin(base + path, loc))
            # Alleen redirects binnen dezelfde host volgen (en zelfde schema,
            # anders zou een origin-scan via https ineens over het edge-IP gaan)
            if nu.hostname == host and nu.scheme == scheme:
                path = nu.path or "/"
                if nu.query:
                    path += "?" + nu.query
                continue
        return status, headers, body
    return status, headers, body


# ---------------------------------------------------------------------------
# Bekende PHP-omgevingen. Elke signature: naam, cookies (letterlijke substrings
# in Set-Cookie, of "re:<regex>"), headers {naam: substring}, body (regexen), paths (extra
# GET-paden die de app bevestigen; "pad": regex-op-body of None),
# version (regex met groep 1 = app-versie, toegepast op alle bodies).
# ---------------------------------------------------------------------------
APP_SIGNATURES = [
    {"name": "WordPress", "cookies": ["wordpress_", "wp-settings-"],
     "body": [r"/wp-content/", r"/wp-includes/", r'name="generator" content="WordPress'],
     "paths": {"/wp-login.php": r"wp-submit|wordpress", "/wp-json/": r'"namespaces"'},
     "version": r'name="generator" content="WordPress ([\d.]+)'},
    {"name": "WooCommerce", "cookies": ["woocommerce_"], "body": [r"/plugins/woocommerce/", r"woocommerce-"]},
    {"name": "Drupal", "cookies": ["re:SESS[0-9a-f]{32}", "SSESS"], "headers": {"x-generator": "Drupal", "x-drupal-cache": ""},
     "body": [r"/sites/default/files/", r"drupalSettings", r"Drupal\.settings"],
     "paths": {"/core/CHANGELOG.txt": r"Drupal", "/CHANGELOG.txt": r"Drupal"},
     "version": r"X-Generator: Drupal ([\d.]+)|Drupal ([\d.]+),"},
    {"name": "Joomla", "body": [r'name="generator" content="Joomla', r"/media/jui/", r"/media/system/js/"],
     "paths": {"/administrator/": r"joomla", "/administrator/manifests/files/joomla.xml": r"<version>"},
     "version": r"<version>([\d.]+)</version>"},
    {"name": "Magento", "cookies": ["X-Magento-Vary", "mage-cache-", "form_key"],
     "body": [r"/static/version\d+/", r"Magento_", r"mage/"],
     "paths": {"/magento_version": r"Magento"},
     "version": r"Magento/([\d.]+)"},
    {"name": "Laravel", "cookies": ["laravel_session", "XSRF-TOKEN"], "body": [r"laravel", r"Illuminate\\"]},
    {"name": "Symfony", "cookies": ["sf_redirect", "PHPSESSID"], "headers": {"x-debug-token": "", "x-symfony-cache": ""},
     "paths": {"/_profiler/": r"Symfony|profiler", "/_wdt/": r"Symfony"}},
    {"name": "CodeIgniter", "cookies": ["ci_session"]},
    {"name": "CakePHP", "cookies": ["CAKEPHP"]},
    {"name": "Yii", "cookies": ["_csrf", "YII_CSRF_TOKEN", "_identity"], "body": [r"yii\.js", r"yii\\"]},
    {"name": "Zend/Laminas", "body": [r"Laminas\\", r"Zend\\", r"ZendFramework"]},
    {"name": "TYPO3", "cookies": ["fe_typo_user", "be_typo_user"], "body": [r"/typo3conf/", r"/typo3temp/", r'name="generator" content="TYPO3'],
     "paths": {"/typo3/": r"TYPO3"}},
    {"name": "PrestaShop", "cookies": ["PrestaShop-"], "body": [r"prestashop", r"/modules/ps_"],
     "paths": {"/img/prestashop.ico": None}},
    {"name": "OpenCart", "cookies": ["OCSESSID"], "body": [r"catalog/view/theme", r"route=common/home"]},
    {"name": "Shopware", "cookies": ["sw-", "session-"], "body": [r"shopware", r"/bundles/storefront/"]},
    {"name": "Craft CMS", "cookies": ["CraftSessionId", "CRAFT_CSRF_TOKEN"], "headers": {"x-powered-by": "Craft CMS"}},
    {"name": "Statamic", "cookies": ["statamic_"], "body": [r"statamic"]},
    {"name": "OctoberCMS/Winter", "cookies": ["october_session", "winter_session"]},
    {"name": "Concrete CMS", "cookies": ["CONCRETE5"], "body": [r"/concrete/", r"ccm-"]},
    {"name": "SilverStripe", "body": [r"/_resources/", r"silverstripe"], "headers": {"x-powered-by": "SilverStripe"}},
    {"name": "Grav", "cookies": ["grav-site-"], "body": [r"/user/themes/", r"grav"]},
    {"name": "MediaWiki", "cookies": ["re:\\bwiki\\w*_session=", "re:\\bwiki\\w*UserID="], "body": [r"mediawiki", r"/load\.php\?", r'name="generator" content="MediaWiki'],
     "paths": {"/api.php": r"MediaWiki API", "/w/api.php": r"MediaWiki API"},
     "version": r'name="generator" content="MediaWiki ([\d.]+)'},
    {"name": "Moodle", "cookies": ["MoodleSession"], "body": [r"moodle", r"/theme/boost/"]},
    {"name": "Nextcloud/ownCloud", "cookies": ["oc_sessionPassphrase", "nc_session_id", "ocXX"],
     "paths": {"/status.php": r'"installed":true', "/nextcloud/status.php": r'"installed":true'},
     "version": r'"versionstring":"([\d.]+)"'},
    {"name": "phpMyAdmin", "cookies": ["phpMyAdmin", "pma_lang", "pmaCookieVer"],
     "paths": {"/phpmyadmin/": r"phpMyAdmin", "/pma/": r"phpMyAdmin", "/phpMyAdmin/": r"phpMyAdmin"},
     "version": r"phpMyAdmin ([\d.]+)"},
    {"name": "Adminer", "paths": {"/adminer.php": r"Adminer", "/adminer/": r"Adminer"}, "version": r"Adminer ([\d.]+)"},
    {"name": "Roundcube", "cookies": ["roundcube_sessid", "roundcube_sessauth"], "body": [r"roundcube"],
     "paths": {"/roundcube/": r"roundcube", "/webmail/": r"roundcube"}},
    {"name": "Matomo/Piwik", "cookies": ["MATOMO_SESSID", "PIWIK_SESSID"], "body": [r"matomo\.js", r"piwik\.js"],
     "paths": {"/matomo.php": None, "/piwik.php": None}},
    {"name": "phpBB", "cookies": ["phpbb3_", "phpbb_"], "body": [r"phpBB"]},
    {"name": "XenForo", "cookies": ["xf_session", "xf_csrf"], "body": [r"XenForo"]},
    {"name": "vBulletin", "cookies": ["bb_sessionhash", "bbsessionhash"], "body": [r"vBulletin"]},
    {"name": "MyBB", "cookies": ["mybb["], "body": [r"MyBB"]},
    {"name": "Zabbix", "cookies": ["zbx_session"], "body": [r"zabbix"]},
    {"name": "GLPI", "cookies": ["glpi_"], "body": [r"/glpi/", r"GLPI"]},
    {"name": "Dolibarr", "cookies": ["DOLSESSID_"], "body": [r"dolibarr"]},
    {"name": "SuiteCRM/SugarCRM", "cookies": ["sugar_user_theme", "ck_login_id_20"], "body": [r"SuiteCRM", r"SugarCRM"]},
    {"name": "Mautic", "cookies": ["mautic_session", "mtc_id"], "body": [r"mautic"]},
    {"name": "Limesurvey", "cookies": ["LS-"], "body": [r"limesurvey"]},
    {"name": "Kirby", "cookies": ["kirby_session"]},
    {"name": "ProcessWire", "cookies": ["wire", "wires"], "body": [r"processwire"]},
    {"name": "Bolt CMS", "cookies": ["bolt_session"]},
    {"name": "Elgg", "cookies": ["Elgg"]},
    {"name": "osTicket", "cookies": ["OSTSESSID"]},
    {"name": "Froxlor/ISPConfig/Plesk", "cookies": ["PLESKSESSID", "ispconfig"], "body": [r"froxlor", r"ispconfig", r"plesk"]},
    {"name": "cPanel/WHM (PHP-interface)", "cookies": ["cpsession", "whostmgrsession"]},
]

# Gevoelige bestanden die niet publiek horen te zijn. Alleen aanwezigheid wordt
# gemeld; inhoud wordt niet getoond.
EXPOSURE_CHECKS = [
    ("/.env",                            r"APP_KEY=|DB_PASSWORD=|APP_ENV=",      "Laravel/.env publiek (secrets!)"),
    ("/composer.json",                   r'"require"',                          "composer.json publiek (pakketlijst)"),
    ("/composer.lock",                   r'"packages"',                         "composer.lock publiek (exacte versies)"),
    ("/vendor/composer/installed.json",  r'"name"\s*:',                         "vendor/composer/installed.json publiek"),
    ("/.git/HEAD",                       r"^ref: refs/",                         "git-repository publiek (.git/HEAD)"),
    ("/wp-config.php.bak",               r"DB_PASSWORD",                         "wp-config.php backup publiek (secrets!)"),
    ("/config.php.bak",                  r"password|passwd",                     "config.php backup publiek"),
    ("/server-status",                   r"Apache Server Status",                "Apache server-status publiek"),
    ("/.user.ini",                       r"^\s*[a-z_.]+\s*=",                    ".user.ini publiek"),
]

# PHP-versie-eis uit composer-bestanden ("php": ">=8.1") → geeft een branch-hint
COMPOSER_PHP_RE = re.compile(r'"php"\s*:\s*"[^\d]*(\d+\.\d+)')
GENERATOR_RE = re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', re.I)


def match_app_signatures(headers, body):
    """Geeft {appnaam: bewijs} voor alle signatures die op deze response matchen."""
    hits = {}
    sc = headers.get("set-cookie", "")
    for sig in APP_SIGNATURES:
        for c in sig.get("cookies", []):
            pat = c[3:] if c.startswith("re:") else re.escape(c)
            if re.search(pat, sc):
                hits.setdefault(sig["name"], f"cookie {c}")
        for hname, sub in sig.get("headers", {}).items():
            hv = headers.get(hname)
            if hv is not None and sub.lower() in hv.lower():
                hits.setdefault(sig["name"], f"header {hname}")
        if body:
            for rx in sig.get("body", []):
                if re.search(rx, body, re.I):
                    hits.setdefault(sig["name"], "html-inhoud")
                    break
    return hits


def app_version_from_body(name, body):
    for sig in APP_SIGNATURES:
        if sig["name"] == name and sig.get("version") and body:
            m = re.search(sig["version"], body, re.I)
            if m:
                return next((g for g in m.groups() if g), None)
    return None


def detect_edge(headers):
    """Welke CDN/WAF/proxy staat ervoor? Lege lijst = niets herkend."""
    found = []
    for name, test in EDGE_SIGNATURES:
        try:
            if test(headers):
                found.append(name)
        except Exception:
            pass
    # generieke melding weglaten als er al een specifieke is
    if len(found) > 1 and "Reverse proxy (generiek)" in found:
        found.remove("Reverse proxy (generiek)")
    return found


def extract_signals(status, headers, body, path):
    """Zoekt naar PHP-aanwijzingen, versies en bekende apps in headers en body.
    Retourneert (versions, signals, apps{naam: {"bewijs":..., "versie":...}})."""
    versions = set()
    signals = []
    apps = {}

    for name, evidence in match_app_signatures(headers, body).items():
        apps[name] = {"bewijs": f"{path}: {evidence}", "versie": app_version_from_body(name, body)}
    if body:
        m = GENERATOR_RE.search(body)
        if m and not any(a.lower() in m.group(1).lower() for a in apps):
            signals.append(f"meta generator: {m.group(1)[:50]}")

    xpb = headers.get("x-powered-by", "")
    if xpb:
        if "php" in xpb.lower():
            signals.append(f"X-Powered-By: {xpb}")
        for m in VERSION_RE.finditer(xpb):
            versions.add(m.group(1))

    srv = headers.get("server", "")
    if srv and "php" in srv.lower():
        signals.append(f"Server: {srv}")
        for m in VERSION_RE.finditer(srv):
            versions.add(m.group(1))

    sc = headers.get("set-cookie", "")
    if "PHPSESSID" in sc:
        signals.append("Set-Cookie: PHPSESSID")

    # Gedragsfingerprint: PHP's session_start() zet altijd deze vaste Expires-datum.
    # Proxies laten die vrijwel altijd staan.
    if "19 Nov 1981" in headers.get("expires", ""):
        signals.append("Expires: 19 Nov 1981 (PHP sessie-cacheheader, proxy-bestendig)")

    if body:
        if "<title>phpinfo()</title>" in body or ("PHP Version" in body and "php.net" in body):
            signals.append(f"phpinfo() pagina publiek op {path} (!!)")
            for rx in (PHPINFO_RE, PHPINFO_RE2):
                for m in rx.finditer(body):
                    versions.add(m.group(1))
        if path == "/" or path.endswith(".php") or path.endswith("/"):
            if re.search(r'href=["\'][^"\']*\.php', body) and "PHP" not in " ".join(signals):
                signals.append("Links naar .php-bestanden in HTML")

    return versions, signals, apps


def behavioural_probes(base, timeout, insecure, origin_ip):
    """
    Fingerprints die niet afhangen van versie-headers (die een WAF/proxy stript):
      1. niet-bestaand .php vs .txt pad → php-fpm 'File not found.' / afwijkende afhandeling
      2. PHP easter egg → bewijst PHP < 5.5 (EOL)
    Retourneert (versions, signals).
    """
    versions, signals = set(), []
    rnd = "".join(random.choices(string.ascii_lowercase, k=10))
    try:
        s_php, h_php, b_php = fetch(base, f"/php2shell-probe-{rnd}.php", timeout, insecure, origin_ip)
        s_txt, h_txt, b_txt = fetch(base, f"/php2shell-probe-{rnd}.txt", timeout, insecure, origin_ip)
        if "File not found." in b_php and s_php == 404:
            signals.append("php-fpm 'File not found.' op niet-bestaand .php-pad (proxy-bestendig)")
        elif "No input file specified" in b_php:
            signals.append("PHP-CGI 'No input file specified' op niet-bestaand .php-pad (proxy-bestendig)")
        elif s_php != s_txt:
            signals.append(f"Server behandelt .php ({s_php}) anders dan .txt ({s_txt}) → PHP-handler aanwezig")
        elif "php" in h_php.get("x-powered-by", "").lower() and "php" not in h_txt.get("x-powered-by", "").lower():
            signals.append("X-Powered-By alleen op .php-pad → PHP-handler aanwezig")
        for m in VERSION_RE.finditer(h_php.get("x-powered-by", "")):
            versions.add(m.group(1))
    except OSError:
        pass

    try:
        s, h, b = fetch(base, EASTER_EGG, timeout, insecure, origin_ip)
        if s == 200 and h.get("content-type", "").startswith("image/"):
            signals.append("PHP easter egg actief → PHP < 5.5 (EOL)")
            versions.add("5.4")
    except OSError:
        pass

    return versions, signals


def app_probes(base, timeout, insecure, origin_ip, known_apps, delay):
    """
    Bevestigt bekende apps via hun eigen paden (alleen voor apps die al
    vermoed worden, of die alleen via een pad herkenbaar zijn) en controleert
    op publiek staande gevoelige bestanden.
    Retourneert (versions, signals, apps, exposures).
    """
    versions, signals, apps, exposures = set(), [], {}, []
    # Apps die geen cookie/body-signature hebben en dus alleen via pad te vinden zijn
    path_only = {sig["name"] for sig in APP_SIGNATURES if not sig.get("cookies") and not sig.get("body") and not sig.get("headers")}
    for sig in APP_SIGNATURES:
        if not sig.get("paths"):
            continue
        if sig["name"] not in known_apps and sig["name"] not in path_only:
            continue
        for p, rx in sig["paths"].items():
            try:
                st, h, b = fetch(base, p, timeout, insecure, origin_ip)
            except (OSError, http.client.HTTPException, ValueError):
                continue
            if st == 200 and (rx is None or re.search(rx, b, re.I)):
                ver = app_version_from_body(sig["name"], b)
                cur = apps.setdefault(sig["name"], {"bewijs": f"{p}: pad bevestigd", "versie": None})
                if ver and not cur["versie"]:
                    cur["versie"] = ver
                if sig["name"] == "phpMyAdmin" or sig["name"] == "Adminer":
                    exposures.append(f"{sig['name']} publiek bereikbaar op {p} (!!)")
            # Nextcloud status.php, composer e.d. kunnen PHP-eisen bevatten
            for m in VERSION_RE.finditer(h.get("x-powered-by", "")):
                versions.add(m.group(1))
            if delay:
                time.sleep(delay)

    for p, rx, label in EXPOSURE_CHECKS:
        try:
            st, h, b = fetch(base, p, timeout, insecure, origin_ip)
        except (OSError, http.client.HTTPException, ValueError):
            continue
        looks_html = re.search(r"<(!doctype|html|head|body)\b", b[:2000], re.I) is not None
        if st == 200 and re.search(rx, b, re.I | re.M) and (not looks_html or p == "/server-status"):
            exposures.append(f"{label} op {p}")
            m = COMPOSER_PHP_RE.search(b)
            if m and p.startswith(("/composer", "/vendor")):
                signals.append(f"composer eist php {m.group(1)}+ (branch-hint, geen exacte versie)")
        if delay:
            time.sleep(delay)

    return versions, signals, apps, exposures


def normalize_targets(raw, global_origin=None):
    """Geeft lijst van (base_url, origin_ip|None)."""
    out = []
    for t in raw:
        t = t.strip()
        if not t or t.startswith("#"):
            continue
        origin = global_origin
        if "@" in t and "://" not in t.split("@", 1)[0]:
            t, origin = t.rsplit("@", 1)
            origin = origin.strip() or None
        elif "@" in t:
            t, origin = t.rsplit("@", 1)
            origin = origin.strip() or None
        if "://" in t:
            out.append((t.rstrip("/"), origin))
        else:
            out.append((f"https://{t}", origin))
            out.append((f"http://{t}", origin))
    seen, res = set(), []
    for item in out:
        if item not in seen:
            seen.add(item)
            res.append(item)
    return res


def label_of(base, origin_ip):
    return f"{base} (origin {origin_ip})" if origin_ip else base


def scan_target(base, origin_ip, paths, timeout, insecure, delay, behaviour, apps_on):
    result = {
        "target": label_of(base, origin_ip),
        "url": base,
        "origin_ip": origin_ip,
        "reachable": False,
        "php_detected": False,
        "edge": [],
        "apps": {},
        "exposures": [],
        "versions": [],
        "signals": [],
        "status": "ONBEREIKBAAR",
        "detail": "",
        "errors": [],
    }
    all_versions, all_signals = set(), []

    def add_signals(prefix, sg):
        for s in sg:
            if not any(x.split(": ", 1)[-1] == s for x in all_signals):
                all_signals.append(f"{prefix}: {s}")

    for p in paths:
        try:
            status, headers, body = fetch(base, p, timeout, insecure, origin_ip)
            result["reachable"] = True
            if p == "/":
                result["edge"] = detect_edge(headers)
            vs, sg, ap = extract_signals(status, headers, body, p)
            all_versions |= vs
            add_signals(p, sg)
            for name, info in ap.items():
                cur = result["apps"].setdefault(name, info)
                if info.get("versie") and not cur.get("versie"):
                    cur["versie"] = info["versie"]
        except (OSError, http.client.HTTPException, ValueError) as e:
            msg = str(getattr(e, "reason", e)) or e.__class__.__name__
            result["errors"].append(f"{p}: {msg}")
            if p == "/":
                break   # host dicht op dit schema; rest overslaan
        if delay:
            time.sleep(delay)

    if result["reachable"] and behaviour:
        vs, sg = behavioural_probes(base, timeout, insecure, origin_ip)
        all_versions |= vs
        add_signals("gedrag", sg)

    if result["reachable"] and apps_on:
        vs, sg, ap, ex = app_probes(base, timeout, insecure, origin_ip, set(result["apps"]), delay)
        all_versions |= vs
        add_signals("apps", sg)
        for name, info in ap.items():
            cur = result["apps"].setdefault(name, info)
            if info.get("versie") and not cur.get("versie"):
                cur["versie"] = info["versie"]
        result["exposures"] = ex

    result["versions"] = sorted(all_versions, key=lambda v: parse_version(v) or (0, 0, 0))
    result["signals"] = all_signals
    result["php_detected"] = bool(all_versions or all_signals or result["apps"])
    return result


def finalize(result, fixed_map):
    if not result["reachable"]:
        result["status"] = "ONBEREIKBAAR"
        result["detail"] = "; ".join(result["errors"][:2])
        return result

    edge = ", ".join(result["edge"])
    masked_hint = ""
    if result["edge"] and not result["origin_ip"]:
        masked_hint = (f" — zit achter {edge}; versie-headers worden daar vaak gestript. "
                       f"Scan de origin direct: {urllib.parse.urlsplit(result['url']).hostname}@ORIGIN-IP")

    if not result["php_detected"]:
        if result["edge"] and not result["origin_ip"]:
            result["status"] = "GEMASKEERD"
            result["detail"] = "Geen PHP-signalen via de edge" + masked_hint
        else:
            result["status"] = "GEEN-PHP-GEZIEN"
            result["detail"] = "Geen PHP-signalen van buiten; sluit PHP niet uit (expose_php=Off is gebruikelijk)"
        return result

    if result["versions"]:
        worst = None
        for v in result["versions"]:
            st, det = classify(v, fixed_map)
            rank = {"KWETSBAAR-EOL": 0, "KWETSBAAR": 1, "WAARSCHIJNLIJK-KWETSBAAR": 2,
                    "ONBEKEND": 3, "GEPATCHT": 4}[st]
            if worst is None or rank < worst[0]:
                worst = (rank, st, det)
        result["status"], result["detail"] = worst[1], worst[2]
    else:
        if result["edge"] and not result["origin_ip"]:
            result["status"] = "GEMASKEERD"
            result["detail"] = "PHP herkend aan gedrag, maar versie onzichtbaar" + masked_hint
        else:
            result["status"], result["detail"] = classify(None, fixed_map)
    return result


ORDER = ["KWETSBAAR-EOL", "KWETSBAAR", "WAARSCHIJNLIJK-KWETSBAAR", "ONBEKEND",
         "GEMASKEERD", "GEPATCHT", "GEEN-PHP-GEZIEN", "ONBEREIKBAAR"]


def print_report(results, fixed_map):
    results = sorted(results, key=lambda r: ORDER.index(r["status"]))
    w = max(len(r["target"]) for r in results) if results else 20
    print()
    print("PHP2Shell scan — CVE-2026-109618 / CVE-2026-109619")
    print("Gefixte versies gebruikt: " + ", ".join(f"{k}→{v}" for k, v in fixed_map.items()))
    print("=" * (w + 60))
    for r in results:
        ver = ", ".join(r["versions"]) or "-"
        print(f"{r['target']:<{w}}  {r['status']:<24} versie: {ver}")
        if r["edge"]:
            print(f"{'':<{w}}  ▸ edge/WAF: {', '.join(r['edge'])}")
        if r["apps"]:
            apps = ", ".join(f"{n} {i['versie']}" if i.get("versie") else n for n, i in r["apps"].items())
            print(f"{'':<{w}}  ▸ PHP-apps: {apps}")
        for e in r["exposures"]:
            print(f"{'':<{w}}  ⚠ {e}")
        if r["detail"]:
            print(f"{'':<{w}}  └ {r['detail']}")
        for s in r["signals"][:5]:
            print(f"{'':<{w}}    · {s}")
    print("=" * (w + 60))
    counts = {}
    for r in results:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    print("Samenvatting: " + ", ".join(f"{k}: {v}" for k, v in counts.items()))
    print()
    print("Let op: 'GEEN-PHP-GEZIEN', 'ONBEKEND' en 'GEMASKEERD' betekenen NIET veilig. Veel servers")
    print("verbergen de PHP-versie (expose_php=Off, CDN/WAF, reverse proxy). Scan die hosts via hun")
    print("origin-IP (host@IP) of controleer intern met `php -v` / `php-fpm -v`.")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("targets", nargs="*", help="hostnames, IP's, URL's of host@ORIGIN-IP")
    ap.add_argument("-f", "--file", help="bestand met één target per regel")
    ap.add_argument("-o", "--json", help="schrijf JSON-rapport naar bestand")
    ap.add_argument("--csv", help="schrijf CSV-rapport naar bestand")
    ap.add_argument("--origin", help="origin-IP voor alle targets zonder eigen @IP (omzeilt CDN/WAF)")
    ap.add_argument("-t", "--timeout", type=float, default=8.0, help="timeout per request (s)")
    ap.add_argument("-c", "--concurrency", type=int, default=10, help="aantal gelijktijdige hosts")
    ap.add_argument("--delay", type=float, default=0.0, help="pauze tussen requests per host (s)")
    ap.add_argument("--insecure", action="store_true", help="TLS-certificaten niet valideren")
    ap.add_argument("--quick", action="store_true", help="alleen / en /index.php proberen")
    ap.add_argument("--no-behaviour", action="store_true", help="gedragsfingerprints (.php vs .txt, easter egg) overslaan")
    ap.add_argument("--no-apps", action="store_true", help="app-herkenning en exposure-checks (.env, composer, .git) overslaan")
    ap.add_argument("--path", action="append", default=[], help="extra pad om te proberen (herhaalbaar)")
    ap.add_argument("--fixed", action="append", default=[],
                    help="override gefixte versie, bv. --fixed 8.4=8.4.27 (herhaalbaar)")
    args = ap.parse_args()

    raw = list(args.targets)
    if args.file:
        with open(args.file, encoding="utf-8") as fh:
            raw += fh.read().splitlines()
    targets = normalize_targets(raw, args.origin)
    if not targets:
        ap.error("geen targets opgegeven (argumenten of -f bestand)")

    fixed_map = dict(DEFAULT_FIXED)
    for item in args.fixed:
        if "=" not in item:
            ap.error(f"--fixed verwacht BRANCH=VERSIE, kreeg: {item}")
        k, v = item.split("=", 1)
        fixed_map[k.strip()] = v.strip()

    paths = ["/", "/index.php"] if args.quick else list(PROBE_PATHS)
    for p in args.path:
        if not p.startswith("/"):
            p = "/" + p
        if p not in paths:
            paths.append(p)

    print(f"Scannen van {len(targets)} target(s) met {len(paths)} pad(en) elk ...", file=sys.stderr)
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as ex:
        futs = [ex.submit(scan_target, base, origin, paths, args.timeout, args.insecure,
                          args.delay, not args.no_behaviour, not args.no_apps) for base, origin in targets]
        for fut in concurrent.futures.as_completed(futs):
            r = finalize(fut.result(), fixed_map)
            results.append(r)
            print(f"  [{r['status']}] {r['target']}", file=sys.stderr)

    print_report(results, fixed_map)

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump({"cves": ["CVE-2026-109618", "CVE-2026-109619"],
                       "fixed_versions": fixed_map,
                       "scanned_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                       "results": results}, fh, indent=2, ensure_ascii=False)
        print(f"JSON geschreven naar {args.json}")
    if args.csv:
        with open(args.csv, "w", newline="", encoding="utf-8") as fh:
            wr = csv.writer(fh)
            wr.writerow(["target", "status", "versies", "edge", "apps", "exposures", "detail", "signalen"])
            for r in results:
                apps = ", ".join(f"{n} {i['versie']}" if i.get("versie") else n for n, i in r["apps"].items())
                wr.writerow([r["target"], r["status"], " ".join(r["versions"]), ", ".join(r["edge"]),
                             apps, " | ".join(r["exposures"]), r["detail"], " | ".join(r["signals"])])
        print(f"CSV geschreven naar {args.csv}")

    bad = any(r["status"].startswith("KWETSBAAR") or r["status"] == "WAARSCHIJNLIJK-KWETSBAAR" for r in results)
    sys.exit(2 if bad else 0)


if __name__ == "__main__":
    main()

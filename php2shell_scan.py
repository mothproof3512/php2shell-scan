#!/usr/bin/env python3
"""
php2shell_scan.py — externe-oppervlak scanner voor PHP2Shell
(CVE-2026-109618 / CVE-2026-109619)

Fingerprint je EIGEN publieke hosts op PHP-aanwezigheid en -versie en
vergelijk die met de gepatchte releases. Niet-intrusief: alleen gewone
HTTP GET/HEAD requests, geen exploit-pogingen.

Gebruik:
    python3 php2shell_scan.py example.com www.example.com 203.0.113.10
    python3 php2shell_scan.py -f hosts.txt -o rapport.json --csv rapport.csv
    python3 php2shell_scan.py -f hosts.txt --fixed 8.4=8.4.27 --fixed 8.3=8.3.36

Alleen Python 3.8+ standaardbibliotheek nodig.
"""

import argparse
import concurrent.futures
import csv
import json
import re
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from http.cookiejar import CookieJar

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
    "/wp-login.php",          # WordPress
    "/administrator/",        # Joomla
    "/user/login",            # Drupal
    "/magento_version",       # Magento
]

VERSION_RE = re.compile(r"PHP/?\s*v?(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)
PHPINFO_RE = re.compile(r"PHP Version\s*(?:</[^>]+>\s*)*<[^>]*>?\s*(\d+\.\d+\.\d+)", re.IGNORECASE)
PHPINFO_RE2 = re.compile(r"PHP Version\s+(\d+\.\d+\.\d+)", re.IGNORECASE)

UA = "php2shell-scan/1.0 (eigen-oppervlak controle; CVE-2026-109618/109619)"


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


def build_opener(insecure):
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    handlers = [
        urllib.request.HTTPSHandler(context=ctx),
        urllib.request.HTTPCookieProcessor(CookieJar()),
    ]
    opener = urllib.request.build_opener(*handlers)
    opener.addheaders = [("User-Agent", UA), ("Accept", "*/*")]
    return opener


def fetch(opener, url, timeout, max_bytes=200_000):
    """Retourneert (status, headers_dict, body_str) of raise."""
    req = urllib.request.Request(url, method="GET")
    try:
        with opener.open(req, timeout=timeout) as resp:
            headers = {k.lower(): v for k, v in resp.headers.items()}
            # Set-Cookie kan meerdere keren voorkomen
            cookies = resp.headers.get_all("Set-Cookie") or []
            headers["set-cookie"] = "; ".join(cookies)
            body = resp.read(max_bytes).decode("utf-8", "replace")
            return resp.status, headers, body
    except urllib.error.HTTPError as e:
        headers = {k.lower(): v for k, v in e.headers.items()} if e.headers else {}
        cookies = e.headers.get_all("Set-Cookie") if e.headers else []
        headers["set-cookie"] = "; ".join(cookies or [])
        try:
            body = e.read(max_bytes).decode("utf-8", "replace")
        except Exception:
            body = ""
        return e.code, headers, body


def extract_signals(status, headers, body, path):
    """Zoekt naar PHP-aanwijzingen en versies in headers en body."""
    versions = set()
    signals = []

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

    if body:
        if "<title>phpinfo()</title>" in body or "PHP Version" in body and "php.net" in body:
            signals.append(f"phpinfo() pagina publiek op {path} (!!)")
            for rx in (PHPINFO_RE, PHPINFO_RE2):
                for m in rx.finditer(body):
                    versions.add(m.group(1))
        if path == "/" or path.endswith(".php") or path.endswith("/"):
            if re.search(r'href=["\'][^"\']*\.php', body) and "PHP" not in " ".join(signals):
                signals.append("Links naar .php-bestanden in HTML")
        if "/wp-content/" in body or "/wp-includes/" in body:
            signals.append("WordPress gedetecteerd (draait op PHP)")
        if "Joomla" in body and "administrator" in path:
            signals.append("Joomla gedetecteerd (draait op PHP)")
        if "Drupal" in body or "drupal.js" in body:
            signals.append("Drupal gedetecteerd (draait op PHP)")
        if path == "/magento_version" and status == 200 and "Magento" in body:
            signals.append(f"Magento gedetecteerd: {body.strip()[:60]}")

    return versions, signals


def normalize_targets(raw):
    out = []
    for t in raw:
        t = t.strip()
        if not t or t.startswith("#"):
            continue
        if "://" in t:
            out.append(t.rstrip("/"))
        else:
            # Geen schema: beide proberen
            out.append(f"https://{t}")
            out.append(f"http://{t}")
    # dedupe, volgorde behouden
    seen, res = set(), []
    for t in out:
        if t not in seen:
            seen.add(t)
            res.append(t)
    return res


def scan_target(base, paths, timeout, insecure, delay):
    opener = build_opener(insecure)
    result = {
        "target": base,
        "reachable": False,
        "php_detected": False,
        "versions": [],
        "signals": [],
        "status": "ONBEREIKBAAR",
        "detail": "",
        "errors": [],
    }
    all_versions, all_signals = set(), []
    for p in paths:
        url = base + p
        try:
            status, headers, body = fetch(opener, url, timeout)
            result["reachable"] = True
            vs, sg = extract_signals(status, headers, body, p)
            all_versions |= vs
            for s in sg:
                # zelfde signaal maar één keer melden (eerste pad waarop het gezien is)
                if not any(x.split(": ", 1)[1] == s for x in all_signals):
                    all_signals.append(f"{p}: {s}")
        except (urllib.error.URLError, socket.timeout, ssl.SSLError,
                ConnectionError, OSError, ValueError) as e:
            msg = str(getattr(e, "reason", e))
            # Eerste pad onbereikbaar = host waarschijnlijk dicht op dit schema
            if p == "/" :
                result["errors"].append(f"{p}: {msg}")
                break
            result["errors"].append(f"{p}: {msg}")
        if delay:
            time.sleep(delay)

    result["versions"] = sorted(all_versions, key=lambda v: parse_version(v) or (0, 0, 0))
    result["signals"] = all_signals
    result["php_detected"] = bool(all_versions or all_signals)
    return result


def finalize(result, fixed_map):
    if not result["reachable"]:
        result["status"] = "ONBEREIKBAAR"
        result["detail"] = "; ".join(result["errors"][:2])
        return result
    if not result["php_detected"]:
        result["status"] = "GEEN-PHP-GEZIEN"
        result["detail"] = "Geen PHP-signalen van buiten; sluit PHP niet uit (expose_php=Off is gebruikelijk)"
        return result
    if result["versions"]:
        # Meest specifieke (langste) versie wint; bij meerdere de laagste melden
        worst = None
        for v in result["versions"]:
            st, det = classify(v, fixed_map)
            rank = {"KWETSBAAR-EOL": 0, "KWETSBAAR": 1, "WAARSCHIJNLIJK-KWETSBAAR": 2,
                    "ONBEKEND": 3, "GEPATCHT": 4}[st]
            if worst is None or rank < worst[0]:
                worst = (rank, st, det)
        result["status"], result["detail"] = worst[1], worst[2]
    else:
        result["status"], result["detail"] = classify(None, fixed_map)
    return result


ORDER = ["KWETSBAAR-EOL", "KWETSBAAR", "WAARSCHIJNLIJK-KWETSBAAR", "ONBEKEND",
         "GEPATCHT", "GEEN-PHP-GEZIEN", "ONBEREIKBAAR"]


def print_report(results, fixed_map):
    results = sorted(results, key=lambda r: ORDER.index(r["status"]))
    w = max(len(r["target"]) for r in results) if results else 20
    print()
    print(f"PHP2Shell scan — CVE-2026-109618 / CVE-2026-109619")
    print(f"Gefixte versies gebruikt: " + ", ".join(f"{k}→{v}" for k, v in fixed_map.items()))
    print("=" * (w + 60))
    for r in results:
        ver = ", ".join(r["versions"]) or "-"
        print(f"{r['target']:<{w}}  {r['status']:<24} versie: {ver}")
        if r["detail"]:
            print(f"{'':<{w}}  └ {r['detail']}")
        for s in r["signals"][:4]:
            print(f"{'':<{w}}    · {s}")
    print("=" * (w + 60))
    counts = {}
    for r in results:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    print("Samenvatting: " + ", ".join(f"{k}: {v}" for k, v in counts.items()))
    print()
    print("Let op: 'GEEN-PHP-GEZIEN' en 'ONBEKEND' betekenen NIET veilig. Veel servers verbergen")
    print("de PHP-versie (expose_php=Off, reverse proxy, WAF). Controleer die hosts intern met")
    print("`php -v` / `php-fpm -v` of vraag het je hoster.")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("targets", nargs="*", help="hostnames, IP's of URL's")
    ap.add_argument("-f", "--file", help="bestand met één target per regel")
    ap.add_argument("-o", "--json", help="schrijf JSON-rapport naar bestand")
    ap.add_argument("--csv", help="schrijf CSV-rapport naar bestand")
    ap.add_argument("-t", "--timeout", type=float, default=8.0, help="timeout per request (s)")
    ap.add_argument("-c", "--concurrency", type=int, default=10, help="aantal gelijktijdige hosts")
    ap.add_argument("--delay", type=float, default=0.0, help="pauze tussen requests per host (s)")
    ap.add_argument("--insecure", action="store_true", help="TLS-certificaten niet valideren")
    ap.add_argument("--quick", action="store_true", help="alleen / en /index.php proberen")
    ap.add_argument("--path", action="append", default=[], help="extra pad om te proberen (herhaalbaar)")
    ap.add_argument("--fixed", action="append", default=[],
                    help="override gefixte versie, bv. --fixed 8.4=8.4.27 (herhaalbaar)")
    args = ap.parse_args()

    raw = list(args.targets)
    if args.file:
        with open(args.file, encoding="utf-8") as fh:
            raw += fh.read().splitlines()
    targets = normalize_targets(raw)
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
        futs = {ex.submit(scan_target, t, paths, args.timeout, args.insecure, args.delay): t for t in targets}
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
            wr.writerow(["target", "status", "versies", "detail", "signalen"])
            for r in results:
                wr.writerow([r["target"], r["status"], " ".join(r["versions"]),
                             r["detail"], " | ".join(r["signals"])])
        print(f"CSV geschreven naar {args.csv}")

    bad = any(r["status"].startswith("KWETSBAAR") or r["status"] == "WAARSCHIJNLIJK-KWETSBAAR" for r in results)
    sys.exit(2 if bad else 0)


if __name__ == "__main__":
    main()

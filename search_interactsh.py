#!/usr/bin/env python3
"""Scanner for public, token-less Interactsh servers.

Searches Shodan, Censys or LeakIX for hosts serving `<h1>Interactsh Server</h1>`,
extracts the associated domains (hostnames / certificate SAN / CN) and tries
to register a client against `/register` without providing a token.
Servers that accept the request expose OOB subdomains publicly and are
printed to stdout.
"""

import argparse
import base64
import json
import os
import random
import string
import sys
import uuid

import requests
import urllib3
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SHODAN_QUERY = 'http.html:"Interactsh Server"'
CENSYS_QUERY = 'services.http.response.body: "Interactsh Server"'
LEAKIX_QUERY = '+"Interactsh Server"'

SUCCESS_MARKERS = ("registration successful", "\"message\"")


def generate_public_key_b64() -> str:
    """Generate a base64-encoded RSA 2048 public key in PEM format."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return base64.b64encode(pem).decode()


def random_correlation_id(length: int = 20) -> str:
    alphabet = string.ascii_lowercase + string.digits
    return "".join(random.choices(alphabet, k=length))


def search_shodan(api_key: str, limit: int = 100):
    url = "https://api.shodan.io/shodan/host/search"
    params = {"key": api_key, "query": SHODAN_QUERY, "limit": limit}
    r = requests.get(url, params=params, timeout=30)
    r.raise_for_status()
    data = r.json()
    out = []
    for match in data.get("matches", []):
        ssl = match.get("ssl") or {}
        cert = ssl.get("cert") or {}
        subject = cert.get("subject") or {}
        out.append(
            {
                "ip": match.get("ip_str"),
                "port": match.get("port") or 443,
                "hostnames": match.get("hostnames") or [],
                "cn": subject.get("CN"),
            }
        )
    return out


def search_censys(api_id: str, api_secret: str, pages: int = 1):
    url = "https://search.censys.io/api/v2/hosts/search"
    out, cursor = [], None
    for _ in range(pages):
        params = {"q": CENSYS_QUERY, "per_page": 100}
        if cursor:
            params["cursor"] = cursor
        r = requests.get(
            url, auth=(api_id, api_secret), params=params, timeout=30,
            allow_redirects=False,
        )
        if r.status_code in (301, 302):
            sys.exit(
                "Censys returned 302 - your account no longer has access to Search API v2.\n"
                "Censys migrated Search to the paid platform in 2025. Options:\n"
                "  1) Use --source shodan\n"
                "  2) Use --hosts-file with IPs/domains gathered from another source\n"
                "     (Shodan web UI, FOFA, ZoomEye, manual list)"
            )
        r.raise_for_status()
        result = r.json().get("result")
        if not isinstance(result, dict):
            sys.exit(f"unexpected Censys response: {result!r}")
        for hit in result.get("hits", []):
            out.append(
                {
                    "ip": hit.get("ip"),
                    "port": 443,
                    "hostnames": hit.get("names") or [],
                    "cn": None,
                }
            )
        cursor = (result.get("links") or {}).get("next")
        if not cursor:
            break
    return out


def search_leakix(api_key: str, pages: int = 3):
    """Search for Interactsh servers on LeakIX (free key at leakix.net/auth)."""
    url = "https://leakix.net/search"
    headers = {"api-key": api_key, "Accept": "application/json"}
    out = []
    for page in range(pages):
        params = {"q": LEAKIX_QUERY, "scope": "service", "page": page}
        r = requests.get(url, headers=headers, params=params, timeout=30)
        if r.status_code == 429:
            print(f"[!] leakix rate-limit on page {page}, stopping")
            break
        r.raise_for_status()
        data = r.json()
        if isinstance(data, dict) and data.get("Error"):
            sys.exit(f"LeakIX: {data['Error']}")
        if not data:
            break
        for svc in data:
            ssl = svc.get("ssl") or {}
            cert = ssl.get("certificate") or {}
            hostnames = []
            for name in cert.get("domain") or []:
                if name:
                    hostnames.append(name)
            host = svc.get("host") or svc.get("reverse")
            if host:
                hostnames.append(host)
            out.append(
                {
                    "ip": svc.get("ip"),
                    "port": int(svc.get("port") or 443),
                    "hostnames": hostnames,
                    "cn": cert.get("cn"),
                }
            )
    return out


def load_hosts_file(path: str):
    """Load candidates from a file (one host/IP/domain per line)."""
    out = []
    with open(path) as fp:
        for raw in fp:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if ":" in line and not line.count(":") > 1:
                name, _, port = line.partition(":")
                port = int(port) if port.isdigit() else 443
            else:
                name, port = line, 443
            entry = {"ip": name, "port": port, "hostnames": [], "cn": None}
            try:
                import ipaddress
                ipaddress.ip_address(name)
            except ValueError:
                entry["hostnames"] = [name]
            out.append(entry)
    return out


def candidate_domains(host: dict):
    """Derive testable domains from the host's hostnames/CN."""
    found = set()
    raw = list(host.get("hostnames") or [])
    if host.get("cn"):
        raw.append(host["cn"])
    for name in raw:
        name = name.strip(". ").lower().lstrip("*.")
        if not name or "." not in name:
            continue
        found.add(name)
        parts = name.split(".")
        if len(parts) >= 3:
            found.add(".".join(parts[-2:]))
    return sorted(found)


def try_register(domain: str, timeout: int = 10):
    """POST to /register without a token. Returns (ok, detail)."""
    payload = {
        "public-key": generate_public_key_b64(),
        "secret-key": str(uuid.uuid4()),
        "correlation-id": random_correlation_id(),
    }
    last_err = "no response"
    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}/register"
        try:
            r = requests.post(
                url,
                json=payload,
                timeout=timeout,
                verify=False,
                headers={"Content-Type": "application/json"},
                allow_redirects=False,
            )
        except requests.RequestException as exc:
            last_err = f"{scheme}: {exc.__class__.__name__}"
            continue

        body = (r.text or "").lower()
        if r.status_code == 200 and any(m in body for m in SUCCESS_MARKERS):
            return True, f"{scheme} 200 corr={payload['correlation-id']}"
        if r.status_code == 401:
            return False, f"{scheme} 401 token required"
        last_err = f"{scheme} {r.status_code}: {body[:120]}"
    return False, last_err


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source", choices=["shodan", "censys", "leakix", "file"], required=True
    )
    parser.add_argument("--hosts-file", help="file with IPs/domains (file mode)")
    parser.add_argument("--limit", type=int, default=100, help="shodan: max results")
    parser.add_argument("--pages", type=int, default=3,
                        help="censys/leakix: pages (100 per page, ignored on shodan)")
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--output", help="file to save valid hosts")
    parser.add_argument("--json", dest="json_out", help="save details as JSON")
    args = parser.parse_args()

    if args.source == "shodan":
        key = os.environ.get("SHODAN_API_KEY")
        if not key:
            sys.exit("set SHODAN_API_KEY")
        hosts = search_shodan(key, limit=args.limit)
    elif args.source == "censys":
        api_id = os.environ.get("CENSYS_API_ID")
        api_secret = os.environ.get("CENSYS_API_SECRET")
        if not (api_id and api_secret):
            sys.exit("set CENSYS_API_ID and CENSYS_API_SECRET")
        hosts = search_censys(api_id, api_secret, pages=args.pages)
    elif args.source == "leakix":
        key = os.environ.get("LEAKIX_API_KEY")
        if not key:
            sys.exit("set LEAKIX_API_KEY (free at https://leakix.net/auth)")
        hosts = search_leakix(key, pages=args.pages)
    else:
        if not args.hosts_file:
            sys.exit("--source file requires --hosts-file")
        hosts = load_hosts_file(args.hosts_file)

    print(f"[+] {len(hosts)} hosts returned by source\n")

    valid, details, seen = [], [], set()
    for h in hosts:
        domains = candidate_domains(h)
        if not domains:
            print(f"[-] {h['ip']}: no usable hostname/CN")
            continue
        for domain in domains:
            if domain in seen:
                continue
            seen.add(domain)
            ok, info = try_register(domain, timeout=args.timeout)
            tag = "OK " if ok else "--"
            print(f"[{tag}] {domain:40s} {info}")
            details.append({"domain": domain, "ip": h["ip"], "ok": ok, "info": info})
            if ok:
                valid.append(domain)

    print(f"\n[+] {len(valid)} interactsh servers without token")
    for v in valid:
        print(f"    - {v}")

    if args.output and valid:
        with open(args.output, "w") as fp:
            fp.write("\n".join(valid) + "\n")
        print(f"[+] saved to {args.output}")
    if args.json_out:
        with open(args.json_out, "w") as fp:
            json.dump(details, fp, indent=2)
        print(f"[+] details in {args.json_out}")


if __name__ == "__main__":
    main()

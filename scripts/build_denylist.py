#!/usr/bin/env python3
from __future__ import annotations

import datetime as dt
import hashlib
import ipaddress
import json
from pathlib import Path
import urllib.error
import urllib.request

SOURCES = {
    "ipsum_level3": {
        "url": "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt",
        "min": 1000,
    },
    "blocklist_de_apache": {
        "url": "https://lists.blocklist.de/lists/apache.txt",
        "min": 100,
    },
    "blocklist_de_bruteforce": {
        "url": "https://lists.blocklist.de/lists/bruteforcelogin.txt",
        "min": 10,
    },
    "blocklist_de_strongips": {
        "url": "https://lists.blocklist.de/lists/strongips.txt",
        "min": 10,
    },
}

GOOGLE_RELAY = (
    "https://raw.githubusercontent.com/digicompkala/"
    "dck-google-ipranges-relay/main/dist/google-ipranges.json"
)
PROTECTED_FILE = Path("config/protected-networks.txt")
DIST = Path("dist")
OUT4 = DIST / "dck-hard-deny-v4.txt"
OUT6 = DIST / "dck-hard-deny-v6.txt"
REPORT = DIST / "dck-threat-report.json"
MAX_BODY = 8 * 1024 * 1024
UA = "DCK-Threat-Denylist-Relay/1.0 (+https://github.com/digicompkala/dck-threat-denylist-relay)"


def now_utc() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def fetch(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "text/plain,application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            if getattr(r, "status", r.getcode()) != 200:
                raise RuntimeError(f"HTTP {getattr(r, 'status', r.getcode())}: {url}")
            body = r.read(MAX_BODY + 1)
    except (urllib.error.HTTPError, urllib.error.URLError) as exc:
        raise RuntimeError(f"download failed: {url}: {exc}") from exc
    if not body or len(body) > MAX_BODY:
        raise RuntimeError(f"invalid body size for {url}: {len(body)}")
    return body


def parse_network_lines(body: bytes) -> set[ipaddress._BaseNetwork]:
    out: set[ipaddress._BaseNetwork] = set()
    text = body.decode("utf-8", "replace")
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        token = line.split()[0].strip().strip(",;")
        try:
            net = ipaddress.ip_network(token, strict=False)
        except ValueError:
            continue
        # Never publish RFC1918, loopback, link-local, multicast, reserved, etc.
        if not net.is_global:
            continue
        out.add(net)
    return out


def load_static_protected() -> set[ipaddress._BaseNetwork]:
    if not PROTECTED_FILE.is_file():
        raise RuntimeError("protected-networks.txt missing")
    return parse_network_lines(PROTECTED_FILE.read_bytes())


def load_google_protected() -> set[ipaddress._BaseNetwork]:
    data = json.loads(fetch(GOOGLE_RELAY).decode("utf-8"))
    rows = data.get("ranges")
    if not isinstance(rows, list) or len(rows) < 10:
        raise RuntimeError("Google relay ranges missing/too small")
    out: set[ipaddress._BaseNetwork] = set()
    for row in rows:
        if not isinstance(row, dict) or not row.get("cidr"):
            continue
        try:
            out.add(ipaddress.ip_network(str(row["cidr"]), strict=False))
        except ValueError:
            raise RuntimeError(f"invalid Google CIDR: {row.get('cidr')}")
    if len(out) < 10:
        raise RuntimeError("Google protected set unexpectedly small")
    return out


def collapse(items: set[ipaddress._BaseNetwork]) -> list[ipaddress._BaseNetwork]:
    result: list[ipaddress._BaseNetwork] = []
    for version in (4, 6):
        same = [n for n in items if n.version == version]
        result.extend(ipaddress.collapse_addresses(same))
    return sorted(result, key=lambda n: (n.version, int(n.network_address), n.prefixlen))


def overlaps_protected(net: ipaddress._BaseNetwork, protected: list[ipaddress._BaseNetwork]) -> bool:
    return any(net.version == p.version and net.overlaps(p) for p in protected)


def atomic_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(path)


def atomic_json(path: Path, obj: dict) -> None:
    atomic_text(path, json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True) + "\n")


def main() -> int:
    source_sets: dict[str, set[ipaddress._BaseNetwork]] = {}
    source_meta: dict[str, dict] = {}
    combined: set[ipaddress._BaseNetwork] = set()

    for name, cfg in SOURCES.items():
        body = fetch(cfg["url"])
        nets = parse_network_lines(body)
        if len(nets) < int(cfg["min"]):
            raise RuntimeError(f"{name}: count too small: {len(nets)} < {cfg['min']}")
        source_sets[name] = nets
        combined.update(nets)
        source_meta[name] = {
            "url": cfg["url"],
            "count": len(nets),
            "sha256": hashlib.sha256(body).hexdigest(),
        }
        print(f"SOURCE={name} COUNT={len(nets)}")

    static_protected = load_static_protected()
    google_protected = load_google_protected()
    protected = collapse(static_protected | google_protected)

    before = len(combined)
    safe = {n for n in combined if not overlaps_protected(n, protected)}
    excluded = before - len(safe)

    final = collapse(safe)
    v4 = [n for n in final if n.version == 4]
    v6 = [n for n in final if n.version == 6]

    if len(v4) < 1000:
        raise RuntimeError(f"final IPv4 list unexpectedly small: {len(v4)}")

    text4 = "".join(f"{n}\n" for n in v4)
    text6 = "".join(f"{n}\n" for n in v6)

    report_payload = {
        "schema_version": 1,
        "generated_at": now_utc(),
        "policy": {
            "purpose": "high-confidence inbound HTTP threat hard-deny relay",
            "google_excluded": True,
            "local_protected_networks_excluded": True,
            "non_global_networks_excluded": True,
            "ipsum_min_blacklist_occurrences": 3,
        },
        "sources": source_meta,
        "counts": {
            "raw_unique_networks": before,
            "protected_networks": len(protected),
            "excluded_due_to_protection": excluded,
            "final_ipv4_networks": len(v4),
            "final_ipv6_networks": len(v6),
        },
        "outputs": {
            "dck-hard-deny-v4.txt": hashlib.sha256(text4.encode()).hexdigest(),
            "dck-hard-deny-v6.txt": hashlib.sha256(text6.encode()).hexdigest(),
        },
    }

    atomic_text(OUT4, text4)
    atomic_text(OUT6, text6)
    atomic_json(REPORT, report_payload)

    print(f"RAW_UNIQUE={before}")
    print(f"PROTECTED={len(protected)}")
    print(f"EXCLUDED_PROTECTED={excluded}")
    print(f"FINAL_IPV4={len(v4)}")
    print(f"FINAL_IPV6={len(v6)}")
    print("STATUS=OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

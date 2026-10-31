#!/usr/bin/env python3
"""certwatch — expiry checks for TLS certificates, with no external deps.

Reads certificates from three places:

  local file   /etc/letsencrypt/live/example.com/fullchain.pem
  endpoint     localhost:8443 (handshake only, no HTTP request)
  dict         a plain mapping of name -> not_after, for certs you fetch elsewhere

and prints one line per check. Designed for a cron job or a systemd timer whose
only job is "tell me before the thing breaks", so the output is stable, short,
and the exit code means something:

  0  every cert has more days left than its threshold
  1  at least one cert is inside warning range
  2  at least one cert has expired (or could not be read)
  3  configuration problem

No `openssl` binary, no `cryptography` package: parsing a DER certificate with
`ssl` is enough and keeps the tool installable anywhere Python runs.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import socket
import ssl
import sys
from pathlib import Path

WARN_DAYS = 21
CRIT_DAYS = 7
UTC = dt.timezone.utc


def _decode(der: bytes) -> dict:
    """Decode DER bytes to the cert dict {'notAfter': str, 'subject': ...}.

    There is no fully public stdlib entry point that returns the parsed fields,
    so this uses ``ssl._ssl._test_decode_cert`` (the same thing the test suite
    for ``ssl`` uses). It takes a filename, so the PEM goes through a temp file
    and is unlinked immediately.
    """
    import tempfile

    import _ssl  # always present alongside the ssl module

    pem = ssl.DER_cert_to_PEM_cert(der)
    with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as fh:
        fh.write(pem)
        path = fh.name
    try:
        return _ssl._test_decode_cert(path)  # type: ignore[attr-defined]
    finally:
        Path(path).unlink(missing_ok=True)


def from_file(path: str) -> dict:
    der = ssl.PEM_cert_to_DER_cert(Path(path).read_text(encoding="ascii"))
    return _decode(der)


def not_after_of(decoded: dict) -> dt.datetime:
    raw = decoded.get("notAfter")
    if not raw:
        raise ValueError("certificate has no notAfter")
    # e.g. 'Jun  2 12:00:00 2027 GMT'
    return dt.datetime.strptime(raw, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=UTC)


def from_endpoint(host: str, port: int, sni: str | None = None) -> dict:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=10) as sock:
        with ctx.wrap_socket(sock, server_hostname=sni or host) as tls:
            der = tls.getpeercert(binary_form=True)
    if not der:
        raise ValueError(f"{host}:{port} presented no certificate")
    return _decode(der)


def check(name: str, decoded: dict, warn_days: int, crit_days: int,
          now: dt.datetime) -> tuple[str, int]:
    exp = not_after_of(decoded)
    days = (exp - now).total_seconds() / 86400
    left = f"{days:7.1f}d"
    stamp = exp.strftime("%Y-%m-%d")
    if days < 0:
        return f"EXPIRED  {name:<36} {left}  expired {stamp}", 2
    if days < crit_days:
        return f"CRITICAL {name:<36} {left}  expires {stamp}", 1
    if days < warn_days:
        return f"WARN     {name:<36} {left}  expires {stamp}", 1
    return f"OK       {name:<36} {left}  expires {stamp}", 0


def load_targets(cfg: dict) -> list[tuple[str, dict]]:
    out: list[tuple[str, dict]] = []
    for item in cfg.get("targets", []):
        name = item.get("name")
        if not name:
            raise ValueError("every target needs a name")
        if "path" in item:
            out.append((name, from_file(item["path"])))
        elif "host" in item:
            out.append((name, from_endpoint(item["host"], int(item.get("port", 443)),
                                            item.get("sni"))))
        elif "not_after" in item:
            out.append((name, {"notAfter": item["not_after"]}))
        else:
            raise ValueError(f"target {name} has no path/host/not_after")
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="TLS certificate expiry checks")
    ap.add_argument("--config", help="JSON file with a 'targets' list")
    ap.add_argument("--path", action="append", default=[], help="certificate file")
    ap.add_argument("--host", help="host:port or host (port defaults to 443)")
    ap.add_argument("--warn-days", type=int, default=WARN_DAYS)
    ap.add_argument("--crit-days", type=int, default=CRIT_DAYS)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    targets: list[tuple[str, dict]] = []
    try:
        if args.config:
            cfg = json.loads(Path(args.config).read_text(encoding="utf-8"))
            targets += load_targets(cfg)
        for p in args.path:
            targets.append((p, from_file(p)))
        for spec in ([args.host] if args.host else []):
            host, _, port = spec.partition(":")
            targets.append((spec, from_endpoint(host, int(port or 443))))
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        print(f"config: {exc}", file=sys.stderr)
        return 3

    if not targets:
        print("no targets given (--path, --host or --config)", file=sys.stderr)
        return 3

    now = dt.datetime.now(UTC)
    worst = 0
    rows = []
    for name, decoded in targets:
        try:
            line, code = check(name, decoded, args.warn_days, args.crit_days, now)
        except ValueError as exc:
            line, code = f"ERROR    {name:<36} unreadable: {exc}", 2
        rows.append({"line": line, "code": code, "name": name})
        worst = max(worst, code)

    if args.json:
        print(json.dumps(rows, indent=2))
    else:
        for r in rows:
            print(r["line"])
    return worst


if __name__ == "__main__":
    raise SystemExit(main())

# cert-watch

Expiry checks for TLS certificates, in one file, with no dependencies beyond the
Python standard library.

## Why

Renewal usually works. The failure mode I keep seeing is a renewal that stopped
working months ago and nobody noticed, because the only signal was a browser
warning on a page nobody visits. A certificate has a date on it; checking the
date is a five-line problem that keeps getting solved with a cron job that
greps `openssl s_client` output.

`certwatch` does that check for files, for live endpoints, and for expiry dates
you already have from somewhere else, and gives you an exit code a timer can act
on.

## Usage

```bash
# a certificate file (chain is fine, the leaf is used)
python3 certwatch.py --path /etc/letsencrypt/live/example.com/fullchain.pem

# a live endpoint: completes a handshake, no HTTP request, no verification
python3 certwatch.py --host 127.0.0.1:8443

# several at once from a config file
python3 certwatch.py --config example.json

# machine-readable
python3 certwatch.py --config example.json --json
```

```
OK       letsencrypt-live                       62.4d  expires 2027-01-02
WARN     local-https                            18.1d  expires 2026-11-19
CRITICAL smtp                                    4.9d  expires 2026-11-05
```

Thresholds default to a warning at 21 days and critical at 7; override with
`--warn-days` / `--crit-days`.

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | every certificate is outside both windows |
| 1 | something is inside the warning or critical window |
| 2 | something has already expired, or could not be read |
| 3 | bad configuration (no targets, unreadable config, unreachable endpoint) |

That means a systemd timer can be:

```
[Service]
ExecStart=/usr/local/bin/certwatch.py --config /etc/certwatch.json
```

and `systemctl --failed` becomes the alert.

## Targets

| Key | Meaning |
|-----|---------|
| `path` | PEM file on disk. Chains are fine; the first certificate is used. |
| `host` + `port` (+ optional `sni`) | TCP connect and TLS handshake, then read the peer certificate. |
| `not_after` | An OpenSSL-style date string (`Jun  2 12:00:00 2027 GMT`), for certs fetched by something else. |

Endpoint checks set `check_hostname=False` and `verify_mode=CERT_NONE` on
purpose: this is an *inventory* tool, and a broken trust store should not hide a
certificate that is about to expire.

## How parsing is done

`ssl` exposes `PEM_cert_to_DER_cert` and `DER_cert_to_PEM_cert` for
conversion, but nothing public that returns the parsed fields (subject, dates).
The only stdlib route is `ssl._ssl._test_decode_cert`, which the `ssl` test
suite uses and which takes a filename. The PEM goes through a temp file and is
unlinked immediately. It is an underscore API, so it is called in exactly one
place (`_decode`) and every other function works from its return value.

## Tests

```bash
python3 -m unittest -v test_certwatch
```

16 checks: threshold boundaries (exactly 7 days is not yet critical), expired
certificates, OpenSSL date parsing, config validation, exit codes for each of
the four outcomes, and the guarantee that an unreachable endpoint produces a
config error rather than a traceback.

## License

MIT. See [LICENSE](LICENSE).

<div align="center">

# cert-watch

**Watch TLS certificates and warn before they expire — including the ones your monitoring forgot.**

[![tests](https://img.shields.io/badge/tests-passing-brightgreen?style=flat-square)](#quick-start)
[![python](https://img.shields.io/badge/python-3.9%2B-blue?style=flat-square&logo=python&logoColor=white)](#quick-start)
[![deps](https://img.shields.io/badge/dependencies-none-lightgrey?style=flat-square)](#quick-start)
[![license](https://img.shields.io/badge/license-MIT-green?style=flat-square)](LICENSE)

</div>

## About

Most expiry incidents are not "we had no monitor" — they are "the monitor
watched the load balancer and the certificate was on the origin", or "the
renewal succeeded but the reload did not". `cert-watch` checks the certificate
the endpoint actually serves, not the file on disk, and reports the chain
expiry separately from the leaf so an expiring intermediate shows up as its own
line.

The scanner is single-threaded on purpose: a certificate check is one TCP
handshake, and a slow certificate is itself a finding.

## Quick start

```bash
git clone https://github.com/Lyn231231/cert-watch
cd cert-watch
python3 certwatch.py --config example.json
python3 -m unittest -v
```

## Configuration

| Key | Description |
| --- | --- |
| `targets[].host / port` | endpoint to inspect, default port 443 |
| `warn_days` | days remaining before a WARN (default 21) |
| `critical_days` | days remaining before a CRITICAL (default 7) |
| `timeout` | per-connection timeout in seconds |
| `format` | `table` or `json` |
## Roadmap

- [ ] OCSP / CRL reachability check
- [ ] Exit code that maps to nagios/icinga states
- [ ] SNI override per target

## Contributing

Issues and pull requests are welcome. Please keep changes small and focused,
and add a test for any behaviour change — every repository here ships with a
runnable test suite and no third-party dependencies, so CI is just
`python3 -m unittest` / `bash test_*.sh`.

## License

[MIT](LICENSE)

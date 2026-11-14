# Q-Key TLS Report 20261114T171609.714411593Z

- Assessment: `tls-endpoint-check`
- Started: 2026-11-14T17:16:09Z
- Finished: 2026-11-14T17:16:09Z
- Tool: qkey-tls-reporter 0.1.0-alpha.1
- Result: 0/1 scenarios matched expectations

## Environment

- go_version: `go1.27.4`
- goarch: `amd64`
- goos: `linux`

## Results

| Lab | Scenario | Match | Expected | Observed |
|---|---|---|---|---|
| tls | endpoint | NO | TLS 1.3; certificate verifies; policy=require-hybrid | status=inconclusive category=network_error certificate=not_completed error=dial tcp: lookup tcp///example.test: unknown port |

## Limitations

- One TLS connection from this client to the reached TLS termination point; not a full supported-group or interoperability scan.
- Not a certification, validation, or compliance attestation (including FIPS 140-3, CNSA 2.0, or Common Criteria).
- Results describe the named library versions only and require human cryptography review before external use.

Per-scenario findings, standards references and limitations are in `artifacts/`. Verify integrity with `sha256sum -c SHA256SUMS`.

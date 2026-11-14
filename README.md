# Q-Key TLS Regression Reporter

A small, free command-line tool that checks one TLS 1.3 connection against a
selected key-exchange policy. It verifies the server certificate, reports the
negotiated group, and writes JSON results, a Markdown report and SHA-256 checksums
to a local directory.

The default policy passes only when a verified connection negotiates
`X25519MLKEM768`. An optional baseline records differences from a previous result;
baseline differences alone do not fail the check.

**Alpha — v0.1.0-alpha.1.** Tested on Linux with Go 1.27.4. Hybrid negotiation is
tested with Go loopback fixtures. The optional Go/OpenSSL tests cover classical
TLS 1.3, certificate failures and handshake rejection; they do not establish
hybrid OpenSSL interoperability. See [validation](docs/VALIDATION.md).

## Try it without a server

Requires Go 1.27 or later; the Go CLI has no third-party module dependencies.

```bash
go build -trimpath -o bin/qkey-tls-reporter ./cmd/qkey-tls-reporter
./bin/qkey-tls-reporter -demo -out results/demo
```

The demo runs real TLS connections over loopback using certificates and keys
generated in memory. It records four separate outcomes:

| Case | Recorded result |
|---|---|
| Hybrid negotiation, valid certificate | Pass |
| Classical negotiation under require-hybrid | Fail, with changes from the first baseline |
| Classical negotiation explicitly allowed | Pass |
| Wrong certificate hostname | Fail |

The demo exits 0 only when all four **expected outcomes** occurred. The individual
negative bundles still record failures. Demo keys are never written to disk.

## Check your staging endpoint

Use only endpoints you own or have permission to test. This makes one TCP/TLS
connection and sends no HTTP requests or application data.

```bash
./bin/qkey-tls-reporter \
  -target staging.example.com:443 \
  -policy require-hybrid \
  -out results/first
```

`staging.example.com` is a placeholder; replace it with your own staging service.
For a private CA or a connection by IP:

```bash
./bin/qkey-tls-reporter \
  -target 127.0.0.1:9443 \
  -servername staging.example.com \
  -ca-file ./staging-ca.pem \
  -policy require-hybrid \
  -out results/second
```

`-ca-file` adds trusted public certificates to system trust. No client private key
or authentication credential is requested. Certificate verification is always on.

## Policies and exit codes

- `require-hybrid` (default): the verified handshake must negotiate
  `X25519MLKEM768`.
- `allow-classical`: a verified TLS 1.3 handshake may use any of the offered groups.

Both policies offer the same explicit set: `X25519MLKEM768`, `X25519`, `P-256`,
and `P-384`. The policy evaluates the negotiated outcome after the handshake;
classical groups remain in the client's offer. TLS 1.2 is not supported.

| Exit | Meaning |
|---|---|
| 0 | Verified handshake matched the selected policy, or the demo matched all expected outcomes |
| 1 | Observed policy mismatch or certificate validation failure |
| 2 | Configuration/output error or inconclusive network/handshake failure |

These exit codes let a CI job fail on a policy mismatch or certificate error,
and distinguish either from an inconclusive check. To retain results alongside
CI logs, configure your workflow to run the CLI and upload its output directory.
The bundled CI workflow runs local fixtures and checks demo checksums; it does
not scan a deployment or upload evidence bundles.

A failed handshake does not prove that a server lacks PQ support. The tool keeps
network, certificate and other handshake errors distinct in the artifact.

## Compare a baseline

```bash
./bin/qkey-tls-reporter \
  -target staging.example.com:443 \
  -policy require-hybrid \
  -baseline results/first/artifacts/tls.endpoint.json \
  -out results/after-change
```

Baseline target, certificate name, policy and CA-input identity must match. Changes
to group, TLS version, cipher suite, certificate verification and leaf fingerprint
are recorded in the new artifact. Certificate rotation can be a legitimate change.
**A baseline difference alone does not change the exit code**; the current policy
and connection outcome determine it. Use only a baseline you trust; it is not
authenticated by the reporter. System trust-store changes are not independently
inventoried, and additional CA-input identity is based on the supplied PEM bytes.

## Evidence output

Every check creates a new private directory and refuses to overwrite an existing
one. The directory contains:

```text
REPORT.md
manifest.json
SHA256SUMS
artifacts/tls.endpoint.json
observations/tls.endpoint.json
```

JSON includes the status/category, negotiated group, certificate-verification
result, leaf fingerprint/signature algorithm, policy and bounded limitations.
Evidence is unreviewed. Target names and error details may be confidential: the
`results/` directory is Git-ignored. Review results before sharing them.

Verify file integrity with standard Linux tools:

```bash
cd results/first
sha256sum -c SHA256SUMS
```

An optional Python validator also checks the observation schema, manifest totals,
confined evidence references and private-key PEM markers:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install --require-hashes -r requirements.txt
.venv/bin/python scripts/validate_evidence.py results/first
```

Hashes detect changes relative to the recorded hashes. They do not establish who
collected the evidence, whether the collector is trustworthy, or whether its
conclusions are correct.

## Scope and limits

This release observes one connection from Go's TLS client to the reached TLS
termination point. It does not enumerate every supported group or test other
client implementations. A load balancer/CDN result says nothing about later hops.
A hybrid key exchange does not establish a PQ certificate, data-at-rest protection,
whole-product quantum safety, certification or compliance. This is an engineering
aid, not a cryptographic assessment or production approval.

## Development and feedback

```bash
make check
make demo
make interop  # optional: requires OpenSSL on PATH
```

`make check` checks Go formatting, runs `go vet`, race-enabled Go tests, the
release-source pattern check and Python release-tool tests. Tests use loopback
fixtures, not outside services. The optional
[OpenSSL interoperability suite](docs/INTEROPERABILITY.md) adds the seven
cross-stack cases listed in that document. `.github/workflows/ci.yml` runs both
commands and the demo. Source pattern checks do not guarantee that all sensitive
material has been detected.

Useful feedback: what workflow you tried, whether you ran it again or put it into
CI, and what your existing tools already handle better. Use the feedback issue
template and share a synthetic reproducer. Do not post private endpoints or raw
production results. Security concerns can be reported via GitHub's private
vulnerability reporting if the maintainer enables it; see [SECURITY.md](SECURITY.md).

The reporter contains **no analytics, signup requirement, update check or telemetry
calls**. The Go build/dependency installer and GitHub services have their own network
behavior.

## License

Apache-2.0. Copyright 2026 a1a23linux and contributors.
See [LICENSE](LICENSE) and [NOTICE](NOTICE). This alpha reuses Q-Key's original
evidence recorder/schema/validator and adds a standalone endpoint adapter and demo.

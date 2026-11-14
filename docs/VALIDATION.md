# Alpha validation record

Validated November 14, 2026 on Linux amd64 with Go 1.27.4 and Python 3.12.
The Go distribution was verified against the SHA-256 published in the official
Go download metadata. It was installed locally for preparation, not shipped in
this source release.

Checks completed:

- gofmt check, go vet and Go race-enabled tests.
- Real loopback TLS 1.3 handshakes: hybrid success, classical policy mismatch,
  explicitly allowed classical success, wrong-hostname rejection and untrusted
  certificate rejection.
- Refused connection and handshake timeout remain inconclusive, distinct from a
  successful handshake that violates policy.
- Baseline differences, mismatched comparison context and existing-output refusal.
- Documented CLI build and four-case local demonstration.
- Fresh Python virtual environment with --require-hashes installation of the
  optional validator dependencies; pinned package license metadata inspected.
- Every demo bundle passes schema, checksum, manifest and reference validation.
- Modified artifact and escaping evidence-reference negative checks.
- Public-source checks for selected private-path, private-host/IP, credential and
  private-key patterns. These pattern checks do not guarantee absence of arbitrary
  confidential information.

The local tests do not establish performance, external-stack interoperability,
production readiness, cryptographic assessment or certification. No public endpoint
was scanned for this validation. GitHub CI awaits publication. Runtime analytics
are not implemented.

The release includes source only. Generated evidence, environments and build
outputs used in preparation are excluded from the public source package.

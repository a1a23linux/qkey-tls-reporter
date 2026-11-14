# Go and OpenSSL interoperability

Run the optional cross-stack suite on Linux:

```bash
make interop
```

This requires OpenSSL on PATH and the same Go toolchain as the reporter. Normal
Go tests and the CLI do not require OpenSSL. The suite uses loopback endpoints;
no outside service, container, daemon configuration or package installation is
performed by the tests. Go/OpenSSL versions are printed by the test runner.

## Verified scope

On November 14, 2026, Go 1.27.4 and OpenSSL 3.0.13 passed seven cases:

| Direction | Case | Observed result |
|---|---|---|
| Go client → OpenSSL server | Classical X25519 explicitly allowed | Verified TLS 1.3 connection; policy pass |
| Go client → OpenSSL server | Same connection with require-hybrid policy | Verified TLS 1.3 / X25519; policy failure |
| Go client → OpenSSL server | Wrong certificate hostname | Certificate failure |
| Go client → OpenSSL server | Untrusted certificate | Certificate failure |
| OpenSSL client → Go server | Classical X25519 and valid hostname | Verified TLS 1.3 connection |
| OpenSSL client → Go server | Wrong hostname | Hostname verification rejected the connection |
| OpenSSL client → Go server | Classical-only client, hybrid-only server | Handshake rejected |

All seven are expected-outcome assertions. A policy/certificate rejection in a
negative case remains a rejection; it is not relabeled as a successful connection.
The suite does not prove OpenSSL hybrid negotiation or any other stack's behavior.
The declared X25519-only configurations make these cases meaningful on older and
newer OpenSSL versions without confusing a classical success with a PQ result.

The OpenSSL server test writes a newly generated synthetic private key into its
private test temporary directory (mode 0600) because s_server reads a key file.
Go's test cleanup removes that directory. No real key is used or saved in the
repository. The normal CLI and the standalone demo still write no private keys.

This suite prints test results rather than generating reporter evidence bundles
for every reverse-direction client case. Do not count it as part of the separate
private 58-check nightly lab until that lab explicitly integrates and verifies it.

## Remaining coverage

- Hybrid negotiation with an appropriately configured OpenSSL backend.
- BoringSSL, NSS, Java and Windows SChannel integrations.
- Wider version/platform matrices and behavior behind real staging proxies.

These remain untested by this suite. GitHub CI includes `make interop`;
[run 43632016088](https://github.com/a1a23linux/qkey-tls-reporter/actions/runs/43632016088)
completed successfully for commit `3a113a3949bb6c3f059f18d8deb30a404d96d15b`.
That result does not extend the suite's coverage beyond the cases listed above.

# Changelog

## Unreleased

- Clarify the current single-connection policy check, local output and CI setup;
  scope validation claims to recorded tests and update the publishing guidance for
  the existing repository.

- Add optional make interop: seven loopback Go/OpenSSL expected-outcome checks,
  covering classical TLS 1.3, certificate rejection and a hybrid-only server's
  rejection of a classical client. Hybrid OpenSSL negotiation remains untested.
- Add the optional interoperability suite to CI.
- Reject URL targets and invalid/non-numeric ports before attempting a connection
  or creating evidence. Strengthen CLI tests to assert no output on invalid input.
- Remove generated invalid-input test results and ignore results directories at
  every depth. No user endpoint results are included in the source release.

## 0.1.0-alpha.1

- Initial research alpha: one endpoint's TLS 1.3 policy check, certificate
  verification, baseline differences, hashed evidence and a local demonstration.

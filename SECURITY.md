# Security and evidence scope

Use only authorized staging endpoints. Certificate verification is always enabled;
there is no insecure-skip option, production-key import, command execution, remote
agent, telemetry collector or hosted dashboard in this package.

Generated evidence can contain endpoint names, public-certificate fingerprints and
error details. Treat it according to your organization's rules. Do not commit it
or attach unredacted results to a public issue. The loopback demo generates keys
in memory and saves no private keys or PINs.

Checks describe one client connection and its exact configured scope. They do not
establish certification, whole-product safety, key custody, all supported groups,
all clients or later network hops. A failed connection is not proof of missing PQ
support. Hashes provide content integrity relative to the manifest, not authenticity
or approval. Treat baselines as trusted local input.

This research alpha has no support or security-response SLA. For a vulnerability,
use the repository's private **Security → Report a vulnerability** route if enabled.
If unavailable, do not publish exploit details or sensitive evidence in an issue;
ask the maintainer for a private contact channel. No private reporting endpoint is
claimed to exist before the repository is published and configured.

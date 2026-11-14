# Contributing

Start with a small issue describing the desired behavior and a sanitized or
loopback reproducer. Keep claims scoped to directly observed behavior. Do not add
credentials, real private keys, private endpoints, benchmark claims without
reproducible inputs, or unsolicited telemetry.

Use Go 1.27 or later on Linux. Run `make check` before proposing a change. Add tests
for network, certificate and policy failures when behavior changes. Keep the
optional validator compatible with the emitted evidence format.

Changes to public JSON fields, policy meaning or exit codes need documentation.
Contributions are provided under the repository's Apache-2.0 license.

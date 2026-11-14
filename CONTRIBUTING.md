# Contributing

Start with a small issue describing the desired behavior and a sanitized or
loopback reproducer. Keep claims scoped to directly observed behavior. Do not add
credentials, real private keys, private endpoints, benchmark claims without
reproducible inputs, or unsolicited telemetry.

Use Go 1.27 or later on Linux. Run `make check` before proposing a change. Add tests
for network, certificate and policy failures when behavior changes. Keep the
optional validator compatible with the emitted evidence format.

Changes to public JSON fields, policy meaning or exit codes need documentation.
Public descriptions must match implemented behavior. Describe planned features as
planned, and name the tested versions, platforms and cases when discussing
validation. Keep endpoint capability, an observed negotiated connection and
server enforcement distinct. Do not infer automatic CI artifact uploads from
local file output, or claim novelty, comparative advantages, certification or
production readiness without supporting evidence.

Contributions are provided under the repository's Apache-2.0 license.

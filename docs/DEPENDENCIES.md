# Dependencies and provenance

## Go tool

The reporter, demo and Go tests use the Go 1.27 standard library only. There are
no third-party Go module dependencies and no vendored libraries. The standard
library performs TLS and cryptography; this package implements no cryptographic
primitive. Go's license is in GO-LICENSE.

## Optional Python evidence validator

The validator uses jsonschema. requirements.txt is copied from the original
Q-Key validator environment and pins transitive packages and artifact hashes.
These packages are downloaded separately through pip, not included as source or
relicensed by the first-party license. Their published project metadata identifies:

- attrs: MIT
- jsonschema: MIT
- jsonschema-specifications: MIT
- referencing: MIT
- rpds-py: MIT
- typing-extensions: PSF-2.0

These expressions were checked against the installed pinned distribution metadata.
Confirm package metadata when updating requirements. Go execution, Go tests,
and the release checker do not require them.

## Origin of copied first-party material

The observation schema, evidence recorder/tests and optional evidence validator
were copied from the owner's Q-Key lab and adapted for endpoint observations.
Changes include the public tool identity, scope statements, private output modes,
and refusal to overwrite output directories. Private reports, deployment tools,
research documents, host settings and signing material were not selected.

Only the Go standard library was used for the new endpoint adapter and ephemeral
demo. GitHub Actions checkouts/setup steps download their own tooling during CI.

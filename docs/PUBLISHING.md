# Publishing changes

Repository: [a1a23linux/qkey-tls-reporter](https://github.com/a1a23linux/qkey-tls-reporter).
The repository is already public. Preserve its existing history when publishing
reviewed changes.

## Review the source

From the reporter checkout on Linux, with Go 1.27 or later available:

```bash
make check
git diff --check
git status --short
git diff
```

For changes affecting TLS behavior, also run `make interop` with OpenSSL available.
Review the exact changes and check results before committing or pushing through
the normal Git workflow. Do not recreate the repository or force-push its history.

Publish only this tool's source. Exclude generated results, build outputs,
environments, private configuration, credentials and unrelated project material.
Review the staged file list before committing; a passing source-pattern check is
not proof that every confidential value has been detected.

## Repository description

Suggested description, limited to implemented behavior:

> TLS 1.3 endpoint policy checker with certificate verification, hybrid
> key-exchange checks, baseline comparison and local JSON reports. Apache-2.0.

Describe CI use precisely: exit codes can gate a job, and the CLI writes local
files. Retaining those files as CI artifacts requires workflow configuration.
The bundled workflow runs loopback fixtures, the demo and checksum checks; it
does not scan a deployment or upload evidence bundles.

## Release scope

Keep release notes tied to the source being released and its recorded checks.
Name tested platforms, tool versions and interoperability cases. Go hybrid
loopback tests do not establish hybrid interoperability with OpenSSL or other
stacks. Saved checksums do not authenticate the collector or certify its results.

Check whether private vulnerability reporting is enabled before directing users
to that channel, and decide who will respond. Create a tag or release only for
reviewed source, with assets corresponding to that version.

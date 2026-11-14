# Publishing this alpha

Suggested repository: `a1a23linux/qkey-tls-reporter`.
The namespace in go.mod and issue references assumes this name; update it if you
choose another. Preparing this directory does not create a GitHub repository.

Publish this directory's contents only. Use the source archive or this directory,
not the parent recovery workspace. Do not copy results/, private
planning, imported conversations or the original deployment repositories.

From this directory on Linux, after reviewing the files:

```bash
make check
git init -b main
git add .
git diff --cached --stat
git commit -m "Initial public research alpha"
gh auth login
gh repo create a1a23linux/qkey-tls-reporter --public --source=. --remote=origin --push
```

Run the create command only when you intend to publish. It is a human-run example,
not something the preparation process executes. Existing repositories require a
different workflow; do not overwrite or force-push to an existing repository.
Set your normal Git author identity if Git requests it. Do not put tokens into
source, shell commands or this directory.

Repository description suggestion:

> Research alpha: TLS 1.3 hybrid-policy checks, baseline differences and hashed
> evidence for staging and CI. Local execution, no telemetry.

Enable private vulnerability reporting and decide who will respond before inviting
security reports. Publish an alpha tag/release when ready, with named binary or
source assets for the supported version.

Keep the first release scoped to the tested Go client and Linux environment.
External-stack interoperability, production hardening and cryptographic assessment
are not established by the local fixture tests. CI is provided but has not run on
GitHub until the repository exists.

#!/usr/bin/env python3
"""Validate a qkeylab evidence bundle.

Checks every observation against schemas/observation.schema.json (JSON Schema
2020-12), confines and verifies every evidence reference, reconciles the
manifest and SHA256SUMS with the files on disk, and rejects private key
material anywhere in the bundle.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from datetime import datetime
from pathlib import Path, PurePosixPath

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "schemas" / "observation.schema.json"
PRIVATE_KEY = re.compile(rb"-{5}BEGIN [A-Z0-9 ]*PRIVATE KEY-{5}")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def confined(run: Path, uri: str) -> Path | None:
    rel = PurePosixPath(uri)
    if rel.is_absolute() or ".." in rel.parts or ":" in uri or "\\" in uri:
        return None
    target = (run / Path(*rel.parts)).resolve()
    if run not in target.parents:
        return None
    return target


def rfc3339(value: str) -> bool:
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})", value):
        return False
    try:
        datetime.fromisoformat(value)
    except ValueError:
        return False
    return True


def validate(run: Path) -> list[str]:
    errors: list[str] = []
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)

    manifest = json.loads((run / "manifest.json").read_text(encoding="utf-8"))
    results = manifest.get("results", [])
    passed = sum(1 for r in results if r.get("pass") is True)
    if (manifest.get("total"), manifest.get("passed"), manifest.get("failed")) != (
        len(results),
        passed,
        len(results) - passed,
    ):
        errors.append("manifest totals do not match results")

    observation_files = sorted(p.relative_to(run).as_posix() for p in (run / "observations").glob("*.json"))
    listed = sorted(r.get("observation", "") for r in results)
    if observation_files != listed:
        errors.append("observation files on disk differ from manifest results")

    for entry in results:
        artifact = confined(run, entry.get("artifact", ""))
        if artifact is None or not artifact.is_file():
            errors.append(f"{entry.get('scenario')}: artifact missing or outside bundle")
        elif sha256(artifact) != entry.get("artifact_sha256"):
            errors.append(f"{entry.get('scenario')}: artifact hash mismatch")

    for name in observation_files:
        obs = json.loads((run / name).read_text(encoding="utf-8"))
        for err in validator.iter_errors(obs):
            errors.append(f"{name}: schema: {err.message} at /{'/'.join(map(str, err.absolute_path))}")
        if not rfc3339(str(obs.get("observed_at", ""))):
            errors.append(f"{name}: observed_at is not RFC 3339 date-time")
        if obs.get("assessment_id") != manifest.get("assessment_id"):
            errors.append(f"{name}: assessment_id differs from manifest")
        for ref in obs.get("evidence", []):
            target = confined(run, str(ref.get("uri", "")))
            if target is None or not target.is_file():
                errors.append(f"{name}: evidence URI missing or outside bundle: {ref.get('uri')}")
            elif sha256(target) != ref.get("sha256"):
                errors.append(f"{name}: evidence hash mismatch for {ref.get('uri')}")

    sums: dict[str, str] = {}
    for line in (run / "SHA256SUMS").read_text(encoding="utf-8").splitlines():
        digest, _, rel = line.partition("  ")
        sums[rel] = digest
    on_disk = sorted(p.relative_to(run).as_posix() for p in run.rglob("*") if p.is_file() and p.name != "SHA256SUMS")
    if sorted(sums) != on_disk:
        errors.append("SHA256SUMS does not list exactly the files in the bundle")
    for rel, digest in sums.items():
        target = confined(run, rel)
        if target is None or not target.is_file() or sha256(target) != digest:
            errors.append(f"SHA256SUMS mismatch: {rel}")

    for path in run.rglob("*"):
        if path.is_file() and PRIVATE_KEY.search(path.read_bytes()):
            errors.append(f"{path.relative_to(run)}: private key material present")
    return errors


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: validate_evidence.py RUN_DIR", file=sys.stderr)
        return 2
    run = Path(sys.argv[1]).resolve()
    if not (run / "manifest.json").is_file():
        print(f"{run}: manifest.json not found", file=sys.stderr)
        return 2
    errors = validate(run)
    if errors:
        print(f"evidence validation failed ({len(errors)} errors):", file=sys.stderr)
        for e in errors:
            print(f"- {e}", file=sys.stderr)
        return 1
    count = len(list((run / "observations").glob("*.json")))
    print(f"evidence validation passed: {count} observations, schema {SCHEMA.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

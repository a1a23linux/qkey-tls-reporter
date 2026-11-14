#!/usr/bin/env python3
"""Check the selected public source tree for accidental private material."""
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
SKIP = {'.git', '.venv', '.cache', '__pycache__', 'bin', 'dist', 'results'}
ALLOWED = {'.go', '.py', '.md', '.txt', '.json', '.yml', '.yaml', '.mod', '.sum', '.in'}
ALLOWED_NAMES = {'LICENSE', 'GO-LICENSE', 'NOTICE', 'Makefile', '.gitignore'}
PATTERNS = {
    'private-key-pem': re.compile(rb'-{5}BEGIN [A-Z0-9 ]*PRIVATE KEY-{5}'),
    'github-token': re.compile(rb'gh[pousr]_[A-Za-z0-9]{36,}'),
    'aws-access-id': re.compile(rb'AKIA[A-Z0-9]{16}'),
    'private-project-path': re.compile(rb'/(?:home/qkey|opt/projects)/'),
    'private-hostname': re.compile(rb'agent1\.localdomain'),
    'private-network-address': re.compile(rb'(?<![0-9])(?:10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|192\.168\.[0-9]{1,3}\.[0-9]{1,3}|172\.(?:1[6-9]|2[0-9]|3[01])\.[0-9]{1,3}\.[0-9]{1,3})(?![0-9])'),
}


def public_files(root=ROOT):
    for path in sorted(root.rglob('*')):
        relative = path.relative_to(root)
        if any(part in SKIP for part in relative.parts):
            continue
        if path.is_symlink():
            raise ValueError(f'Symlink is not allowed in release: {relative}')
        if path.is_file():
            yield path


def check(root=ROOT):
    errors = []
    for path in public_files(root):
        relative = path.relative_to(root)
        if path.suffix not in ALLOWED and path.name not in ALLOWED_NAMES:
            errors.append(f'{relative}: unexpected source file type')
        content = path.read_bytes()
        if len(content) > 1024 * 1024:
            errors.append(f'{relative}: source file exceeds 1 MiB')
        # The checker declares the patterns it checks; do not flag those declarations.
        if path.resolve() == pathlib.Path(__file__).resolve():
            continue
        for name, pattern in PATTERNS.items():
            if pattern.search(content):
                errors.append(f'{relative}: {name}')
    return errors


if __name__ == '__main__':
    errors = check()
    if errors:
        print('\n'.join(errors), file=sys.stderr)
        raise SystemExit(1)
    print(f'Public source check passed: {len(list(public_files()))} files; pattern check is not a guarantee against arbitrary secrets.')

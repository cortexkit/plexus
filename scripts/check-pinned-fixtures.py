#!/usr/bin/env python3
"""Verify the vendored SHA256SUMS corpora without building their generators."""
import hashlib
from pathlib import Path
import re
import sys

CORPORA = (
    'flow-audience-v1',
    'permissions-v1',
    'entorhinal-roles/role-claims-v1',
    'cingulate-consent-requester/vectors/consent-requester-v1',
    'cingulate-consent-requester/vectors/consent-requester-v2',
    'cingulate-consent-requester/vectors/consent-late-answer-v1',
)


def verify_manifest(manifest):
    checked = 0
    for line in manifest.read_text().splitlines():
        match = re.fullmatch(r'([0-9a-f]{64}) [ *](.+)', line)
        if not match:
            raise ValueError(f'{manifest}: malformed checksum line')
        expected, name = match.groups()
        # The upstream permissions manifest includes aggregator vectors that
        # Plexus does not vendor. SOURCE.md specifies this exact subset.
        if manifest.parent.name == 'permissions-v1' and not name.startswith(('provider-', 'README')):
            continue
        path = manifest.parent / name
        if not path.resolve().is_relative_to(manifest.parent.resolve()):
            raise ValueError(f'{manifest}: checksum path escapes corpus: {name}')
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError(f'{path}: pinned SHA256SUMS mismatch')
        checked += 1
    if not checked:
        raise ValueError(f'{manifest}: no copied fixture checksums')
    return checked


def main():
    root = Path(__file__).resolve().parents[1] / 'crates/plexus-module/tests/fixtures'
    # Require the known manifests even if a corpus is accidentally removed,
    # and pick up new checksum corpora without changing the gate.
    manifests = {root / corpus / 'SHA256SUMS' for corpus in CORPORA}
    manifests.update(root.rglob('SHA256SUMS'))
    try:
        checked = sum(verify_manifest(path) for path in sorted(manifests))
    except (OSError, ValueError) as error:
        sys.exit(f'pinned fixtures: {error}')
    print(f'pinned fixtures: {checked} files in {len(manifests)} checksum manifests verified')


if __name__ == '__main__':
    main()

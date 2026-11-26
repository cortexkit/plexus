"""Package and verify Plexus's installer assets on the release runners."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
from zipfile import ZIP_DEFLATED, BadZipFile, ZipFile


BINARIES = ("ck-plexus", "ck-plexus-admin")
TARGETS = ("darwin-arm64", "darwin-x64", "linux-x64", "linux-arm64", "windows-x64")
CATALOG = "ck-plexus-catalog"
TRIPLET = r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"


def archive_path(directory, target, name):
    return directory / f"{name}-{target}.zip"


def member_name(target, binary):
    return f"{binary}.exe" if target.startswith("windows-") else binary


def pack(args):
    name = member_name(args.target, args.binary)
    args.directory.mkdir(parents=True, exist_ok=True)
    with ZipFile(archive_path(args.directory, args.target, args.binary), "x", ZIP_DEFLATED) as archive:
        archive.write(args.source / name, arcname=name)


def checksum(archive):
    digest = hashlib.sha256()
    with archive.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return f"{digest.hexdigest()}  {archive.name}\n".encode("ascii")


def archive_member(archive, target, binary):
    expected = member_name(target, binary)
    entries = archive.infolist()
    if len(entries) != 1 or entries[0].filename != expected or not entries[0].file_size:
        raise ValueError(f"{archive.filename}: expected only a nonempty {expected} at the ZIP root")
    if not target.startswith("windows-"):
        mode = entries[0].external_attr >> 16
        if not stat.S_ISREG(mode) or not mode & stat.S_IXUSR:
            raise ValueError(f"{archive.filename}: {expected} must be a regular executable")
    return entries[0]


def probe(path, flag):
    return subprocess.check_output([str(path), flag], text=True, timeout=15).strip()


def verify_target(args):
    validate_revision(args.revision)
    for binary in BINARIES:
        path = archive_path(args.directory, args.target, binary)
        # Test the extracted release bytes, including the effect of hardened
        # runtime on macOS, not just the pre-signing build in target/release.
        with ZipFile(path) as archive, tempfile.TemporaryDirectory() as scratch:
            member = archive_member(archive, args.target, binary)
            executable = Path(scratch) / f"ckdev-{member.filename.removeprefix('ck-')}"
            with archive.open(member) as source, executable.open("xb") as destination:
                shutil.copyfileobj(source, destination)
            executable.chmod(0o755)
            version = probe(executable, "--version")
            reported = re.fullmatch(rf"{binary} (\S+) \(commit {args.revision}, lock [0-9a-f]{{64}}\)", version)
            if not reported or reported[1] != args.version:
                raise ValueError(f"{path}: unexpected --version for {args.version} at {args.revision}: {version!r}")
            if binary == "ck-plexus":
                manifest = json.loads(probe(executable, "--manifest"))
                revision = manifest["provenance"]["build_git_sha"]
                if revision != args.revision:
                    raise ValueError(f"{path}: --manifest reports {revision!r}, expected {args.revision}")
                if args.target.startswith("darwin-"):
                    smoke = probe(executable, "--smoke-probe")
                    if smoke != "ck-plexus smoke-probe ok: sandbox guest returned 42":
                        raise ValueError(f"{path}: unexpected --smoke-probe result: {smoke!r}")
                    print(f"{path.name}: {smoke}")
            print(f"{path.name}: {version}")
        path.with_suffix(".zip.sha256").write_bytes(checksum(path))


def validate_revision(revision):
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("expected a full 40-character Git commit SHA")


def core_floor(dry_run):
    floor = os.environ.get("PLEXUS_REQUIRES_CORE", "")
    if not floor and dry_run:
        return None
    if not re.fullmatch(TRIPLET, floor):
        raise ValueError("PLEXUS_REQUIRES_CORE must be set to the confirmed MAJOR.MINOR.PATCH floor before publishing")
    return floor


def assemble_catalog(output, revision, targets):
    # Read the Git tree and blobs, not the checkout, so no local edits or
    # generated files can enter the reviewed catalog.
    tree = subprocess.check_output(["git", "ls-tree", "-z", f"{revision}:catalog"])
    entries = []
    for entry in tree.split(b"\0"):
        if not entry:
            continue
        metadata, name = entry.split(b"\t", 1)
        if not name.endswith(b".jsonc"):
            continue
        mode, kind, blob = metadata.split()
        if mode not in (b"100644", b"100755") or kind != b"blob" or b"\\" in name:
            raise ValueError(f"catalog/{name!r}: expected a regular manifest with a ZIP root filename")
        entries.append((name.decode("utf-8"), blob.decode("ascii")))
    if not entries:
        raise ValueError(f"{revision}:catalog contains no reviewed JSONC manifests")

    # The release index requires a target in each asset name. Write the ZIP
    # once so every target gets the same bytes, including the ZIP metadata.
    original, *copies = [archive_path(output, target, CATALOG) for target in targets]
    with ZipFile(original, "x", ZIP_DEFLATED) as archive:
        for name, blob in entries:
            content = subprocess.check_output(["git", "cat-file", "blob", blob])
            if not content:
                raise ValueError(f"catalog/{name}: manifest is empty")
            archive.writestr(name, content)
    with ZipFile(original) as archive:
        if archive.testzip() is not None:
            raise ValueError(f"{original}: ZIP integrity check failed")

    sidecar = checksum(original)
    original.with_suffix(".zip.sha256").write_bytes(sidecar)
    for path in copies:
        shutil.copyfile(original, path)
        copy_checksum = checksum(path)
        if copy_checksum.split()[0] != sidecar.split()[0]:
            raise ValueError(f"{path}: catalog ZIP differs from {original.name}")
        path.with_suffix(".zip.sha256").write_bytes(copy_checksum)


def assemble(args):
    validate_revision(args.revision)
    floor = core_floor(args.dry_run)
    archives = [archive_path(args.directory, target, binary) for target in TARGETS for binary in BINARIES]
    files = {path.name for path in archives} | {f"{path.name}.sha256" for path in archives}
    actual = {path.name for path in args.directory.iterdir()}
    if actual != files:
        raise ValueError(f"wrong asset inventory: missing {sorted(files - actual)}; unexpected {sorted(actual - files)}")
    args.output.mkdir(parents=True)
    publish_targets = [target for target in TARGETS if target != "windows-x64" or args.dry_run or args.publish_windows]
    for target in TARGETS:
        for binary in BINARIES:
            path = archive_path(args.directory, target, binary)
            sidecar = path.with_suffix(".zip.sha256")
            if sidecar.read_bytes() != checksum(path):
                raise ValueError(f"{sidecar}: checksum does not match the ZIP")
            with ZipFile(path) as archive:
                archive_member(archive, target, binary)
                if archive.testzip() is not None:
                    raise ValueError(f"{path}: ZIP integrity check failed")
            # All targets are verified even when Windows is not yet released.
            if target in publish_targets:
                shutil.copyfile(path, args.output / path.name)
                shutil.copyfile(sidecar, args.output / sidecar.name)

    assemble_catalog(args.output, args.revision, publish_targets)
    manifest: dict[str, object] = {"binaries": {binary: {"reports": args.revision} for binary in BINARIES}}
    if floor is not None:
        manifest["requires_core"] = floor
    (args.output / "release-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"Verified {len(archives)} binary ZIPs and sidecars; prepared {len(list(args.output.iterdir()))} files in {args.output}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    packaging = commands.add_parser("pack")
    packaging.add_argument("source", type=Path)
    packaging.add_argument("directory", type=Path)
    packaging.add_argument("target", choices=TARGETS)
    packaging.add_argument("binary", choices=BINARIES)
    verification = commands.add_parser("verify-target")
    verification.add_argument("directory", type=Path)
    verification.add_argument("target", choices=TARGETS)
    verification.add_argument("version")
    verification.add_argument("revision")
    assembly = commands.add_parser("assemble")
    assembly.add_argument("directory", type=Path)
    assembly.add_argument("output", type=Path)
    assembly.add_argument("revision")
    assembly.add_argument("--dry-run", action="store_true")
    assembly.add_argument("--publish-windows", action="store_true")
    commands.add_parser("check-floor")
    args = parser.parse_args()
    try:
        if args.command == "pack":
            pack(args)
        elif args.command == "verify-target":
            verify_target(args)
        elif args.command == "assemble":
            assemble(args)
        elif args.command == "check-floor":
            print(f"requires_core: {core_floor(dry_run=False)}")
    except (BadZipFile, KeyError, OSError, TypeError, ValueError, subprocess.SubprocessError) as error:
        parser.exit(1, f"release assets: {error}\n")


if __name__ == "__main__":
    main()

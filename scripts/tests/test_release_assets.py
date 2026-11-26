"""Exercise the release-asset CLI with synthetic binaries and a reviewed catalog."""

import hashlib
import json
import sys
from zipfile import ZipFile

from test_scripts import SCRIPTS, Scratch, git, run, write_executable


ASSETS = SCRIPTS / "release" / "assets.py"
BINARIES = ("ck-plexus", "ck-plexus-admin")
TARGETS = ("darwin-arm64", "darwin-x64", "linux-x64", "linux-arm64", "windows-x64")
VERSION = "0.1.0"
REVISION = "a" * 40
DIGEST = "b" * 64


class ReleaseAssetsTests(Scratch):
    def invoke(self, *args, floor=""):
        return run([sys.executable, ASSETS, *args], cwd=self.tmp, env={"PLEXUS_REQUIRES_CORE": floor})

    def git(self, *args):
        result = git(*args, cwd=self.tmp)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.strip()

    def assert_checksum(self, path):
        archive = path.read_bytes()
        expected = f"{hashlib.sha256(archive).hexdigest()}  {path.name}\n"
        self.assertEqual(path.with_suffix(".zip.sha256").read_text(), expected)
        return archive

    def test_assembly_copies_only_reviewed_catalog_bytes_to_each_included_target(self):
        self.git("init", "-q")
        catalog = self.tmp / "catalog"
        catalog.mkdir()
        manifests = {"first.jsonc": b"// reviewed\n{}\n", "second.jsonc": b"{\n}\n"}
        for name, contents in manifests.items():
            (catalog / name).write_bytes(contents)
        (catalog / "README.md").write_text("Not a manifest")
        self.git("add", "catalog")
        self.git("-c", "user.name=Release Test", "-c", "user.email=test@example.invalid", "commit", "-qm", "catalog")
        revision = self.git("rev-parse", "HEAD")
        (catalog / "first.jsonc").write_text("not committed")
        (catalog / "untracked.jsonc").write_text("not committed")

        built = self.tmp / "built"
        built.mkdir()
        for target in TARGETS:
            for binary in BINARIES:
                member = binary + (".exe" if target == "windows-x64" else "")
                executable = write_executable(self.tmp / member, "placeholder")
                path = built / f"{binary}-{target}.zip"
                with ZipFile(path, "w") as archive:
                    archive.write(executable, arcname=member)
                digest = hashlib.sha256(path.read_bytes()).hexdigest()
                path.with_suffix(".zip.sha256").write_text(f"{digest}  {path.name}\n")

        cases = [
            ("publish", (), "1.2.3", TARGETS[:-1]),
            ("publish-windows", ("--publish-windows",), "1.2.3", TARGETS),
            ("rehearse", ("--dry-run",), "", TARGETS),
        ]
        for name, flags, floor, targets in cases:
            with self.subTest(name=name):
                output = self.tmp / name
                result = self.invoke("assemble", built, output, revision, *flags, floor=floor)
                self.assertEqual(result.returncode, 0, result.stderr)
                expected = {"release-manifest.json"}
                copies = []
                for target in targets:
                    for asset in (*BINARIES, "ck-plexus-catalog"):
                        expected.update([f"{asset}-{target}.zip", f"{asset}-{target}.zip.sha256"])
                    archive = output / f"ck-plexus-catalog-{target}.zip"
                    copies.append(self.assert_checksum(archive))
                    with ZipFile(archive) as zip_file:
                        self.assertCountEqual(zip_file.namelist(), manifests)
                        self.assertEqual({name: zip_file.read(name) for name in zip_file.namelist()}, manifests)
                self.assertTrue(all(data == copies[0] for data in copies))
                self.assertEqual({path.name for path in output.iterdir()}, expected)
                manifest = {"binaries": {binary: {"reports": revision} for binary in BINARIES}}
                if floor:
                    manifest["requires_core"] = floor
                self.assertEqual(json.loads((output / "release-manifest.json").read_text()), manifest)

    def test_tag_requires_a_confirmed_core_floor(self):
        for floor in ("", "01.2.3", "1.2", "v1.2.3"):
            with self.subTest(floor=floor):
                result = self.invoke("check-floor", floor=floor)
                self.assertEqual(result.returncode, 1)
                self.assertIn("PLEXUS_REQUIRES_CORE must be set", result.stderr)
        result = self.invoke("check-floor", floor="1.2.3")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "requires_core: 1.2.3")

    def verify_archives(self, target, *, result=42, admin_version=VERSION):
        output = self.tmp / "assets"
        for binary in BINARIES:
            version = VERSION if binary == "ck-plexus" else admin_version
            smoke = f'echo "ck-plexus smoke-probe ok: sandbox guest returned {result}"'
            if binary == "ck-plexus-admin" or not target.startswith("darwin-"):
                smoke = "exit 2"
            write_executable(self.tmp / binary, f"""
                #!/bin/sh
                test "${{0##*/}}" = 'ckdev-{binary.removeprefix('ck-')}' || exit 2
                case "$1" in
                    --version) echo '{binary} {version} (commit {REVISION}, lock {DIGEST})' ;;
                    --manifest) echo '{{"provenance":{{"build_git_sha":"{REVISION}"}}}}' ;;
                    --smoke-probe) {smoke} ;;
                    *) exit 2 ;;
                esac
            """)
            packed = self.invoke("pack", self.tmp, output, target, binary)
            self.assertEqual(packed.returncode, 0, packed.stderr)
            (self.tmp / binary).unlink()
        return self.invoke("verify-target", output, target, VERSION, REVISION), output

    def test_darwin_probes_extracted_module_and_requires_guest_result(self):
        verified, output = self.verify_archives("darwin-arm64", result=41)
        self.assertEqual(verified.returncode, 1)
        self.assertIn("unexpected --smoke-probe result", verified.stderr)
        self.assertFalse(list(output.glob("*.sha256")))

    def test_darwin_checksums_both_final_archives_after_successful_probes(self):
        verified, output = self.verify_archives("darwin-x64")
        self.assertEqual(verified.returncode, 0, verified.stderr)
        self.assertIn("sandbox guest returned 42", verified.stdout)
        for binary in BINARIES:
            self.assert_checksum(output / f"{binary}-darwin-x64.zip")

    def test_linux_requires_the_admin_crate_version_without_running_the_smoke_probe(self):
        verified, output = self.verify_archives("linux-x64", admin_version="9.9.9")
        self.assertEqual(verified.returncode, 1)
        self.assertIn("ck-plexus-admin-linux-x64.zip: unexpected --version", verified.stderr)
        self.assert_checksum(output / "ck-plexus-linux-x64.zip")
        self.assertFalse((output / "ck-plexus-admin-linux-x64.zip.sha256").exists())

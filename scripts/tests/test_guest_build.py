"""Exercise the offline guest rebuild plumbing without a compiler or SDK download."""
import json
import shutil
import tarfile

from test_scripts import SCRIPTS, SYSTEM_PATH, Scratch, run, write_executable


class GuestBuildTests(Scratch):
    def test_check_compares_rebuilt_bytes_and_preserves_the_embedded_asset(self):
        root = self.tmp / 'source with spaces'
        script = root / 'scripts/build-probe-guest.sh'
        script.parent.mkdir(parents=True)
        shutil.copy2(SCRIPTS / 'build-probe-guest.sh', script)
        guest = root / 'crates/plexus-probe/guest'
        guest.mkdir(parents=True)
        target = self.tmp / 'external target'
        artifact = target / 'wasm32-wasip1/release/plexus-probe-guest.wasm'
        artifact.parent.mkdir(parents=True)
        asset = root / 'crates/plexus-probe/assets/plexus-probe-guest.wasm'
        asset.parent.mkdir()
        asset.write_bytes(b'expected wasm')
        artifact.write_bytes(asset.read_bytes())
        sdk = self.tmp / 'sdk'
        write_executable(sdk / 'bin/clang', '#!/bin/sh\nexit 0\n')
        (sdk / 'share/wasi-sysroot').mkdir(parents=True)
        archive = self.tmp / 'sdk.tar.gz'
        with tarfile.open(archive, 'w:gz') as output:
            output.add(sdk, arcname='sdk')
        sysroot = self.tmp / 'sysroot'
        (sysroot / 'lib/rustlib/wasm32-wasip1').mkdir(parents=True)
        tools = self.tmp / 'bin'
        write_executable(tools / 'uname', '#!/bin/sh\ncase "$1" in -s) echo Linux;; -m) echo x86_64;; esac\n')
        write_executable(tools / 'rustc', f'#!/bin/sh\ncase "$1" in --version) echo "rustc 1.99.0 (b940084d7 2026-09-28)";; --print) echo "{sysroot}";; esac\n')
        write_executable(tools / 'sha256sum', '#!/bin/sh\necho "c6c38aab56e5de88adf6c1ebc9c3ae8da72f88ec2b656fb024eda8d4167a0bc5  archive"\n')
        capture = self.tmp / 'flags.json'
        python = shutil.which('python3', path=SYSTEM_PATH)
        write_executable(tools / 'cargo', f'''#!{python}
import json, os, shlex, sys
if sys.argv[1] == 'metadata':
    print(json.dumps({{'target_directory': {str(target)!r}}}))
else:
    assert os.environ['RUSTUP_TOOLCHAIN'] == '1.99.0'
    flags = os.environ['CARGO_ENCODED_RUSTFLAGS'].split(chr(31))
    cflags = shlex.split(os.environ['CFLAGS_wasm32_wasip1'])
    assert os.environ['CC_SHELL_ESCAPED_FLAGS'] == '1'
    with open({str(capture)!r}, 'w') as output:
        json.dump([flags, cflags], output)
''')
        env = {'PATH': f'{tools}:{SYSTEM_PATH}', 'CARGO_HOME': str(self.tmp / 'cargo home'),
               'WASI_SDK_ARCHIVE': str(archive)}
        passed = run(['bash', script, '--check'], env=env)
        self.assertEqual(passed.returncode, 0, passed.stdout + passed.stderr)
        flags, cflags = json.loads(capture.read_text())
        self.assertIn(f'--remap-path-prefix={root}=/plexus', flags)
        self.assertIn(f'-ffile-prefix-map={root}=/plexus', cflags)
        artifact.write_bytes(b'changed wasm')
        failed = run(['bash', script, '--check'], env=env)
        self.assertNotEqual(failed.returncode, 0)
        self.assertIn('differs', failed.stderr)
        self.assertEqual(asset.read_bytes(), b'expected wasm')
        archive.write_bytes(b'invalid replacement archive')
        invalid = run(['bash', script, '--check'], env=env)
        self.assertNotEqual(invalid.returncode, 0, 'an explicit archive must override a cached one')

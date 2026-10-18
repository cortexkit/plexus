"""The shared CI installer must verify downloaded bytes before installation."""
import hashlib
import io
import tarfile

from test_scripts import SCRIPTS, SYSTEM_PATH, Scratch, run, write_executable


class NatsInstallerTests(Scratch):
    def test_archive_checksum_is_checked_before_installation(self):
        archive = self.tmp / 'nats.tar.gz'
        payload = b'#!/bin/sh\necho fixture\n'
        with tarfile.open(archive, 'w:gz') as output:
            entry = tarfile.TarInfo('nats-server-v2.15.0-linux-amd64/nats-server')
            entry.size, entry.mode = len(payload), 0o755
            output.addfile(entry, io.BytesIO(payload))
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        tools = self.tmp / 'bin'
        calls = self.tmp / 'installation'
        write_executable(tools / 'uname', '#!/bin/sh\ncase "$1" in -s) echo Linux;; -m) echo x86_64;; esac\n')
        write_executable(tools / 'curl', '''#!/bin/sh
while [ "$#" -gt 0 ]; do
  if [ "$1" = --output ]; then cp "$NATS_FIXTURE" "$2"; exit 0; fi
  shift
done
exit 99
''')
        write_executable(tools / 'sudo', '#!/bin/sh\nprintf "%s\\n" "$*" > "$NATS_CALLS"\n')
        write_executable(tools / 'nats-server', '#!/bin/sh\necho "nats-server: v2.15.0"\n')
        env = {'PATH': f'{tools}:{SYSTEM_PATH}', 'NATS_SERVER_VERSION': '2.15.0',
               'NATS_SERVER_LINUX_AMD64_SHA256': digest, 'NATS_FIXTURE': str(archive),
               'NATS_CALLS': str(calls), 'TMPDIR': str(self.tmp)}
        valid = run(['bash', SCRIPTS / 'install-nats-server.sh'], env=env)
        self.assertEqual(valid.returncode, 0, valid.stdout + valid.stderr)
        self.assertIn('/usr/local/bin/nats-server', calls.read_text())
        calls.unlink()
        invalid = run(['bash', SCRIPTS / 'install-nats-server.sh'], env={**env, 'NATS_SERVER_LINUX_AMD64_SHA256': '0' * 64})
        self.assertNotEqual(invalid.returncode, 0, 'mismatched archive digest must refuse installation')
        self.assertIn('checksum verification failed', invalid.stderr)
        self.assertFalse(calls.exists(), 'checksum refusal must precede sudo install')

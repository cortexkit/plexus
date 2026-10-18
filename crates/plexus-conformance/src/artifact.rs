//! Private scratch directories and atomic owner-only artifact publication.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

pub(crate) struct Scratch(PathBuf);

impl Scratch {
    pub(crate) fn directory_in(parent: &Path) -> io::Result<Self> {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        for _ in 0..32 {
            let name = format!(
                ".plexus-{}-{}-{}",
                std::process::id(),
                crate::evidence::now_ms(),
                SEQ.fetch_add(1, Ordering::Relaxed)
            );
            let path = parent.join(name);
            let mut builder = fs::DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            match builder.create(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "scratch directory collision limit",
        ))
    }

    pub(crate) fn database() -> io::Result<Self> {
        let mut directory = Self::directory_in(&std::env::temp_dir())?;
        directory.0.push("store.sqlite");
        Ok(directory)
    }
}

impl std::ops::Deref for Scratch {
    type Target = Path;
    fn deref(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let directory = if self
            .0
            .file_name()
            .is_some_and(|name| name == "store.sqlite")
        {
            self.0.parent().unwrap()
        } else {
            &self.0
        };
        let _ = fs::remove_dir_all(directory);
    }
}

/// Publish a complete file without following a destination symlink or exposing
/// partial content. A private sibling directory protects the temporary name.
pub fn write_owner_only(path: &Path, bytes: &[u8]) -> io::Result<()> {
    write_with(path, |file| file.write_all(bytes))
}

fn write_with(path: &Path, write: impl FnOnce(&mut File) -> io::Result<()>) -> io::Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let directory = Scratch::directory_in(parent)?;
    let temporary = directory.join("artifact");
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temporary)?;
    write(&mut file)?;
    file.sync_all()?;
    fs::rename(&temporary, path)?;
    #[cfg(unix)]
    File::open(parent)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_writes_preserve_the_previous_artifact() {
        let dir = Scratch::directory_in(&std::env::temp_dir()).unwrap();
        let path = dir.join("evidence.json");
        write_owner_only(&path, b"previous").unwrap();
        assert!(write_with(&path, |file| {
            file.write_all(b"partial")?;
            Err(io::Error::other("injected write failure"))
        })
        .is_err());
        assert_eq!(fs::read(path).unwrap(), b"previous");
    }

    #[cfg(unix)]
    #[test]
    fn publication_replaces_symlinks_and_detaches_existing_readers() {
        use std::io::Read;
        use std::os::unix::fs::{symlink, PermissionsExt};
        let dir = Scratch::directory_in(&std::env::temp_dir()).unwrap();
        let victim = dir.join("victim");
        fs::write(&victim, b"untouched").unwrap();
        let path = dir.join("output");
        symlink(&victim, &path).unwrap();
        write_owner_only(&path, b"first").unwrap();
        assert_eq!(fs::read(&victim).unwrap(), b"untouched");
        let mut earlier = File::open(&path).unwrap();
        write_owner_only(&path, b"second").unwrap();
        let mut old = String::new();
        earlier.read_to_string(&mut old).unwrap();
        assert_eq!(old, "first");
        assert_eq!(fs::read(&path).unwrap(), b"second");
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn scratch_creation_failure_is_an_error() {
        let dir = Scratch::directory_in(&std::env::temp_dir()).unwrap();
        assert!(Scratch::directory_in(&dir.join("absent")).is_err());
    }
}

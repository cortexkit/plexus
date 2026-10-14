//! Scratch filesystem paths for tests and the conformance harness.
//!
//! Scratch data this workspace writes while testing goes under ONE directory,
//! `$TMPDIR/plexus-tests`, and every scratch path is handed out by this module
//! rather than assembled at the call site.
//!
//! Two reasons the shape matters.
//!
//! The shared temp directory is walked by other tools on the same host. Test
//! stores written straight into it accumulate tens of thousands of entries
//! (three files per SQLite store, `.db`, `.db-wal` and `.db-shm`, each named
//! with the test process's pid), and a bare listing of such a directory can
//! take many minutes, which stalls unrelated programs that only want to read
//! it. One directory entry costs those readers nothing.
//!
//! Without a sweep, nothing removes the files. A clean run removes the `.db`
//! and leaves the write-ahead-log pair; a killed or timed-out run leaves all
//! three forever, and orphans from killed runs are the larger share. So a scratch path needs both
//! halves of the cleanup: [`Scratch`] removes its directory on drop for the
//! clean path, and [`sweep`] reclaims aged leftovers from runs that never got
//! to drop anything.

use std::fs;
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Once;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// The name every scratch entry starts with, and the only name the sweep will
/// remove.
///
/// The sweep is deliberately unable to touch anything that is not ours. A tool
/// that matches temp entries on a broad pattern can believe the hits are its
/// own and delete directories belonging to a different harness. Two
/// independent fences keep that from happening here: the sweep
/// reads only our own root, and inside it removes only entries whose name
/// starts with this literal.
const SCRATCH_PREFIX: &str = "plexus-";

/// How old an entry in the root must be before the sweep treats it as an
/// orphan.
///
/// This cannot be allowed to reap a suite that is still running. The full
/// workspace suite finishes in minutes, so an hour leaves more than an order of
/// magnitude of headroom, and [`last_touched`] additionally reads the timestamps
/// of the files INSIDE a candidate — an open SQLite store's `-wal` is touched on
/// every write, so a scratch directory that is genuinely in use keeps looking
/// young no matter how long the run lasts.
const ORPHAN_AGE: Duration = Duration::from_secs(60 * 60);

/// The single directory holding every scratch path this workspace creates.
pub fn root() -> PathBuf {
    std::env::temp_dir().join("plexus-tests")
}

/// Build the unique directory name for one scratch path.
///
/// The pid stays in the name, and stays the first numeric token, because a host
/// reaper tells a live scratch directory from an orphan by looking for a dead
/// pid there — and so does a human reading the listing. The clock reading and
/// the counter together keep two scratch paths apart even when they are
/// requested in the same clock tick, which happens on macOS because its clock
/// ticks in microseconds while creation is faster than that.
fn unique_name(label: &str) -> String {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos())
        .unwrap_or(0);
    format!(
        "{SCRATCH_PREFIX}{}-{}-{nanos}-{}",
        sanitize(label),
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    )
}

/// Reduce a caller's label to characters that are safe in one path component.
///
/// Labels are written by hand and interpolated from test names, so a separator
/// or a `..` in one would otherwise place a scratch path outside the root,
/// where neither the drop nor the sweep would ever find it.
fn sanitize(label: &str) -> String {
    let mapped: String = label
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || character == '-' || character == '_' {
                character
            } else {
                '-'
            }
        })
        .collect();
    if mapped.is_empty() {
        "scratch".to_string()
    } else {
        mapped
    }
}

/// A scratch path under [`root`], whose directory is removed when this value
/// drops.
///
/// Each one owns a directory of its own even when the caller only wanted a
/// single file. That is what makes the clean-path cleanup complete: a SQLite
/// store is three files, and removing the directory removes the write-ahead-log
/// pair that removing the `.db` by name leaves behind.
///
/// It dereferences to the path that was asked for, so a call site uses it
/// wherever it used to use the `PathBuf` it built by hand.
#[derive(Debug)]
pub struct Scratch {
    /// The directory this value owns and removes on drop.
    directory: PathBuf,
    /// What the caller asked for: the directory itself, or a file inside it.
    target: PathBuf,
}

impl Scratch {
    /// A fresh empty directory for a test that writes several files.
    pub fn directory(label: &str) -> Self {
        let directory = create_directory(label);
        Self {
            target: directory.clone(),
            directory,
        }
    }

    /// A path for a SQLite store, inside a fresh directory of its own.
    ///
    /// The file name is fixed because the containing directory already carries
    /// the label and the uniqueness.
    pub fn database(label: &str) -> Self {
        Self::file(label, "store.db")
    }

    /// A path for one named file, inside a fresh directory of its own.
    ///
    /// Callers that care about the extension — a `.jsonl` trace, a `.json`
    /// schema dump — name the file here and keep it.
    pub fn file(label: &str, file_name: &str) -> Self {
        let directory = create_directory(label);
        Self {
            target: directory.join(file_name),
            directory,
        }
    }

    /// The path that was asked for.
    pub fn path(&self) -> &Path {
        &self.target
    }

    /// The owned directory, which is the same as [`Scratch::path`] for
    /// [`Scratch::directory`] and its parent otherwise.
    pub fn owned_directory(&self) -> &Path {
        &self.directory
    }
}

impl Deref for Scratch {
    type Target = Path;

    fn deref(&self) -> &Path {
        &self.target
    }
}

impl AsRef<Path> for Scratch {
    fn as_ref(&self) -> &Path {
        &self.target
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        // A failure here is not worth failing a test over: the sweep in the
        // next run reclaims whatever this could not.
        let _ = fs::remove_dir_all(&self.directory);
    }
}

/// Create the root if needed, sweep it once per process, and make one fresh
/// scratch directory inside it.
fn validate_root(root: &Path) -> std::io::Result<()> {
    let metadata = fs::symlink_metadata(root)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(std::io::Error::other(
            "scratch root must be a real directory",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // The directory may be pre-created in shared /tmp. Its owner must be
        // this process's effective user before we create or remove any children.
        if metadata.uid() != rustix::process::geteuid().as_raw() {
            return Err(std::io::Error::other(
                "scratch root belongs to another user",
            ));
        }
    }
    Ok(())
}

fn prepare_root(root: &Path) -> std::io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    if let Err(error) = builder.create(root) {
        if error.kind() != std::io::ErrorKind::AlreadyExists {
            return Err(error);
        }
    }
    validate_root(root)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(root, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn create_directory(label: &str) -> PathBuf {
    prepare_root(&root()).expect("safe scratch root");
    sweep_once();
    let directory = root().join(unique_name(label));
    if let Err(error) = fs::create_dir_all(&directory) {
        panic!("create scratch directory {}: {error}", directory.display());
    }
    directory
}

/// Sweep the root once per process, before the first scratch path is handed
/// out.
///
/// Start of the run rather than end of it, and that placement is the point. The
/// entries that used to live forever came from runs that were killed or timed
/// out, and no exit hook, drop, or teardown runs in those. A sweep that happens
/// when the NEXT process asks for its first scratch path reclaims them whatever
/// killed the run that created them — including a run that failed, panicked, or
/// was cancelled.
fn sweep_once() {
    static SWEPT: Once = Once::new();
    SWEPT.call_once(|| {
        let root = root();
        prepare_root(&root).expect("safe scratch root");
        sweep(&root, SystemTime::now(), ORPHAN_AGE);
    });
}

/// Remove scratch entries in `root` last touched more than `max_age` before
/// `now`, and report how many were removed.
///
/// Reads `root` only, never the shared temp directory that contains it.
/// Enumerating that directory is the cost this whole module exists to avoid —
/// it is the operation that was taking minutes — so the sweep must never be the
/// thing that does it.
fn sweep(root: &Path, now: SystemTime, max_age: Duration) -> usize {
    if validate_root(root).is_err() {
        return 0;
    }
    let Ok(entries) = fs::read_dir(root) else {
        return 0;
    };
    let mut removed = 0;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if !name.starts_with(SCRATCH_PREFIX) {
            continue;
        }
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        // A symlink is left alone: removing one either deletes a link we did
        // not make or, worse, reaches outside the root we are allowed to touch.
        if file_type.is_symlink() {
            continue;
        }
        let path = entry.path();
        let Some(touched) = last_touched(&path) else {
            // No usable timestamp means no evidence of age, and the sweep only
            // removes on evidence.
            continue;
        };
        let aged = now
            .duration_since(touched)
            .map(|age| age > max_age)
            .unwrap_or(false);
        if !aged {
            continue;
        }
        let outcome = if file_type.is_dir() {
            fs::remove_dir_all(&path)
        } else {
            fs::remove_file(&path)
        };
        if outcome.is_ok() {
            removed += 1;
        }
    }
    removed
}

/// The most recent moment anything at `path` was written, including one level
/// of contents when it is a directory.
///
/// A directory's own timestamp only moves when an entry is added or removed, so
/// it says nothing about a store being written inside it. Reading the immediate
/// children is what keeps a long-running suite safe from the sweep: an open
/// SQLite store touches its `-wal` on every write, and there are only a handful
/// of files in a scratch directory to look at.
fn last_touched(path: &Path) -> Option<SystemTime> {
    let metadata = fs::symlink_metadata(path).ok()?;
    let mut newest = timestamp(&metadata);
    if metadata.is_dir() {
        if let Ok(children) = fs::read_dir(path) {
            for child in children.flatten() {
                let Ok(child_metadata) = fs::symlink_metadata(child.path()) else {
                    continue;
                };
                if let Some(child_touched) = timestamp(&child_metadata) {
                    newest = Some(match newest {
                        Some(current) => current.max(child_touched),
                        None => child_touched,
                    });
                }
            }
        }
    }
    newest
}

/// When a single entry was last written.
///
/// Modification time is the question being asked, and creation time is only a
/// fallback for filesystems that do not report one. Taking the later of the two
/// instead would make the sweep unable to see any entry whose modification time
/// is older than its creation time, which is the only shape a backdated entry
/// has — and that is the shape the age test has to be able to observe.
fn timestamp(metadata: &fs::Metadata) -> Option<SystemTime> {
    metadata.modified().ok().or_else(|| metadata.created().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn sweep_refuses_a_symlink_root_without_deleting_its_target() {
        let holder = isolated_root("root-link-holder");
        let victim = holder.join("victim");
        fs::create_dir(&victim).unwrap();
        let child = victim.join("plexus-core");
        fs::create_dir(&child).unwrap();
        fs::write(child.join("source.rs"), b"keep").unwrap();
        let link = holder.join("root-link");
        std::os::unix::fs::symlink(&victim, &link).unwrap();
        assert_eq!(
            sweep(&link, SystemTime::now() + ORPHAN_AGE * 2, ORPHAN_AGE),
            0,
            "a symlink root must never be swept"
        );
        assert!(
            child.join("source.rs").exists(),
            "symlink target must survive"
        );
    }

    /// A root of its own per test, so these never sweep the real one.
    fn isolated_root(name: &str) -> Scratch {
        Scratch::directory(name)
    }

    #[test]
    fn scratch_paths_live_under_one_root() {
        let scratch = Scratch::database("root-containment");
        assert_eq!(
            scratch.path().parent().and_then(Path::parent),
            Some(root().as_path()),
            "a database scratch path sits one directory below the root"
        );
        let directory = Scratch::directory("root-containment");
        assert_eq!(directory.path().parent(), Some(root().as_path()));
    }

    #[test]
    fn scratch_names_keep_the_pid_as_the_first_numeric_token() {
        let scratch = Scratch::directory("pid-token");
        let name = scratch
            .path()
            .file_name()
            .and_then(|name| name.to_str())
            .expect("scratch directory name");
        assert!(name.starts_with("plexus-pid-token-"), "unexpected: {name}");
        let first_number = name
            .split('-')
            .find(|token| token.chars().all(|c| c.is_ascii_digit()) && !token.is_empty())
            .expect("a numeric token");
        assert_eq!(
            first_number,
            std::process::id().to_string(),
            "the first numeric token is the pid a host reaper looks for"
        );
    }

    #[test]
    fn a_label_cannot_escape_the_root() {
        let scratch = Scratch::directory("../../escape/attempt");
        assert_eq!(
            scratch.path().parent(),
            Some(root().as_path()),
            "a label with separators still lands inside the root"
        );
    }

    #[test]
    fn dropping_a_scratch_removes_the_whole_directory_including_the_wal_pair() {
        let directory;
        let database;
        {
            let scratch = Scratch::database("drop-removes-all");
            database = scratch.path().to_path_buf();
            directory = scratch.owned_directory().to_path_buf();
            // The two files a clean run used to leave behind after removing
            // the .db by name.
            for suffix in ["-wal", "-shm"] {
                let mut sibling = database.clone().into_os_string();
                sibling.push(suffix);
                fs::write(PathBuf::from(sibling), b"x").expect("write sibling");
            }
            fs::write(&database, b"x").expect("write database");
            assert!(directory.exists());
        }
        assert!(
            !directory.exists(),
            "{} outlived its Scratch",
            directory.display()
        );
    }

    #[test]
    fn the_sweep_removes_aged_scratch_and_keeps_everything_else() {
        let harness = isolated_root("sweep-fence");
        let aged_directory = harness.join("plexus-aged-1234-1-0");
        fs::create_dir_all(&aged_directory).expect("aged directory");
        fs::write(aged_directory.join("store.db"), b"x").expect("aged store");
        let aged_file = harness.join("plexus-aged-file-1234-1-1");
        fs::write(&aged_file, b"x").expect("aged file");
        // Named by another harness. Inside our root only because this test put
        // it there, which is exactly the case the prefix fence has to refuse.
        let foreign = harness.join("someone-elses-cache");
        fs::create_dir_all(&foreign).expect("foreign directory");

        // Everything above was created just now. Reading the clock an hour
        // ahead is what makes them older than the threshold, and it beats a
        // zero threshold against the real clock, which depends on how coarsely
        // the filesystem rounds a timestamp it has only just written.
        let an_hour_from_now = SystemTime::now() + Duration::from_secs(60 * 60);
        let removed = sweep(&harness, an_hour_from_now, Duration::from_secs(60));

        assert_eq!(removed, 2, "both aged plexus entries were removed");
        assert!(!aged_directory.exists(), "aged directory survived");
        assert!(!aged_file.exists(), "aged file survived");
        assert!(foreign.exists(), "the sweep removed a foreign entry");
    }

    #[test]
    fn the_sweep_keeps_scratch_younger_than_the_threshold() {
        let harness = isolated_root("sweep-age");
        let young = harness.join("plexus-young-1234-1-0");
        fs::create_dir_all(&young).expect("young directory");

        let removed = sweep(&harness, SystemTime::now(), ORPHAN_AGE);

        assert_eq!(removed, 0, "a young scratch directory was swept");
        assert!(young.exists(), "a young scratch directory was removed");
    }

    /// Push one entry's modification time back, so the sweep sees the age an
    /// orphan from a killed run would really have.
    fn backdate(path: &Path, by: Duration) {
        let file = fs::File::open(path).expect("open for backdating");
        let when = SystemTime::now() - by;
        file.set_times(fs::FileTimes::new().set_modified(when))
            .expect("backdate");
    }

    /// The load-bearing property of the whole module: a run that was killed
    /// leaves its scratch behind, and the NEXT run is what reclaims it.
    ///
    /// Proved in a child process because the sweep happens once per process,
    /// before the first scratch path is handed out — by the time this test body
    /// runs, this process has already swept. The young directory planted
    /// alongside keeps the assertion from passing for a sweep that simply
    /// emptied the root.
    #[test]
    fn an_orphan_from_a_killed_run_is_reclaimed_when_the_next_run_starts() {
        const CHILD: &str = "PLEXUS_SCRATCH_SWEEP_CHILD";
        const TEST: &str = "test_scratch::tests::an_orphan_from_a_killed_run_is_reclaimed_when_the_next_run_starts";
        if std::env::var(CHILD).is_ok() {
            // Asking for a scratch path is what triggers the sweep.
            let _child_scratch = Scratch::directory("sweep-wiring");
            return;
        }

        let orphan = root().join(format!("{SCRATCH_PREFIX}orphan-{}-0-0", std::process::id()));
        fs::create_dir_all(&orphan).expect("plant orphan");
        let orphan_store = orphan.join("store.db");
        fs::write(&orphan_store, b"x").expect("plant orphan store");
        backdate(&orphan_store, ORPHAN_AGE * 3);
        backdate(&orphan, ORPHAN_AGE * 3);
        let live = root().join(format!("{SCRATCH_PREFIX}live-{}-0-0", std::process::id()));
        fs::create_dir_all(&live).expect("plant live scratch");

        let output = crate::test_http::bounded::child_output(
            std::process::Command::new(std::env::current_exe().expect("test binary"))
                .args(["--exact", TEST, "--nocapture"])
                .env(CHILD, "1"),
            Duration::from_secs(30),
            "scratch sweep test child",
        )
        .expect("run child");
        assert!(
            output.status.success(),
            "child run failed: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );

        let orphan_survived = orphan.exists();
        let live_survived = live.exists();
        let _ = fs::remove_dir_all(&orphan);
        let _ = fs::remove_dir_all(&live);
        assert!(!orphan_survived, "the aged orphan was not reclaimed");
        assert!(
            live_survived,
            "the sweep reclaimed a scratch that is in use"
        );
    }

    #[test]
    fn a_running_suites_scratch_is_young_because_of_the_file_inside_it() {
        // The directory's own timestamp stops moving once its entries exist,
        // which is what would otherwise let the sweep reap a store that is
        // still being written to.
        let harness = isolated_root("sweep-liveness");
        let live = harness.join("plexus-live-1234-1-0");
        fs::create_dir_all(&live).expect("live directory");
        let wal = live.join("store.db-wal");
        fs::write(&wal, b"x").expect("wal");

        let directory_only = timestamp(&fs::symlink_metadata(&live).expect("stat")).expect("time");
        let with_contents = last_touched(&live).expect("time");

        assert!(
            with_contents >= directory_only,
            "the contents timestamp is at least as recent as the directory's"
        );
        assert_eq!(
            sweep(&harness, SystemTime::now(), ORPHAN_AGE),
            0,
            "a store that is being written to was swept"
        );
    }

    #[test]
    fn the_sweep_leaves_symlinks_alone() {
        let harness = isolated_root("sweep-symlink");
        let outside = Scratch::directory("sweep-symlink-target");
        let link = harness.join("plexus-link-1234-1-0");
        std::os::unix::fs::symlink(outside.path(), &link).expect("symlink");

        let an_hour_from_now = SystemTime::now() + Duration::from_secs(60 * 60);
        let removed = sweep(&harness, an_hour_from_now, Duration::from_secs(60));

        assert_eq!(removed, 0, "the sweep followed or removed a symlink");
        assert!(
            fs::symlink_metadata(&link).is_ok(),
            "the symlink was removed"
        );
        assert!(outside.path().exists(), "the symlink's target was removed");
    }
}

//! Embed the dependency-set digest into the binary at compile time.
//!
//! Every existing way to identify a deployed CortexKit binary answers "which
//! SOURCE did this come from": inode identity, `LC_UUID`, the commit recorded
//! at build time. None of them answers "which DEPENDENCIES did it link", and
//! the two diverge whenever a build resolves against a lock that is not the
//! committed one.
//!
//! That gap is not closable by the operator who deploys the artifact, because
//! the build happened somewhere else. A deploy ritual can verify identity and
//! cannot verify provenance -- it can only trust that whoever built the binary
//! used the enforced path. Embedding the digest converts that trust into a
//! check: the artifact carries the answer, so anyone holding it can compare
//! against the lock in git without asking how it was built.
//!
//! Deliberately a digest of the lock FILE rather than a package list. The file
//! is what `--locked` enforces, so the value matches exactly what the flag
//! guarantees, and any difference at all -- a version move, an added
//! transitive dependency, a checksum change -- moves it.

use std::path::PathBuf;
use std::process::Command;

mod build_support;

fn main() {
    let workspace_lock = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../Cargo.lock")
        .canonicalize();

    // Declare the lock as an input so cargo recomputes the digest when it
    // moves. Without any `rerun-if-changed` directive cargo falls back to
    // re-running the script when files in THIS PACKAGE change, and the
    // workspace lock is not one of them -- so the dependency would rest on a
    // heuristic that does not name the file the value is about.
    //
    // Honest limit: an attempt to observe a stale digest by deleting this line
    // did NOT reproduce one, because other build inputs changed in the same
    // step and the script re-ran anyway. So this is stated as the reason the
    // directive belongs here, not as a failure mode that was measured.
    let digest = match &workspace_lock {
        Ok(path) => {
            println!("cargo:rerun-if-changed={}", path.display());
            std::fs::read(path).ok().map(|bytes| sha256_hex(&bytes))
        }
        Err(_) => None,
    };

    // "unavailable" rather than a placeholder digest: an absent answer must be
    // distinguishable from a real one. A zeroed or faked hash would render
    // "not computed" identically to "computed and equal to nothing", which is
    // the false-negative shape this marker exists to avoid.
    let digest = digest.unwrap_or_else(|| "unavailable".to_string());
    println!("cargo:rustc-env=PLEXUS_LOCK_DIGEST={digest}");

    // Re-run when HEAD moves, or the recorded commit goes stale.
    //
    // MEASURED, not theoretical: with only the lock declared as an input, a
    // binary built two commits after the marker shipped still reported the
    // OLD commit, because nothing cargo watches had changed. A provenance
    // marker that lies is worse than none, since it invites exactly the
    // comparison it will fail.
    //
    // HEAD covers checkouts and branch switches; the current branch's loose
    // ref covers commits on that branch, which is the case that bit. Packed
    // refs cover a branch whose loose ref is absent. Ask git for these paths:
    // in a linked worktree `.git` is a file, HEAD is worktree-specific, and
    // branch refs and packed-refs live in the common git directory.
    //
    // During a rebase or a detached-HEAD build the ref file may be absent, so
    // each path is only declared when it exists — a missing rerun trigger
    // degrades to the stale value this fixes, while a declared-but-absent path
    // would make cargo re-run the script on every single build.
    let reference = git_output(&["rev-parse", "--symbolic-full-name", "HEAD"])
        .filter(|reference| reference.starts_with("refs/"));
    for input in ["HEAD", "packed-refs"]
        .into_iter()
        .chain(reference.as_deref())
    {
        if let Some(path) = git_output(&["rev-parse", "--git-path", input]) {
            let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(path);
            if path.exists() {
                println!("cargo:rerun-if-changed={}", path.display());
            }
        }
    }

    // Watch compiled sources so edits refresh the binary's `-dirty` suffix.
    // Once a build script emits `rerun-if-changed`, Cargo reruns it only when
    // a listed path changes. Watching only the lockfile and Git refs could
    // rebuild edited source while retaining an earlier clean commit label.
    // Cargo scans watched directories recursively. Also watch the Git index:
    // staging or unstaging can change `git status` without editing source, and
    // the build script must recompute the dirty label in that case too.
    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    for input in ["crates", "Cargo.toml"] {
        if let Ok(path) = workspace.join(input).canonicalize() {
            println!("cargo:rerun-if-changed={}", path.display());
        }
    }
    if let Some(index) = git_output(&["rev-parse", "--git-path", "index"]) {
        let index = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(index);
        if index.exists() {
            println!("cargo:rerun-if-changed={}", index.display());
        }
    }

    // The binary embeds a Git commit for source identity and a separate
    // Cargo.lock digest for dependency identity. An uncommitted source edit
    // changes neither value, so add `-dirty` to the commit to avoid claiming
    // that the binary matches the committed source.
    //
    // Include untracked source files, but not unrelated docs or operator notes:
    // the dirty check must cover exactly the compiled inputs watched above.
    let dirty = compiled_inputs_dirty(&workspace);
    // Full 40-hex rather than an abbreviated form: the wire provenance
    // contract (subc-protocol `build_provenance`) validates canonical 40-hex,
    // and every downstream reader here resolves the value through git (which
    // accepts either) rather than comparing string lengths. An abbreviation
    // saves nothing and forks the fact into two spellings.
    let commit = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()
        .filter(|out| out.status.success())
        .and_then(|out| String::from_utf8(out.stdout).ok())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .map(|value| {
            if dirty {
                format!("{value}-dirty")
            } else {
                value
            }
        })
        .unwrap_or_else(|| "unavailable".to_string());
    println!("cargo:rustc-env=PLEXUS_BUILD_COMMIT={commit}");
}

pub(crate) fn compiled_inputs_dirty(workspace: &std::path::Path) -> bool {
    build_support::dirty_command(workspace)
        .output()
        .ok()
        .filter(|out| out.status.success())
        .map(|out| !out.stdout.is_empty())
        .unwrap_or(false)
}

fn git_output(args: &[&str]) -> Option<String> {
    Command::new("git")
        .args(args)
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .ok()
        .filter(|out| out.status.success())
        .and_then(|out| String::from_utf8(out.stdout).ok())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

/// Minimal SHA-256 so the build script pulls in no dependencies.
///
/// A build-dependency would be resolved by the same lock this digest is meant
/// to describe, which is a circularity worth avoiding for forty lines of
/// arithmetic.
fn sha256_hex(input: &[u8]) -> String {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut state: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    let mut message = input.to_vec();
    let bit_len = (input.len() as u64) * 8;
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in message.chunks(64) {
        let mut w = [0u32; 64];
        for (index, word) in w.iter_mut().enumerate().take(16) {
            let base = index * 4;
            *word = u32::from_be_bytes([
                chunk[base],
                chunk[base + 1],
                chunk[base + 2],
                chunk[base + 3],
            ]);
        }
        for index in 16..64 {
            let s0 = w[index - 15].rotate_right(7)
                ^ w[index - 15].rotate_right(18)
                ^ (w[index - 15] >> 3);
            let s1 = w[index - 2].rotate_right(17)
                ^ w[index - 2].rotate_right(19)
                ^ (w[index - 2] >> 10);
            w[index] = w[index - 16]
                .wrapping_add(s0)
                .wrapping_add(w[index - 7])
                .wrapping_add(s1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = state;
        for index in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[index])
                .wrapping_add(w[index]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        for (slot, value) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *slot = slot.wrapping_add(value);
        }
    }

    state.iter().map(|word| format!("{word:08x}")).collect()
}

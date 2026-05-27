//! Golden tests against canboat's `analyzer/tests/*.in` / `*.out`
//! files. Each case feeds an `.in` through the Rust `analyzer` binary
//! with the same flags canboat passes, then byte-diffs against the
//! corresponding `.out`.
//!
//! Test data is read straight from the sibling canboat checkout at
//! `../canboat/analyzer/tests/`. If that directory isn't present the
//! tests skip gracefully — they're not blockers for users building
//! canboat-rs in isolation.
//!
//! New cases are added by name. v0 covers the ones our decoder can
//! already render; the rest will be added (with documentation of
//! missing features) as their support lands.

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::io::Write;

/// Where the canboat C repo lives, relative to this crate.
fn canboat_tests_dir() -> Option<PathBuf> {
    let manifest: PathBuf = env!("CARGO_MANIFEST_DIR").into();
    let p = manifest
        .parent()?
        .parent()? // canboat-rs/
        .parent()? // ../  (github/)
        .join("canboat")
        .join("analyzer")
        .join("tests");
    if p.is_dir() {
        Some(p)
    } else {
        None
    }
}

fn analyzer_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_analyzer"))
}

/// Drive the analyzer binary on `<test_dir>/<in_name>` with `args`,
/// then byte-diff stdout against `<test_dir>/<expected_name>`.
fn run_case(in_name: &str, expected_name: &str, args: &[&str]) {
    let Some(dir) = canboat_tests_dir() else {
        eprintln!("skipping: canboat test directory not available");
        return;
    };
    let input = std::fs::read(dir.join(in_name)).expect("read .in");
    let expected = std::fs::read(dir.join(expected_name)).expect("read .out");

    let mut child = Command::new(analyzer_path())
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn analyzer");
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(&input)
        .expect("write stdin");
    let out = child.wait_with_output().expect("wait analyzer");
    assert!(
        out.status.success(),
        "analyzer exited with {:?}\nstderr: {}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    if out.stdout != expected {
        let actual = String::from_utf8_lossy(&out.stdout);
        let expected_str = String::from_utf8_lossy(&expected);
        panic!(
            "Golden mismatch for {in_name} → {expected_name}\n\
             --- expected ({} bytes) ---\n{}\n\
             --- actual ({} bytes) ---\n{}\n",
            expected.len(),
            expected_str,
            out.stdout.len(),
            actual,
        );
    }
}

#[test]
fn pgn_60928_json_nv() {
    // The simplest passing case: two PGN 60928 frames, JSON -nv.
    run_case("pgn-60928.in", "pgn-60928-nv.out", &["--json", "--nv"]);
}

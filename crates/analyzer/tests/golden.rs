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

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

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
    run_case_skipping(in_name, expected_name, args, &[]);
}

/// Same as [`run_case`] but allow specific line indices (0-based) to
/// differ. Used for canboat-reference outputs that contain
/// canboat-specific quirks (e.g. reading uninitialized memory past
/// the declared payload) we deliberately don't replicate.
fn run_case_skipping(in_name: &str, expected_name: &str, args: &[&str], skip_lines: &[usize]) {
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

    if skip_lines.is_empty() {
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
        return;
    }

    // Line-by-line compare with allowed skips.
    let actual_str = String::from_utf8(out.stdout).expect("utf-8 stdout");
    let expected_str = String::from_utf8(expected).expect("utf-8 expected");
    let actual_lines: Vec<&str> = actual_str.lines().collect();
    let expected_lines: Vec<&str> = expected_str.lines().collect();
    assert_eq!(
        actual_lines.len(),
        expected_lines.len(),
        "line count differs: actual={} expected={}",
        actual_lines.len(),
        expected_lines.len(),
    );
    for (i, (a, e)) in actual_lines.iter().zip(expected_lines.iter()).enumerate() {
        if skip_lines.contains(&i) {
            continue;
        }
        if a != e {
            panic!(
                "Golden mismatch at {in_name}:{i}\n--- expected ---\n{e}\n--- actual ---\n{a}\n",
            );
        }
    }
}

#[test]
fn pgn_60928_json_nv() {
    // The simplest passing case: two PGN 60928 frames, JSON -nv.
    run_case("pgn-60928.in", "pgn-60928-nv.out", &["--json", "--nv"]);
}

#[test]
fn pgn_126983_json_nv() {
    // Exercises ISO_NAME recursive decode, Reserved-as-hex, and
    // PartOfPrimaryKey "key":true annotation.
    run_case("pgn-126983.in", "pgn-126983-nv.out", &["--json", "--nv"]);
}

/// Big multi-PGN regression test (24 PGNs covering most field types,
/// repeating sets 1 and 2, ISO_NAME, STRING_LAU, DYNAMIC fields,
/// unit conversions, lat/lon width padding). Skips one line at the
/// end of the GNSS Sats in View payload where canboat C reads from
/// uninitialized memory past the declared payload length — that
/// behavior is a canboat-specific quirk we deliberately don't
/// replicate, see analyzer/print.c::extractNumber and the static
/// `RawMessage::data[FASTPACKET_MAX_SIZE]` buffer reuse.
#[test]
fn pgn_test_json() {
    // Line 6 (0-based) in pgn-test-json.out is the PGN 129540 "GNSS
    // Sats in View" frame. The last sat's `Range residuals` field
    // crosses the payload-end boundary; canboat extracts whatever was
    // in memory (happens to be `0.00000`), we correctly drop it.
    run_case_skipping("pgn-test.in", "pgn-test-json.out", &["--json"], &[6]);
}

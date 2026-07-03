// (C) 2009-2026, Kees Verruijt, Harlingen, The Netherlands.

//! End-to-end integration: write a synthetic iKonvert ASCII capture
//! and verify the binary's stdout matches the expected PLAIN line.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

#[test]
fn replays_synthetic_ikonvert_into_plain_line() {
    // One !PDGY line carrying PGN 60928 with the canboat test bytes
    // and an iKonvert keep-alive heartbeat — the all-empty 6-field
    // form (`$PDGY,000000,,,,,,`) that the device emits while idle.
    // The keep-alive must be dropped quietly; only the real frame
    // should appear on stdout.
    let body = "$PDGY,000000,,,,,,\r\n\
                !PDGY,60928,6,5,255,12.345,+5twIgCbUMA=\r\n";
    let tmpdir = std::env::temp_dir();
    let cap_path = tmpdir.join(format!(
        "canboat-rs-ikonvert-test-{}.txt",
        std::process::id()
    ));
    {
        let mut f = std::fs::File::create(&cap_path).expect("create temp");
        f.write_all(body.as_bytes()).expect("write");
    }

    let out = Command::new(test_binary_path())
        .arg("--file")
        .arg(&cap_path)
        .stdin(Stdio::null())
        .output()
        .expect("run ikonvert-serial");
    let _ = std::fs::remove_file(&cap_path);
    assert!(
        out.status.success(),
        "binary failed: status={:?} stderr={}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).expect("utf-8 stdout");
    // Output shape: "# format=FAST" header, then the synthetic
    // "CANboat: Startup" record (PGN 262656) that every device-reader
    // binary emits as its first frame, then the actual decoded frame.
    // The codec deliberately overrides the iKonvert's seconds-since-
    // boot timestamp with host wall-clock (matches canboat C's
    // computeIKonvertTime), so only the post-timestamp tail is stable
    // across runs.
    let mut lines = stdout.lines();
    assert_eq!(lines.next(), Some("# format=FAST"));
    skip_startup_record(lines.next().expect("startup line"));
    let frame = lines.next().expect("frame line");
    let (_ts, tail) = frame.split_once(',').expect("comma after timestamp");
    assert_eq!(tail, "6,60928,5,255,8,fb,9b,70,22,00,9b,50,c0");
}

#[test]
fn replays_ikonvert_data_heartbeat_into_synthesized_pgn() {
    // A populated `$PDGY,000000,...` heartbeat: load=38, errors=1,
    // count=38, uptime=753, gateway=2, rejected=0. The binary should
    // synthesize an IKONVERT_BEM (PGN 262400) frame on stdout.
    let body = "$PDGY,000000,38,1,38,753,2,0\r\n";
    let tmpdir = std::env::temp_dir();
    let cap_path = tmpdir.join(format!(
        "canboat-rs-ikonvert-bem-test-{}.txt",
        std::process::id()
    ));
    {
        let mut f = std::fs::File::create(&cap_path).expect("create temp");
        f.write_all(body.as_bytes()).expect("write");
    }

    let out = Command::new(test_binary_path())
        .arg("--file")
        .arg(&cap_path)
        .stdin(Stdio::null())
        .output()
        .expect("run ikonvert-serial");
    let _ = std::fs::remove_file(&cap_path);
    assert!(
        out.status.success(),
        "binary failed: status={:?} stderr={}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).expect("utf-8 stdout");
    let mut lines = stdout.lines();
    assert_eq!(lines.next(), Some("# format=FAST"));
    skip_startup_record(lines.next().expect("startup line"));
    let frame = lines.next().expect("frame line");
    // Timestamp is host wall-clock; check the rest of the line.
    let (_ts, tail) = frame.split_once(',').expect("comma after timestamp");
    assert_eq!(
        tail,
        "7,262400,2,255,15,26,01,00,00,00,26,f1,02,00,00,02,ff,ff,ff,ff"
    );
}

fn test_binary_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_ikonvert-serial"))
}

/// Sanity-check the synthetic startup record (PGN 262656) every
/// device-reader binary emits as its first frame. Asserts the line
/// is the right PGN/header shape; doesn't pin the version or device
/// fields since those vary with the binary's `CARGO_PKG_VERSION`.
fn skip_startup_record(line: &str) {
    assert!(
        line.contains(",7,262656,0,255,66,"),
        "expected CANboat: Startup record, got: {line:?}"
    );
}

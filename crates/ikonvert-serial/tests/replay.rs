//! End-to-end integration: write a synthetic iKonvert ASCII capture
//! and verify the binary's stdout matches the expected PLAIN line.

use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

#[test]
fn replays_synthetic_ikonvert_into_plain_line() {
    // One !PDGY line carrying PGN 60928 with the canboat test bytes
    // and an iKonvert control sentence to verify it's dropped quietly.
    let body = "$PDGY,000000,,,,,\r\n\
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
    // First line is the canboat format header tag; second is the
    // decoded frame.
    let mut lines = stdout.lines();
    assert_eq!(lines.next(), Some("# format=FAST"));
    assert_eq!(
        lines.next(),
        Some("12.345,6,60928,5,255,8,fb,9b,70,22,00,9b,50,c0")
    );
}

fn test_binary_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_ikonvert-serial"))
}

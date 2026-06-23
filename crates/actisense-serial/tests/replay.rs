//! End-to-end integration: write a synthetic NGT-1 binary capture,
//! run the actisense-serial binary against it, and verify the emitted
//! PLAIN line matches what canboat expects for the same N2K frame.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

const DLE: u8 = 0x10;
const STX: u8 = 0x02;
const ETX: u8 = 0x03;
const N2K_MSG_RECEIVED: u8 = 0x93;

/// Build an NGT-1 byte stream containing one N2K_MSG_RECEIVED frame.
fn build_ngt1_frame(prio: u8, pgn: u32, dst: u8, src: u8, ts_ms: u32, data: &[u8]) -> Vec<u8> {
    let mut payload = vec![
        prio,
        (pgn & 0xff) as u8,
        ((pgn >> 8) & 0xff) as u8,
        ((pgn >> 16) & 0xff) as u8,
        dst,
        src,
    ];
    payload.extend_from_slice(&ts_ms.to_le_bytes());
    payload.push(data.len() as u8);
    payload.extend_from_slice(data);

    let mut inner = vec![N2K_MSG_RECEIVED, payload.len() as u8];
    inner.extend_from_slice(&payload);
    let cksum: u8 = inner.iter().copied().fold(0u8, u8::wrapping_add);
    inner.push(0u8.wrapping_sub(cksum));

    let mut wire = vec![DLE, STX];
    for b in &inner {
        wire.push(*b);
        if *b == DLE {
            wire.push(DLE);
        }
    }
    wire.extend_from_slice(&[DLE, ETX]);
    wire
}

#[test]
fn replays_synthetic_ngt1_into_plain_line() {
    // PGN 60928 frame straight out of canboat/analyzer/tests/pgn-test.in:
    //   fb 9b 70 22 00 9b 50 c0  — ISO Address Claim, Manufacturer=Navico.
    let payload: &[u8] = &[0xfb, 0x9b, 0x70, 0x22, 0x00, 0x9b, 0x50, 0xc0];
    let mut bytes = vec![0xff, 0xaa]; // junk to test resync
    bytes.extend(build_ngt1_frame(6, 60928, 255, 5, 12_345, payload));
    bytes.extend_from_slice(&[0x00]);

    let tmpdir = std::env::temp_dir();
    let cap_path = tmpdir.join(format!(
        "canboat-rs-actisense-test-{}.bin",
        std::process::id()
    ));
    {
        let mut f = std::fs::File::create(&cap_path).expect("create temp");
        f.write_all(&bytes).expect("write");
    }

    let exe = test_binary_path();
    let out = Command::new(&exe)
        .arg("--file")
        .arg(&cap_path)
        .stdin(Stdio::null())
        .output()
        .expect("run actisense-serial");
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
    let mut lines = stdout.lines();
    assert_eq!(lines.next(), Some("# format=FAST"));
    let startup = lines.next().expect("startup line");
    assert!(
        startup.contains(",7,262656,0,255,66,"),
        "expected CANboat: Startup record, got: {startup:?}"
    );
    assert_eq!(
        lines.next(),
        Some("12345,6,60928,5,255,8,fb,9b,70,22,00,9b,50,c0"),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Locate the just-built binary. `cargo test -p actisense-serial`
/// produces it next to the test binary under `target/<profile>/`.
fn test_binary_path() -> PathBuf {
    // CARGO_BIN_EXE_<name> is set by Cargo for integration tests.
    PathBuf::from(env!("CARGO_BIN_EXE_actisense-serial"))
}

/// Encoder smoke test: the canboat-core helpers used by the writer
/// thread produce valid NGT-1 frames that decode back to the same
/// payload contents. The binary itself isn't spawned here — that path
/// needs a real serial port to drive end-to-end. This locks in the
/// stdin → write encode contract used by canboat's parseAndWriteIn.
#[test]
fn stdin_line_encodes_to_n2k_send_payload() {
    use canboat_core::format::{
        encode_n2k_send_payload, encode_ngt_message, parse_plain, Ngt1Decoder, NgtEvent,
        N2K_MSG_SEND,
    };

    let line = "12345,6,60928,5,255,8,fb,9b,70,22,00,9b,50,c0";
    let frame = parse_plain(line).expect("parse PLAIN line");

    let mut wire = Vec::new();
    encode_ngt_message(N2K_MSG_SEND, &encode_n2k_send_payload(&frame), &mut wire);
    let mut d = Ngt1Decoder::new();
    let events = d.push_bytes(&wire);
    assert_eq!(events.len(), 1);
    match &events[0] {
        NgtEvent::Message(m) => {
            assert_eq!(m.command, N2K_MSG_SEND);
            // Header layout: prio, pgn(LE) x3, dst, dlen, data...
            assert_eq!(m.payload[0], 6);
            assert_eq!(m.payload[1], 0x00); // 60928 LE
            assert_eq!(m.payload[2], 0xee);
            assert_eq!(m.payload[3], 0x00);
            assert_eq!(m.payload[4], 255);
            assert_eq!(m.payload[5], 8);
            assert_eq!(&m.payload[6..], &frame.data[..]);
        }
        other => panic!("expected Message, got {other:?}"),
    }
}

//! `socketcan-serial`: bridge a Linux SocketCAN interface to/from
//! canboat FAST format, behaving as much like `actisense-serial` and
//! `ikonvert-serial` as possible.
//!
//!   - received CAN frames are reassembled into whole PGNs and written
//!     to stdout in canboat FAST format (one line per PGN, preceded by
//!     a `# format=FAST` header), using [`canboat_core::Reassembler`];
//!   - canboat lines read from stdin are split into CAN frames and sent
//!     to the bus, with the source address forced to our claimed one;
//!   - the program is a real node on the bus: it claims an ISO source
//!     address (PGN 60928), backs off / re-claims on conflict, and
//!     answers ISO Requests (PGN 59904) for its address claim.
//!
//! Unlike the NGT-1 / iKonvert, a raw SocketCAN socket only delivers
//! single <= 8 byte frames, so fast-packet reassembly is done here in
//! software. Which PGNs are fast-packet is decided by range, except for
//! the mixed 0x1F000..0x1FFFF range, for which a table generated from
//! `data/canboat.json` at build time (see `build.rs`) is consulted.
//!
//! Mirrors `canboat/socketcan-serial/socketcan-serial.c`.

use std::process::ExitCode;

use clap::Parser;

include!(concat!(env!("OUT_DIR"), "/fastpacket_table.rs"));

/// Synthetic-PGN range — never on the wire, never sent to the bus.
const CANBOAT_PGN_START: u32 = 0x40000;

#[derive(Debug, Parser)]
#[command(
    name = "socketcan-serial",
    about = "Bridge a Linux SocketCAN interface to/from canboat FAST format",
    version
)]
struct Cli {
    /// SocketCAN interface name, e.g. can0 or nmea2000.
    device: String,

    /// Writeonly: received frames are not written to stdout.
    #[arg(short = 'w', long = "write-only")]
    writeonly: bool,

    /// Readonly: data from stdin is not sent to the device.
    #[arg(short = 'r', long = "read-only")]
    readonly: bool,

    /// Passthru: data from stdin is also echoed to stdout.
    #[arg(short = 'p', long)]
    passthru: bool,

    /// Verbose / debug logging.
    #[arg(short = 'v', long)]
    verbose: bool,

    /// Debug logging.
    #[arg(short = 'd', long)]
    debug: bool,

    /// Do not claim an address (passive bridge only).
    #[arg(short = 'n', long = "no-claim")]
    no_claim: bool,

    /// Timeout: quit if no frame is received for <n> seconds.
    #[arg(short = 't', long, value_name = "SECONDS", default_value_t = 0)]
    timeout: u64,

    /// Preferred source address to claim.
    #[arg(short = 'a', long = "address", value_name = "ADDR", default_value_t = 0)]
    address: u8,

    /// Unique number for the ISO NAME (default derived from the pid).
    #[arg(short = 'u', long = "unique", value_name = "N", default_value_t = 0)]
    unique: u32,

    /// Manufacturer code for the ISO NAME (999 = Signal K).
    #[arg(short = 'm', long = "manufacturer", value_name = "N", default_value_t = 999)]
    manufacturer: u16,
}

fn main() -> ExitCode {
    let cli = Cli::parse_from(canboat_cli::canboat_argv());
    let level = if cli.debug || cli.verbose {
        "debug"
    } else {
        "info"
    };
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(level)).init();

    if let Err(e) = run(cli) {
        eprintln!("socketcan-serial: {e:#}");
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}

/// Classify a PGN as fast-packet or single-frame. Range decides it
/// everywhere except the mixed 0x1F000..0x1FFFF window, which uses the
/// generated table. Mirrors `isFastPacket()` in the C tool.
fn packet_type(pgn: u32) -> canboat_core::FramePacketType {
    use canboat_core::FramePacketType::{Fast, Single};
    if (FASTPACKET_MIXED_START..FASTPACKET_MIXED_END).contains(&pgn) {
        return if FASTPACKET_MIXED[(pgn - FASTPACKET_MIXED_START) as usize] {
            Fast
        } else {
            Single
        };
    }
    if (0x10000..FASTPACKET_MIXED_START).contains(&pgn) {
        return Fast; // fast-packet-only range
    }
    if pgn >= CANBOAT_PGN_START {
        return Fast; // synthetic CANboat fast PGNs (not on the wire)
    }
    Single
}

/// Decompose a 29-bit ISO 11783 CAN id into (prio, pgn, src, dst).
/// Matches `getISO11783BitsFromCanId` in canboat/common/common.c.
fn iso_decompose(id: u32) -> (u8, u32, u8, u8) {
    let prio = ((id >> 26) & 0x7) as u8;
    let rdp = (id >> 24) & 0x3;
    let pf = ((id >> 16) & 0xff) as u8;
    let ps = ((id >> 8) & 0xff) as u8;
    let src = (id & 0xff) as u8;
    if pf < 240 {
        ((rdp << 16) | ((pf as u32) << 8), ps).into_pgn_dst(prio, src)
    } else {
        ((rdp << 16) | ((pf as u32) << 8) | ps as u32, 0xff).into_pgn_dst(prio, src)
    }
}

/// Tiny helper to keep `iso_decompose` readable.
trait IntoPgnDst {
    fn into_pgn_dst(self, prio: u8, src: u8) -> (u8, u32, u8, u8);
}
impl IntoPgnDst for (u32, u8) {
    fn into_pgn_dst(self, prio: u8, src: u8) -> (u8, u32, u8, u8) {
        (prio, self.0, src, self.1)
    }
}

/// Build the 29-bit ISO 11783 CAN id (without the EFF flag) from N2K
/// fields. Mirrors `getCanIdFromISO11783Bits`.
fn iso_compose(prio: u8, pgn: u32, src: u8, dst: u8) -> u32 {
    let mut id = src as u32;
    let pf = (pgn >> 8) & 0xff;
    if pf < 240 {
        id |= (dst as u32) << 8;
        id |= pgn << 8;
    } else {
        id |= pgn << 8;
    }
    id |= (prio as u32) << 26;
    id
}

/// Format epoch milliseconds as `YYYY-MM-DDTHH:MM:SS.mmmZ` (UTC),
/// matching canboat's `fmtTimestamp`. No chrono — civil date via the
/// Howard-Hinnant algorithm, as elsewhere in canboat-core.
fn format_iso(ms: u64) -> String {
    let secs = (ms / 1000) as i64;
    let millis = ms % 1000;
    let days = secs.div_euclid(86_400);
    let tod = secs.rem_euclid(86_400);
    let (y, mo, d) = days_to_ymd(days);
    let (h, mi, s) = (tod / 3600, (tod % 3600) / 60, tod % 60);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}.{millis:03}Z")
}

fn days_to_ymd(days: i64) -> (i32, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    ((y + i64::from(m <= 2)) as i32, m, d)
}

#[cfg(not(target_os = "linux"))]
fn run(_cli: Cli) -> anyhow::Result<()> {
    anyhow::bail!("SocketCAN is Linux-only");
}

#[cfg(target_os = "linux")]
fn run(cli: Cli) -> anyhow::Result<()> {
    linux::run(cli)
}

#[cfg(target_os = "linux")]
mod linux {
    use std::io::Write;
    use std::os::fd::AsRawFd;
    use std::time::{SystemTime, UNIX_EPOCH};

    use anyhow::{Context, Result};
    use canboat_core::format::plain::write_line;
    use canboat_core::frame::RawFrame;
    use canboat_core::{Reassembled, Reassembler};
    use socketcan::{CanSocket, EmbeddedFrame, ExtendedId, Socket};

    use super::*;

    const CAN_EFF_MASK: u32 = 0x1FFF_FFFF;
    const CAN_ERR_FLAG: u32 = 0x2000_0000;

    const PGN_ISO_ADDRESS_CLAIM: u32 = 60928;
    const PGN_ISO_REQUEST: u32 = 59904;
    const ADDR_GLOBAL: u8 = 255;
    const ADDR_NULL: u8 = 254;
    const ADDR_MAX: u8 = 253;
    const CLAIM_TIMEOUT_MS: u64 = 250;
    const SCAN_TIMEOUT_MS: u64 = 1000;

    fn now_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }

    #[derive(PartialEq)]
    enum ClaimState {
        Disabled,
        Scanning,
        Pending,
        Claimed,
        Failed,
    }

    struct Claimer {
        name: u64,
        address: u8,
        preferred: u8,
        state: ClaimState,
        deadline: u64,
        arbitrary: bool,
        used: [bool; 256],
    }

    impl Claimer {
        fn name_to_bytes(&self) -> [u8; 8] {
            self.name.to_le_bytes()
        }

        fn start(&mut self, sock: &CanSocket) {
            self.state = ClaimState::Scanning;
            self.deadline = now_ms() + SCAN_TIMEOUT_MS;
            // Ask every node to (re)announce its address claim so we
            // learn which addresses are taken before we pick one. Sent
            // from the null address since we have not claimed yet.
            self.send_request(sock, ADDR_NULL, ADDR_GLOBAL, PGN_ISO_ADDRESS_CLAIM);
            log::debug!("Scanning bus {SCAN_TIMEOUT_MS} ms before claiming (NAME {:#018x})", self.name);
        }

        fn begin_claim(&mut self, sock: &CanSocket) {
            if self.used[self.preferred as usize] {
                match self.pick_free() {
                    Some(next) => {
                        log::debug!("Preferred address {} is taken, using {next}", self.preferred);
                        self.address = next;
                    }
                    None => {
                        log::error!("No free address available; cannot claim");
                        self.address = ADDR_NULL;
                        self.state = ClaimState::Failed;
                        self.send_claim(sock, ADDR_GLOBAL);
                        return;
                    }
                }
            } else {
                self.address = self.preferred;
            }
            self.state = ClaimState::Pending;
            self.deadline = now_ms() + CLAIM_TIMEOUT_MS;
            self.send_claim(sock, ADDR_GLOBAL);
            log::debug!("Claiming address {} with NAME {:#018x}", self.address, self.name);
        }

        fn send_claim(&self, sock: &CanSocket, dst: u8) {
            let data = self.name_to_bytes();
            send_pgn(sock, 6, PGN_ISO_ADDRESS_CLAIM, self.address, dst, &data);
        }

        fn send_request(&self, sock: &CanSocket, src: u8, dst: u8, pgn: u32) {
            let data = [pgn as u8, (pgn >> 8) as u8, (pgn >> 16) as u8];
            send_pgn(sock, 6, PGN_ISO_REQUEST, src, dst, &data);
        }

        fn pick_free(&self) -> Option<u8> {
            (0..=ADDR_MAX).find(|a| !self.used[*a as usize])
        }

        fn on_claim(&mut self, sock: &CanSocket, src: u8, data: &[u8]) {
            if data.len() < 8 || src > ADDR_MAX {
                return;
            }
            let their_name = u64::from_le_bytes(data[..8].try_into().unwrap());
            // While scanning we own no address yet — just learn what is in use.
            if self.state == ClaimState::Scanning {
                self.used[src as usize] = true;
                return;
            }
            if src != self.address {
                self.used[src as usize] = true;
                return;
            }
            // Someone is claiming our address. Lowest NAME wins.
            if self.name < their_name {
                log::debug!("Won address {} conflict (our NAME lower), re-claiming", self.address);
                self.state = ClaimState::Pending;
                self.deadline = now_ms() + CLAIM_TIMEOUT_MS;
                self.send_claim(sock, ADDR_GLOBAL);
                return;
            }
            // We lost.
            self.used[src as usize] = true;
            if self.arbitrary {
                if let Some(next) = self.pick_free() {
                    log::debug!("Lost address {} conflict, moving to {next}", self.address);
                    self.address = next;
                    self.state = ClaimState::Pending;
                    self.deadline = now_ms() + CLAIM_TIMEOUT_MS;
                    self.send_claim(sock, ADDR_GLOBAL);
                    return;
                }
                log::error!("Lost address {} and no free address left; cannot claim", self.address);
            } else {
                log::error!(
                    "Lost address {} conflict and not arbitrary-address-capable; cannot claim",
                    self.address
                );
            }
            self.address = ADDR_NULL;
            self.state = ClaimState::Failed;
            self.send_claim(sock, ADDR_GLOBAL);
        }

        fn on_request(&self, sock: &CanSocket, dst: u8, data: &[u8]) {
            if data.len() < 3 {
                return;
            }
            let requested = data[0] as u32 | (data[1] as u32) << 8 | (data[2] as u32) << 16;
            if requested == PGN_ISO_ADDRESS_CLAIM
                && (dst == self.address || dst == ADDR_GLOBAL)
                && matches!(self.state, ClaimState::Claimed | ClaimState::Pending)
            {
                self.send_claim(sock, ADDR_GLOBAL);
            }
        }

        fn tick(&mut self, sock: &CanSocket, now: u64) {
            if self.state == ClaimState::Scanning && now >= self.deadline {
                self.begin_claim(sock);
                return;
            }
            if self.state == ClaimState::Pending && now >= self.deadline {
                self.state = ClaimState::Claimed;
                log::info!("Address {} claimed", self.address);
            }
        }
    }

    /// Send an NMEA 2000 message, splitting into a fast packet if the
    /// payload is longer than 8 bytes. Same wire layout as
    /// socketcan-writer.
    fn send_pgn(sock: &CanSocket, prio: u8, pgn: u32, src: u8, dst: u8, data: &[u8]) {
        let can_id = iso_compose(prio, pgn, src, dst);
        if data.len() <= 8 {
            send_raw(sock, can_id, data);
            return;
        }
        let total = data.len();
        let mut index: u8 = 0;
        let mut taken = 0usize;
        while taken < total {
            let mut frame = [0u8; 8];
            frame[0] = index;
            let len = if index == 0 {
                frame[1] = total as u8;
                let chunk = (total - taken).min(6);
                frame[2..2 + chunk].copy_from_slice(&data[taken..taken + chunk]);
                taken += chunk;
                2 + chunk
            } else {
                let chunk = (total - taken).min(7);
                frame[1..1 + chunk].copy_from_slice(&data[taken..taken + chunk]);
                taken += chunk;
                1 + chunk
            };
            send_raw(sock, can_id, &frame[..len]);
            index = index.wrapping_add(1);
        }
    }

    fn send_raw(sock: &CanSocket, can_id: u32, data: &[u8]) {
        let Some(id) = ExtendedId::new(can_id & CAN_EFF_MASK) else {
            return;
        };
        match socketcan::CanFrame::new(socketcan::Id::Extended(id), data) {
            Some(frame) => {
                if let Err(e) = sock.write_frame(&frame) {
                    log::error!("write to CAN: {e}");
                }
            }
            None => log::error!("could not build CAN frame for id {can_id:#x}"),
        }
    }

    /// Read one frame plus its kernel SO_TIMESTAMP via recvmsg.
    /// Returns Ok(None) when the socket has no more frames ready.
    fn recv_frame(fd: i32) -> std::io::Result<Option<(u32, usize, [u8; 8], u64)>> {
        let mut raw = [0u8; 16]; // struct can_frame
        let mut ctrl = [0u8; 64];
        // SAFETY: all pointers refer to live local buffers for the
        // duration of the call; recvmsg only writes within them.
        unsafe {
            let mut iov = libc::iovec {
                iov_base: raw.as_mut_ptr() as *mut libc::c_void,
                iov_len: raw.len(),
            };
            let mut msg: libc::msghdr = std::mem::zeroed();
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            msg.msg_control = ctrl.as_mut_ptr() as *mut libc::c_void;
            msg.msg_controllen = ctrl.len() as _;

            let n = libc::recvmsg(fd, &mut msg, 0);
            if n < 0 {
                let e = std::io::Error::last_os_error();
                return match e.raw_os_error() {
                    Some(code) if code == libc::EAGAIN || code == libc::EWOULDBLOCK => Ok(None),
                    Some(code) if code == libc::EINTR => Ok(None),
                    _ => Err(e),
                };
            }
            if (n as usize) < raw.len() {
                return Ok(None);
            }

            let mut when = 0u64;
            let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
            while !cmsg.is_null() {
                let c = &*cmsg;
                if c.cmsg_level == libc::SOL_SOCKET && c.cmsg_type == libc::SCM_TIMESTAMP {
                    let mut tv: libc::timeval = std::mem::zeroed();
                    std::ptr::copy_nonoverlapping(
                        libc::CMSG_DATA(cmsg),
                        &mut tv as *mut _ as *mut u8,
                        std::mem::size_of::<libc::timeval>(),
                    );
                    when = tv.tv_sec as u64 * 1000 + (tv.tv_usec as u64) / 1000;
                }
                cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
            }

            let id = u32::from_ne_bytes([raw[0], raw[1], raw[2], raw[3]]);
            let dlc = raw[4] as usize;
            let mut data = [0u8; 8];
            data.copy_from_slice(&raw[8..16]);
            Ok(Some((id, dlc.min(8), data, when)))
        }
    }

    fn set_nonblocking(fd: i32) -> std::io::Result<()> {
        // SAFETY: fcntl on a valid fd with documented flags.
        unsafe {
            let flags = libc::fcntl(fd, libc::F_GETFL);
            if flags < 0 || libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) < 0 {
                return Err(std::io::Error::last_os_error());
            }
        }
        Ok(())
    }

    pub fn run(mut cli: Cli) -> Result<()> {
        let sock = CanSocket::open(&cli.device)
            .with_context(|| format!("opening SocketCAN {}", cli.device))?;
        let fd = sock.as_raw_fd();
        sock.set_nonblocking(true).context("set_nonblocking")?;

        // Kernel RX timestamps.
        let on: libc::c_int = 1;
        // SAFETY: setsockopt with a valid fd and an int-sized option.
        unsafe {
            if libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_TIMESTAMP,
                &on as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as _,
            ) < 0
            {
                log::warn!(
                    "SO_TIMESTAMP: {} (continuing without kernel timestamps)",
                    std::io::Error::last_os_error()
                );
            }
        }

        let mut claimer = Claimer {
            name: build_name(&cli),
            address: cli.address,
            preferred: cli.address,
            state: if cli.no_claim { ClaimState::Disabled } else { ClaimState::Pending },
            deadline: 0,
            arbitrary: true,
            used: [false; 256],
        };

        let mut out = std::io::BufWriter::new(std::io::stdout());
        writeln!(out, "# format=FAST")?;
        // Synthetic startup record, like canboat's emitCanboatStartupRecord.
        let rec = canboat_core::startup_record(env!("CARGO_PKG_VERSION"), "socketcan-serial", &cli.device);
        let mut line = String::with_capacity(160);
        write_line(&mut line, &rec).ok();
        out.write_all(line.as_bytes())?;
        out.write_all(b"\n")?;
        out.flush()?;

        if claimer.state != ClaimState::Disabled {
            claimer.start(&sock);
        }

        let mut reasm = Reassembler::new();
        let mut stdin_buf: Vec<u8> = Vec::with_capacity(4096);
        let mut stdin_eof = cli.readonly;
        if !stdin_eof {
            set_nonblocking(libc::STDIN_FILENO).ok();
        }

        loop {
            let now = now_ms();
            let timeout_ms: i32 = if matches!(claimer.state, ClaimState::Pending | ClaimState::Scanning)
                && claimer.deadline > now
            {
                (claimer.deadline - now) as i32
            } else if cli.timeout > 0 {
                (cli.timeout * 1000) as i32
            } else {
                1000
            };

            let mut fds = [
                libc::pollfd { fd, events: libc::POLLIN, revents: 0 },
                libc::pollfd { fd: libc::STDIN_FILENO, events: libc::POLLIN, revents: 0 },
            ];
            let nfds = if stdin_eof { 1 } else { 2 };
            // SAFETY: poll over a valid pollfd array.
            let r = unsafe { libc::poll(fds.as_mut_ptr(), nfds as libc::nfds_t, timeout_ms) };
            if r < 0 {
                let e = std::io::Error::last_os_error();
                if e.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(e).context("poll");
            }
            if r == 0
                && cli.timeout > 0
                && !matches!(claimer.state, ClaimState::Pending | ClaimState::Scanning)
            {
                anyhow::bail!("Timeout {} seconds; no data received", cli.timeout);
            }

            if fds[0].revents & libc::POLLIN != 0 {
                // Drain at most a batch per wake-up, then yield so the
                // address-claim timers keep advancing on a busy bus.
                let mut budget = 256;
                while budget > 0 {
                    budget -= 1;
                    let Some((id, dlc, data, when)) = recv_frame(fd)? else {
                        break;
                    };
                    if id & CAN_ERR_FLAG != 0 {
                        continue;
                    }
                    handle_frame(
                        &sock,
                        &mut reasm,
                        &mut claimer,
                        cli.writeonly,
                        &mut out,
                        id & CAN_EFF_MASK,
                        &data[..dlc],
                        if when != 0 { when } else { now_ms() },
                    )?;
                }
            }

            if !stdin_eof && nfds == 2 && fds[1].revents & (libc::POLLIN | libc::POLLHUP) != 0 {
                match read_stdin(&mut stdin_buf) {
                    StdinResult::Eof => {
                        log::debug!("EOF on stdin, continuing read-only");
                        stdin_eof = true;
                        cli.readonly = true;
                    }
                    StdinResult::Lines => {
                        drain_lines(&sock, &mut claimer, &mut out, cli.passthru, &mut stdin_buf)?;
                    }
                    StdinResult::WouldBlock => {}
                }
            }

            claimer.tick(&sock, now_ms());
        }
    }

    enum StdinResult {
        Lines,
        Eof,
        WouldBlock,
    }

    fn read_stdin(buf: &mut Vec<u8>) -> StdinResult {
        let mut chunk = [0u8; 2048];
        // SAFETY: read into a live local buffer on a valid fd.
        let n = unsafe {
            libc::read(
                libc::STDIN_FILENO,
                chunk.as_mut_ptr() as *mut libc::c_void,
                chunk.len(),
            )
        };
        if n == 0 {
            return StdinResult::Eof;
        }
        if n < 0 {
            let e = std::io::Error::last_os_error();
            return match e.raw_os_error() {
                Some(c) if c == libc::EAGAIN || c == libc::EWOULDBLOCK || c == libc::EINTR => {
                    StdinResult::WouldBlock
                }
                _ => StdinResult::Eof,
            };
        }
        buf.extend_from_slice(&chunk[..n as usize]);
        StdinResult::Lines
    }

    fn drain_lines(
        sock: &CanSocket,
        claimer: &mut Claimer,
        out: &mut impl Write,
        passthru: bool,
        buf: &mut Vec<u8>,
    ) -> Result<()> {
        while let Some(nl) = buf.iter().position(|&b| b == b'\n') {
            let line: Vec<u8> = buf.drain(..=nl).collect();
            let text = String::from_utf8_lossy(&line);
            let trimmed = text.trim_end_matches(['\r', '\n']);
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            match canboat_core::format::plain::parse_line(trimmed) {
                Ok(frame) if frame.pgn < CANBOAT_PGN_START => {
                    send_pgn(sock, frame.prio, frame.pgn, claimer.address, frame.dst, &frame.data);
                }
                Ok(_) => {} // synthetic status PGN, not for the bus
                Err(e) => log::warn!("skipping malformed line: {e}"),
            }
            if passthru {
                out.write_all(&line)?;
                out.flush()?;
            }
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn handle_frame(
        sock: &CanSocket,
        reasm: &mut Reassembler,
        claimer: &mut Claimer,
        writeonly: bool,
        out: &mut impl Write,
        can_id: u32,
        data: &[u8],
        when: u64,
    ) -> Result<()> {
        let (prio, pgn, src, dst) = iso_decompose(can_id);

        if claimer.state != ClaimState::Disabled {
            if pgn == PGN_ISO_ADDRESS_CLAIM {
                claimer.on_claim(sock, src, data);
            } else if pgn == PGN_ISO_REQUEST {
                claimer.on_request(sock, dst, data);
            }
        }

        if writeonly {
            return Ok(());
        }

        let frame = RawFrame::new(Some(format_iso(when)), prio, pgn, src, dst, data.iter().copied());
        match reasm.push(frame, packet_type(pgn)) {
            Reassembled::PassThrough(f) | Reassembled::Complete(f) => {
                let mut line = String::with_capacity(96);
                write_line(&mut line, &f).ok();
                out.write_all(line.as_bytes())?;
                out.write_all(b"\n")?;
                out.flush()?;
            }
            Reassembled::Partial => {}
            Reassembled::Error(e) => log::debug!("reassembly: {e}"),
        }
        Ok(())
    }

    fn build_name(cli: &Cli) -> u64 {
        let unique = if cli.unique != 0 {
            cli.unique & 0x1fffff
        } else {
            // SAFETY: getpid is always safe.
            (unsafe { libc::getpid() } as u32) & 0x1fffff
        };
        let manufacturer = cli.manufacturer as u64 & 0x7ff;
        let device_instance: u64 = 0;
        let device_function: u64 = 130; // PC Gateway
        let device_class: u64 = 25; // Inter/Intranetwork Device
        let system_instance: u64 = 0;
        let industry_group: u64 = 4; // Marine
        let arbitrary: u64 = 1;
        (unique as u64)
            | (manufacturer << 21)
            | ((device_instance & 0x07) << 32)
            | ((device_instance >> 3 & 0x1f) << 35)
            | ((device_function & 0xff) << 40)
            | ((device_class & 0x7f) << 49)
            | ((system_instance & 0x0f) << 56)
            | ((industry_group & 0x07) << 60)
            | (arbitrary << 63)
    }
}

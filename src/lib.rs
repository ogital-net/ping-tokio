#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
// Pedantic-lint allows scoped to the whole crate. These categories are either
// unavoidable in protocol code or low-signal for this library:
// * `doc_markdown` — we'd otherwise have to backtick `ICMPv4`/`ICMPv6` in
//   every doc comment.
// * `missing_errors_doc` / `missing_panics_doc` — most public functions wrap
//   `std::io` and the only `unwrap`s are on length-checked slice conversions
//   that cannot fail.
// * `must_use_candidate` — too noisy for small helpers.
// * The cast lints — packet parsing and stats math intentionally narrow
//   integer types after explicit range checks.
#![allow(
    clippy::doc_markdown,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss
)]

/// Conversion from various inputs (IP addresses, hostnames) into [`std::net::IpAddr`].
pub mod addr;
mod net;
pub(crate) mod time;

use std::{
    mem::MaybeUninit,
    net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6},
    sync::{
        atomic::{AtomicU16, Ordering},
        LazyLock,
    },
    time::Duration,
};

pub use net::IcmpSocket;
use net::SocketType;
use socket2::{MaybeUninitSlice, MsgHdrMut, SockAddr};
use tokio::time::timeout;

use crate::addr::ToIpAddr;

const IP_HEADER_SIZE: usize = 20;
const ICMP_HEADER_SIZE: usize = 8;

const ICMP_ECHO_REQUEST: u8 = 8;
const ICMP_ECHO_REPLY: u8 = 0;
const ICMP6_ECHO_REQUEST: u8 = 128;
const ICMP6_ECHO_REPLY: u8 = 129;

// Seed `REQ_ID` from PID mixed with the low bits of the current wall-clock
// time so two processes started with PIDs differing by a multiple of 65536
// don't begin life with the same id, and so that restarting the same binary
// quickly doesn't reliably reuse the previous run's ids. The id is only used
// to disambiguate replies on a shared raw ICMP socket; reply matching also
// validates `seq` and the echoed timestamp payload, so this seed only needs
// to spread starting points around the 16-bit space, not be cryptographic.
pub(crate) static REQ_ID: LazyLock<AtomicU16> = LazyLock::new(|| {
    let pid = u64::from(std::process::id());
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::from(d.subsec_nanos()));
    #[allow(clippy::cast_possible_truncation)]
    AtomicU16::new(((pid ^ nanos ^ (nanos >> 16)) & 0xffff) as u16)
});

/// Summary statistics produced by [`ping`].
///
/// Mirrors the output of the Unix `ping` command: packet counts and
/// round-trip time statistics computed across all replied probes.
#[derive(Clone, Copy, Debug)]
pub struct PingStats {
    /// Total number of ICMP echo requests transmitted.
    pub packets_tx: u32,
    /// Number of ICMP echo replies received (i.e. non-timed-out probes).
    pub packets_rx: u32,
    /// Minimum round-trip time across all received replies.
    pub rtt_min: Duration,
    /// Mean round-trip time across all received replies.
    pub rtt_avg: Duration,
    /// Maximum round-trip time across all received replies.
    pub rtt_max: Duration,
    /// Population standard deviation of the round-trip times.
    pub rtt_std_dev: Duration,
}

/// The result of a successful ICMPv4 echo (ping) exchange.
#[derive(Clone, Copy, Debug)]
pub struct IcmpEchoReply {
    /// Source IPv4 address of the host that sent the echo reply.
    pub src_addr: Ipv4Addr,
    /// Total byte length of the received ICMP message (header + payload).
    pub len: usize,
    /// Sequence number echoed back by the remote host.
    pub seq: u16,
    /// Time-to-live value from the IP header of the reply.
    pub ttl: u8,
    /// Round-trip time measured from request transmission to reply receipt.
    pub rtt: Duration,
}

/// Send a series of ICMP echo requests to `dest` and return aggregate statistics.
///
/// Automatically selects ICMPv4 or ICMPv6 based on the resolved address family
/// of `dest`. The socket is bound to `src` (typically `UNSPECIFIED`) before
/// connecting.
///
/// # Arguments
///
/// * `src` — Local address to bind the raw socket to (e.g. `Ipv4Addr::UNSPECIFIED`).
/// * `dest` — Destination host; any type that implements [`ToIpAddr`] is accepted
///   (IP address, hostname string, etc.).
/// * `count` — Number of ICMP echo requests to send.
/// * `interval` — How long to wait between sending successive echo requests.
/// * `size` — Total ICMP payload size in bytes. The first 8 bytes are reserved
///   for an internal timestamp; must be greater than 8.
///
/// # Errors
///
/// * [`std::io::ErrorKind::InvalidInput`] — `size` is 8 or fewer bytes.
/// * Any I/O error from socket creation, binding, or connecting.
/// * Individual probe timeouts are counted as lost packets and do **not** cause
///   the function to return an error.
pub async fn ping<A: ToIpAddr>(
    src: A,
    dest: A,
    count: u32,
    interval: Duration,
    size: u16,
) -> std::io::Result<PingStats> {
    use std::net::IpAddr;

    let dest = dest.to_ip_addr().await?;
    let ts_len = time::Timestamp::len();
    if (size as usize) <= ts_len {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("size must be greater than {ts_len} (timestamp bytes)"),
        ));
    }
    let payload = generate_payload(size as usize - ts_len);
    let tout = Duration::from_secs(5);

    let socket = IcmpSocket::bind(src).await?;
    socket.connect(dest).await?;

    let mut packets_rx: u32 = 0;
    let mut rtts: Vec<Duration> = Vec::with_capacity(count as usize);

    for seq in 1..=count {
        let result = match dest {
            IpAddr::V4(_) => send_icmp_echo_v4(&socket, &payload, seq as u16, tout)
                .await
                .map(|r| r.rtt),
            IpAddr::V6(_) => send_icmp_echo_v6(&socket, &payload, seq as u16, tout)
                .await
                .map(|r| r.rtt),
        };
        if let Ok(rtt) = result {
            packets_rx += 1;
            rtts.push(rtt);
        }
        if seq < count {
            tokio::time::sleep(interval).await;
        }
    }

    let packets_tx = count;
    let mut stats = compute_rtt_stats(&rtts);
    stats.packets_tx = packets_tx;
    stats.packets_rx = packets_rx;
    Ok(stats)
}

/// Compute RTT statistics from a list of round-trip time samples.
///
/// `packets_tx` and `packets_rx` are left as `0`; the caller is responsible
/// for filling them in.
fn compute_rtt_stats(rtts: &[Duration]) -> PingStats {
    let (rtt_min, rtt_avg, rtt_max, rtt_std_dev) = if rtts.is_empty() {
        (
            Duration::ZERO,
            Duration::ZERO,
            Duration::ZERO,
            Duration::ZERO,
        )
    } else {
        let min = *rtts.iter().min().unwrap();
        let max = *rtts.iter().max().unwrap();
        let avg_nanos = rtts.iter().map(|d| d.as_nanos() as u64).sum::<u64>() / rtts.len() as u64;
        let avg = Duration::from_nanos(avg_nanos);
        let variance = rtts
            .iter()
            .map(|d| {
                let diff = d.as_nanos() as i64 - avg_nanos as i64;
                (diff * diff) as u64
            })
            .sum::<u64>()
            / rtts.len() as u64;
        let std_dev = Duration::from_nanos(variance.isqrt());
        (min, avg, max, std_dev)
    };
    PingStats {
        packets_tx: 0,
        packets_rx: 0,
        rtt_min,
        rtt_avg,
        rtt_max,
        rtt_std_dev,
    }
}

/// The result of a successful ICMPv6 echo (ping) exchange.
#[derive(Clone, Copy, Debug)]
pub struct IcmpV6EchoReply {
    /// Source IPv6 address of the host that sent the echo reply.
    pub src_addr: Ipv6Addr,
    /// Total byte length of the received ICMPv6 message (header + payload).
    pub len: usize,
    /// Sequence number echoed back by the remote host.
    pub seq: u16,
    /// Hop limit (analogous to TTL) from the received IPv6 packet.
    pub hlim: u8,
    /// Round-trip time measured from request transmission to reply receipt.
    pub rtt: Duration,
}

/// Send an ICMPv4 echo request and wait for the matching echo reply.
///
/// # Arguments
///
/// * `socket` — A bound and connected [`IcmpSocket`] for IPv4.
/// * `payload` — Application data appended after the ICMP header and timestamp.
/// * `seq` — Sequence number embedded in the ICMP echo request.
/// * `tout` — Maximum time to wait for a matching reply before returning
///   [`std::io::ErrorKind::TimedOut`].
///
/// # Errors
///
/// Returns an error if the underlying send or receive fails, or if `tout`
/// elapses before a matching reply is received.
pub async fn send_icmp_echo_v4(
    socket: &IcmpSocket,
    payload: &[u8],
    seq: u16,
    tout: Duration,
) -> std::io::Result<IcmpEchoReply> {
    let sock_type = socket.sock_type();
    let ts_len = time::Timestamp::len();

    // On Linux `SOCK_DGRAM` ping sockets, the kernel uses the bound port as
    // the ICMP identifier. We must use the same id in the packet header AND
    // the bound port. The socket already bound with this id in `bind()`.
    let req_id = match socket.dgram_ident() {
        Some(id) => id,
        None => REQ_ID.fetch_add(1, Ordering::Relaxed),
    };

    // Allocate a single buffer used for both send and receive, like the v6
    // path. For RAW sockets, received data includes a 20-byte IP header;
    // add that overhead so the buffer never truncates.
    let icmp_len = ICMP_HEADER_SIZE + ts_len + payload.len();
    let buf_cap = match sock_type {
        SocketType::Dgram => icmp_len,
        SocketType::Raw => IP_HEADER_SIZE + icmp_len,
    };
    let mut buf: Vec<u8> = Vec::with_capacity(buf_cap);

    add_icmp_header(&mut buf, ICMP_ECHO_REQUEST, req_id, seq);
    let sent_ts_bytes = time::Timestamp::now().as_bytes();
    buf.extend_from_slice(&sent_ts_bytes);
    buf.extend_from_slice(payload);

    let checksum = calculate_checksum(&buf);
    buf[2] = (checksum >> 8) as u8;
    buf[3] = (checksum & 0xff) as u8;

    socket.send(&buf).await?;

    // For DGRAM sockets, we receive via recvmsg to get TTL from IP_TTL cmsg.
    // For RAW sockets, we receive via recv and parse the IP header ourselves.
    match sock_type {
        SocketType::Dgram => {
            send_icmp_echo_v4_dgram(socket, req_id, seq, sent_ts_bytes, buf, tout).await
        }
        SocketType::Raw => {
            send_icmp_echo_v4_raw(socket, req_id, seq, sent_ts_bytes, buf, tout).await
        }
    }
}

/// Receive path for `SOCK_RAW`: IP header is present in the data.
async fn send_icmp_echo_v4_raw(
    socket: &IcmpSocket,
    req_id: u16,
    seq: u16,
    sent_ts_bytes: [u8; 8],
    mut buf: Vec<u8>,
    tout: Duration,
) -> std::io::Result<IcmpEchoReply> {
    let ts_len = time::Timestamp::len();

    let overall = timeout(tout, async {
        loop {
            buf.clear();
            let received = socket.recv(buf.spare_capacity_mut()).await?;
            unsafe { buf.set_len(received) };
            if received < IP_HEADER_SIZE + ICMP_HEADER_SIZE + ts_len {
                continue;
            }
            let msg_type = buf[IP_HEADER_SIZE];
            if msg_type != ICMP_ECHO_REPLY {
                continue;
            }
            let reply_id = u16::from_be_bytes([buf[IP_HEADER_SIZE + 4], buf[IP_HEADER_SIZE + 5]]);
            if req_id != reply_id {
                continue;
            }
            let reply_seq = u16::from_be_bytes([buf[IP_HEADER_SIZE + 6], buf[IP_HEADER_SIZE + 7]]);
            if reply_seq != seq {
                continue;
            }
            let ts_start = IP_HEADER_SIZE + ICMP_HEADER_SIZE;
            let ts_end = ts_start + ts_len;
            if buf[ts_start..ts_end] != sent_ts_bytes {
                continue;
            }
            let now = time::Timestamp::now();
            let src_addr = Ipv4Addr::new(
                buf[IP_HEADER_SIZE - 8],
                buf[IP_HEADER_SIZE - 7],
                buf[IP_HEADER_SIZE - 6],
                buf[IP_HEADER_SIZE - 5],
            );
            let reply_ttl = buf[8];
            let reply_ts =
                time::Timestamp::from(<[u8; 8]>::try_from(&buf[ts_start..ts_end]).unwrap());
            let rtt = now - reply_ts;
            return Ok(IcmpEchoReply {
                src_addr,
                len: received - IP_HEADER_SIZE,
                seq: reply_seq,
                ttl: reply_ttl,
                rtt,
            });
        }
    });

    match overall.await {
        Ok(result) => result,
        Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "timed out",
        )),
    }
}

/// Receive path for `SOCK_DGRAM`: no IP header; TTL via `IP_TTL` cmsg.
async fn send_icmp_echo_v4_dgram(
    socket: &IcmpSocket,
    req_id: u16,
    seq: u16,
    sent_ts_bytes: [u8; 8],
    mut buf: Vec<u8>,
    tout: Duration,
) -> std::io::Result<IcmpEchoReply> {
    let ts_len = time::Timestamp::len();

    // The kernel delivers the source address in the `msg_name` field and TTL
    // in an `IP_TTL` control message (enabled via `IP_RECVTTL` in `bind()`).
    // The storage is sized to comfortably exceed `CMSG_SPACE(sizeof(int))`
    // and is backed by `u64` to satisfy `cmsghdr` alignment; `MSG_CTRUNC` is
    // checked below in case a future change adds more cmsgs and overflows it.
    let mut control_storage: [MaybeUninit<u64>; 8] = [MaybeUninit::uninit(); 8];
    let mut from: SockAddr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0u16).into();

    let overall = timeout(tout, async {
        loop {
            buf.clear();

            let (received, flags, reply_ttl_opt) = {
                let bufs = &mut [MaybeUninitSlice::new(buf.spare_capacity_mut())];
                let control_bytes: &mut [MaybeUninit<u8>] = unsafe {
                    std::slice::from_raw_parts_mut(
                        control_storage.as_mut_ptr().cast::<MaybeUninit<u8>>(),
                        std::mem::size_of_val(&control_storage),
                    )
                };
                let mut msg = MsgHdrMut::new()
                    .with_addr(&mut from)
                    .with_control(control_bytes)
                    .with_buffers(bufs);

                let received = socket.recvmsg(&mut msg).await?;
                // SAFETY: `MsgHdrMut` is `#[repr(transparent)]` over `libc::msghdr`
                let hdr: &libc::msghdr = unsafe { &*(&raw const msg as *const libc::msghdr) };
                let flags = hdr.msg_flags;
                let ttl = decode_ip_ttl(hdr);
                (received, flags, ttl)
            };
            unsafe { buf.set_len(received) };

            if flags & libc::MSG_CTRUNC != 0 {
                return Err(std::io::Error::other(
                    "recvmsg control buffer truncated (MSG_CTRUNC)",
                ));
            }

            if received < ICMP_HEADER_SIZE + ts_len {
                continue;
            }
            // On DGRAM ping sockets, the ICMP message starts at byte 0 (no IP header).
            let msg_type = buf[0];
            if msg_type != ICMP_ECHO_REPLY {
                continue;
            }
            let reply_id = u16::from_be_bytes([buf[4], buf[5]]);
            if req_id != reply_id {
                continue;
            }
            let reply_seq = u16::from_be_bytes([buf[6], buf[7]]);
            if reply_seq != seq {
                continue;
            }
            let ts_end = ICMP_HEADER_SIZE + ts_len;
            if buf[ICMP_HEADER_SIZE..ts_end] != sent_ts_bytes {
                continue;
            }
            let now = time::Timestamp::now();
            let src_addr = from.as_socket_ipv4().map(|s| *s.ip()).ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "recvmsg returned no source address",
                )
            })?;
            // If the kernel didn't attach an `IP_TTL` cmsg (e.g. an older
            // kernel that rejected `IP_RECVTTL`), fall back to 0 rather than
            // dropping the reply. This mirrors iputils `ping(8)`, which only
            // warns on `setsockopt(IP_RECVTTL)` failure and reports ttl 0.
            let reply_ttl = reply_ttl_opt.unwrap_or(0);
            let reply_ts =
                time::Timestamp::from(<[u8; 8]>::try_from(&buf[ICMP_HEADER_SIZE..ts_end]).unwrap());
            let rtt = now - reply_ts;
            return Ok(IcmpEchoReply {
                src_addr,
                len: received,
                seq: reply_seq,
                ttl: reply_ttl,
                rtt,
            });
        }
    });

    match overall.await {
        Ok(result) => result,
        Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "timed out",
        )),
    }
}

/// Send an ICMPv6 echo request and wait for the matching echo reply.
///
/// # Arguments
///
/// * `socket` — A bound and connected [`IcmpSocket`] for IPv6.
/// * `payload` — Application data appended after the ICMPv6 header and timestamp.
/// * `seq` — Sequence number embedded in the ICMPv6 echo request.
/// * `tout` — Maximum time to wait for a matching reply before returning
///   [`std::io::ErrorKind::TimedOut`].
///
/// # Errors
///
/// Returns an error if the underlying send or receive fails, or if `tout`
/// elapses before a matching reply is received.
pub async fn send_icmp_echo_v6(
    socket: &IcmpSocket,
    payload: &[u8],
    seq: u16,
    tout: Duration,
) -> std::io::Result<IcmpV6EchoReply> {
    let mut buf: Vec<u8> =
        Vec::with_capacity(ICMP_HEADER_SIZE + time::Timestamp::len() + payload.len());
    // On Linux `SOCK_DGRAM` ping sockets, the kernel uses the bound port as
    // the ICMP identifier. We use the socket's pre-bound ident if available.
    let req_id = match socket.dgram_ident() {
        Some(id) => id,
        None => REQ_ID.fetch_add(1, Ordering::Relaxed),
    };
    add_icmp_header(&mut buf, ICMP6_ECHO_REQUEST, req_id, seq);
    let sent_ts_bytes = time::Timestamp::now().as_bytes();
    buf.extend_from_slice(&sent_ts_bytes);
    buf.extend_from_slice(payload);

    socket.send(&buf).await?;

    let mut from: SockAddr = SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0u16, 0, 0).into();

    // Ancillary data buffer for `IPV6_HOPLIMIT`. Sized to comfortably exceed
    // `CMSG_SPACE(sizeof(int))` on all supported platforms (~20–24 bytes), and
    // backed by `u64` so it satisfies the alignment requirements of `cmsghdr`
    // (which the `CMSG_*` macros assume). MSG_CTRUNC is checked below in case
    // a future change adds more cmsgs and overflows it.
    let mut control_storage: [MaybeUninit<u64>; 8] = [MaybeUninit::uninit(); 8];

    let overall = timeout(tout, async {
        loop {
            buf.clear();

            // Receive into `buf` + `control_storage` via a `MsgHdrMut`. The
            // wrapper is dropped at the end of this inner block so that we
            // can read from `buf` / `from` / `control_storage` afterwards
            // without conflicting borrows.
            let (received, flags, reply_hlim_opt) = {
                let bufs = &mut [MaybeUninitSlice::new(buf.spare_capacity_mut())];
                let control_bytes: &mut [MaybeUninit<u8>] = unsafe {
                    std::slice::from_raw_parts_mut(
                        control_storage.as_mut_ptr().cast::<MaybeUninit<u8>>(),
                        std::mem::size_of_val(&control_storage),
                    )
                };
                let mut msg = MsgHdrMut::new()
                    .with_addr(&mut from)
                    .with_control(control_bytes)
                    .with_buffers(bufs);

                let received = socket.recvmsg(&mut msg).await?;
                // SAFETY: `MsgHdrMut` is `#[repr(transparent)]` over `libc::msghdr`
                let hdr: &libc::msghdr = unsafe { &*(&raw const msg as *const libc::msghdr) };
                let flags = hdr.msg_flags;
                let hlim = decode_hlim(hdr);
                (received, flags, hlim)
            };
            unsafe { buf.set_len(received) };

            // If the kernel had to drop ancillary data we can't trust the
            // hop-limit extraction below, so surface it instead of silently
            // returning a wrong value.
            if flags & libc::MSG_CTRUNC != 0 {
                return Err(std::io::Error::other(
                    "recvmsg control buffer truncated (MSG_CTRUNC)",
                ));
            }

            if received < ICMP_HEADER_SIZE + time::Timestamp::len() {
                continue;
            }
            let msg_type = buf[0];
            if msg_type != ICMP6_ECHO_REPLY {
                continue;
            }
            let reply_id = u16::from_be_bytes([buf[4], buf[5]]);
            if req_id != reply_id {
                continue;
            }
            let reply_seq = u16::from_be_bytes([buf[6], buf[7]]);
            if reply_seq != seq {
                continue;
            }
            // Validate the echoed timestamp matches what we sent. This is the
            // strongest filter against another raw-ICMP user on this host
            // happening to use the same id while pinging the same peer.
            let ts_end = ICMP_HEADER_SIZE + time::Timestamp::len();
            if buf[ICMP_HEADER_SIZE..ts_end] != sent_ts_bytes {
                continue;
            }
            let now = time::Timestamp::now();
            let src_addr = from.as_socket_ipv6().map(|s| *s.ip()).ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "recvmsg returned no source address",
                )
            })?;
            let reply_hlim = reply_hlim_opt.ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "reply missing IPV6_HOPLIMIT control message",
                )
            })?;
            let reply_ts =
                time::Timestamp::from(<[u8; 8]>::try_from(&buf[ICMP_HEADER_SIZE..ts_end]).unwrap());
            let rtt = now - reply_ts;
            return Ok(IcmpV6EchoReply {
                src_addr,
                len: received,
                seq: reply_seq,
                hlim: reply_hlim,
                rtt,
            });
        }
    });

    match overall.await {
        Ok(result) => result,
        Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "timed out",
        )),
    }
}

/// Generate a ping payload
#[allow(clippy::cast_possible_truncation)]
pub fn generate_payload(size: usize) -> Vec<u8> {
    (0..size).map(|i| (i % 256) as u8).collect()
}

/// Append an 8-byte ICMP/ICMPv6 echo-request header to `buf`.
///
/// The checksum field is written as `0x0000` and must be filled in by the
/// caller after the full packet is assembled.
fn add_icmp_header(buf: &mut Vec<u8>, typ: u8, id: u16, seq: u16) {
    // type
    buf.push(typ);
    // code
    buf.push(0);
    // checksum
    buf.push(0);
    buf.push(0);

    // id
    #[cfg(target_endian = "big")]
    {
        buf.push((id & 0xff) as u8);
        buf.push((id >> 8) as u8);
    }
    #[cfg(not(target_endian = "big"))]
    {
        buf.push((id >> 8) as u8);
        buf.push((id & 0xff) as u8);
    }

    // sequence
    #[cfg(target_endian = "big")]
    {
        buf.push((seq & 0xff) as u8);
        buf.push((seq >> 8) as u8);
    }
    #[cfg(not(target_endian = "big"))]
    {
        buf.push((seq >> 8) as u8);
        buf.push((seq & 0xff) as u8);
    }
}

/// Calculate Internet Checksum (RFC 1071)
fn calculate_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;

    // Sum up 16-bit words
    while i < data.len() - 1 {
        let word = u32::from(u16::from_be_bytes([data[i], data[i + 1]]));
        sum += word;
        i += 2;
    }

    // Add remaining byte if data length is odd
    if data.len() % 2 == 1 {
        sum += u32::from(data[data.len() - 1]) << 8;
    }

    // Fold 32-bit sum to 16 bits
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    // Return one's complement
    #[allow(clippy::cast_possible_truncation)]
    {
        !sum as u16
    }
}

/// Extract the `IP_TTL` ancillary value from a received message on a
/// `SOCK_DGRAM` (ping) socket.
///
/// When using ping sockets on Linux, the kernel delivers TTL via the
/// `IP_TTL` control message instead of in the IP header (which is stripped).
/// Returns `None` if no matching cmsg was present or the value did not fit
/// in a `u8`.
fn decode_ip_ttl(hdr: &libc::msghdr) -> Option<u8> {
    // SAFETY: `hdr` is a valid `*const msghdr` whose `msg_control` /
    // `msg_controllen` were written by the kernel during `recvmsg`. The
    // `CMSG_*` macros expect exactly this.
    let want_len = unsafe { libc::CMSG_LEN(std::mem::size_of::<libc::c_int>() as u32) } as usize;
    let mut p = unsafe { libc::CMSG_FIRSTHDR(hdr) };
    while !p.is_null() {
        let h = unsafe { &*p };
        if h.cmsg_level == libc::IPPROTO_IP
            && h.cmsg_type == libc::IP_TTL
            && h.cmsg_len as usize >= want_len
        {
            let mut value = MaybeUninit::<libc::c_int>::uninit();
            let ttl = unsafe {
                std::ptr::copy_nonoverlapping(
                    libc::CMSG_DATA(p),
                    value.as_mut_ptr().cast::<u8>(),
                    std::mem::size_of::<libc::c_int>(),
                );
                value.assume_init()
            };
            return u8::try_from(ttl).ok();
        }
        p = unsafe { libc::CMSG_NXTHDR(hdr, p) };
    }
    None
}

/// Extract the `IPV6_HOPLIMIT` ancillary value from a received message.
///
/// Walks the control-message chain attached to `hdr` using `CMSG_FIRSTHDR` /
/// `CMSG_NXTHDR`, which is the only portable way to interpret a `recvmsg(2)`
/// control buffer (it handles per-platform alignment and padding via the
/// kernel-provided macros). Returns `None` if no matching cmsg was present
/// or the value did not fit in a `u8`.
fn decode_hlim(hdr: &libc::msghdr) -> Option<u8> {
    // SAFETY: `hdr` is a valid `*const msghdr` whose `msg_control` /
    // `msg_controllen` were written by the kernel during `recvmsg`. The
    // `CMSG_*` macros expect exactly this.
    let want_len = unsafe { libc::CMSG_LEN(size_of::<libc::c_int>() as u32) } as usize;
    let mut p = unsafe { libc::CMSG_FIRSTHDR(hdr) };
    while !p.is_null() {
        let h = unsafe { &*p };
        if h.cmsg_level == libc::IPPROTO_IPV6
            && h.cmsg_type == libc::IPV6_HOPLIMIT
            && h.cmsg_len as usize >= want_len
        {
            let mut value = MaybeUninit::<libc::c_int>::uninit();
            let hlim = unsafe {
                std::ptr::copy_nonoverlapping(
                    libc::CMSG_DATA(p),
                    value.as_mut_ptr().cast::<u8>(),
                    size_of::<libc::c_int>(),
                );
                value.assume_init()
            };
            return u8::try_from(hlim).ok();
        }
        p = unsafe { libc::CMSG_NXTHDR(hdr, p) };
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_icmp_header_writes_8_bytes() {
        let mut buf = Vec::new();
        add_icmp_header(&mut buf, 8, 0, 0);
        assert_eq!(buf.len(), 8);
    }

    #[test]
    fn add_icmp_header_type_field() {
        let mut buf = Vec::new();
        add_icmp_header(&mut buf, 0x08, 0, 0);
        assert_eq!(buf[0], 0x08);
    }

    #[test]
    fn add_icmp_header_code_is_zero() {
        let mut buf = Vec::new();
        add_icmp_header(&mut buf, 8, 0xffff, 0xffff);
        assert_eq!(buf[1], 0);
    }

    #[test]
    fn add_icmp_header_id_big_endian() {
        let mut buf = Vec::new();
        add_icmp_header(&mut buf, 8, 0x1234, 0);
        assert_eq!(buf[4], 0x12);
        assert_eq!(buf[5], 0x34);
    }

    #[test]
    fn add_icmp_header_seq_big_endian() {
        let mut buf = Vec::new();
        add_icmp_header(&mut buf, 8, 0, 1);
        assert_eq!(buf[6], 0);
        assert_eq!(buf[7], 1);
    }

    #[test]
    fn add_icmp_header_appends_to_existing_content() {
        let mut buf = vec![0xde, 0xad];
        add_icmp_header(&mut buf, 8, 0, 0);
        assert_eq!(buf.len(), 10);
        assert_eq!(&buf[..2], &[0xde, 0xad]);
    }

    #[test]
    fn test_checksum() {
        // Test with known ICMP echo request header (checksum field zeroed)
        // Type=8, Code=0, Checksum=0, ID=0, Sequence=0
        let data = vec![0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let checksum = calculate_checksum(&data);
        // Expected: ~(0x0800) = 0xf7ff
        assert_eq!(checksum, 0xf7ff);

        // Test with odd length data
        let data = vec![0x00, 0x01, 0x02];
        let checksum = calculate_checksum(&data);
        // Sum: 0x0001 + 0x0200 = 0x0201, ~0x0201 = 0xfdfe
        assert_eq!(checksum, 0xfdfe);
    }

    #[test]
    fn test_compute_rtt_stats_empty() {
        let stats = compute_rtt_stats(&[]);
        assert_eq!(stats.rtt_min, Duration::ZERO);
        assert_eq!(stats.rtt_avg, Duration::ZERO);
        assert_eq!(stats.rtt_max, Duration::ZERO);
        assert_eq!(stats.rtt_std_dev, Duration::ZERO);
    }

    #[test]
    fn test_compute_rtt_stats_single() {
        let rtts = vec![Duration::from_millis(10)];
        let stats = compute_rtt_stats(&rtts);
        assert_eq!(stats.rtt_min, Duration::from_millis(10));
        assert_eq!(stats.rtt_avg, Duration::from_millis(10));
        assert_eq!(stats.rtt_max, Duration::from_millis(10));
        assert_eq!(stats.rtt_std_dev, Duration::ZERO);
    }

    #[test]
    fn test_compute_rtt_stats_multiple() {
        // 10ms, 20ms, 30ms  → avg=20ms, variance=66_666_666ns², std_dev=8164ns≈8μs
        let rtts = vec![
            Duration::from_millis(10),
            Duration::from_millis(20),
            Duration::from_millis(30),
        ];
        let stats = compute_rtt_stats(&rtts);
        assert_eq!(stats.rtt_min, Duration::from_millis(10));
        assert_eq!(stats.rtt_max, Duration::from_millis(30));
        assert_eq!(stats.rtt_avg, Duration::from_millis(20));
        // population std dev = sqrt(((10-20)²+(20-20)²+(30-20)²)/3) ms
        //                    = sqrt(200/3) ms ≈ 8.165ms
        let expected_std_dev_nanos: u64 = {
            let avg_ns: u64 = 20_000_000;
            let variance = [10_000_000u64, 20_000_000u64, 30_000_000u64]
                .iter()
                .map(|&d| {
                    let diff = d as i64 - avg_ns as i64;
                    (diff * diff) as u64
                })
                .sum::<u64>()
                / 3;
            variance.isqrt()
        };
        assert_eq!(
            stats.rtt_std_dev,
            Duration::from_nanos(expected_std_dev_nanos)
        );
    }

    #[test]
    fn test_compute_rtt_stats_identical() {
        let rtts = vec![
            Duration::from_millis(5),
            Duration::from_millis(5),
            Duration::from_millis(5),
        ];
        let stats = compute_rtt_stats(&rtts);
        assert_eq!(stats.rtt_min, Duration::from_millis(5));
        assert_eq!(stats.rtt_avg, Duration::from_millis(5));
        assert_eq!(stats.rtt_max, Duration::from_millis(5));
        assert_eq!(stats.rtt_std_dev, Duration::ZERO);
    }

    #[tokio::test]
    async fn test_send_icmp_echo_v4() {
        let sock = IcmpSocket::bind(Ipv4Addr::UNSPECIFIED).await.unwrap();
        sock.connect("127.0.0.1").await.unwrap();

        let payload = generate_payload(48);

        let reply = send_icmp_echo_v4(&sock, &payload, 1, Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(reply.src_addr, Ipv4Addr::LOCALHOST);
        assert_eq!(reply.len, 64);
        assert_eq!(reply.seq, 1);
        assert!(reply.ttl > 0);
        assert!(reply.rtt > Duration::ZERO);
    }

    #[tokio::test]
    async fn test_send_icmp_echo_v6() {
        let sock = IcmpSocket::bind(Ipv6Addr::UNSPECIFIED).await.unwrap();
        sock.connect("::1").await.unwrap();

        let payload = [];

        let reply = send_icmp_echo_v6(&sock, &payload, 1, Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(reply.src_addr, Ipv6Addr::LOCALHOST);
        assert_eq!(reply.len, 16);
        assert_eq!(reply.seq, 1);
        assert!(reply.hlim > 0);
        assert!(reply.rtt > Duration::ZERO);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn test_send_icmp_echo_v6_send() {
        let reply = tokio::task::spawn(async {
            let sock = IcmpSocket::bind(Ipv6Addr::UNSPECIFIED).await.unwrap();
            sock.connect("::1").await.unwrap();

            let payload = [];

            let reply = send_icmp_echo_v6(&sock, &payload, 1, Duration::from_secs(5))
                .await
                .unwrap();
            reply
        })
        .await
        .unwrap();

        assert_eq!(reply.src_addr, Ipv6Addr::LOCALHOST);
        assert_eq!(reply.len, 16);
        assert_eq!(reply.seq, 1);
        assert!(reply.hlim > 0);
        assert!(reply.rtt > Duration::ZERO);
    }
}

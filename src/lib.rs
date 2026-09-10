#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
// Pedantic-lint allows scoped to the whole crate:
// * `doc_markdown` - backticking `ICMPv4`/`ICMPv6` in every doc comment
//   is low-signal.
// * `missing_errors_doc` / `missing_panics_doc` - most public functions wrap
//   `std::io` and the only `unwrap`s are on length-checked slice conversions.
// * `must_use_candidate` - too noisy for small helpers.
// * The cast lints - packet parsing and stats math narrow integer types
//   after explicit range checks.
#![allow(
    clippy::doc_markdown,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss
)]

/// Conversion from various inputs (IP addresses, hostnames) into
/// [`HostAddr`], preserving IPv6 scope (zone) identifiers.
pub mod addr;
mod net;
mod stats;
pub(crate) mod time;

use std::{
    future::Future,
    mem::MaybeUninit,
    net::{Ipv4Addr, Ipv6Addr, SocketAddrV6},
    sync::{
        atomic::{AtomicU16, Ordering},
        LazyLock,
    },
    time::Duration,
};
// `SocketAddrV4` is used only by the Linux/Android header-stripping DGRAM
// receive path.
#[cfg(any(target_os = "linux", target_os = "android"))]
use std::net::SocketAddrV4;

pub use addr::{HostAddr, ToHostAddr};
pub use net::IcmpSocket;
use net::SocketType;
use socket2::{MaybeUninitSlice, MsgHdrMut, SockAddr};
use tokio::time::timeout;

use crate::stats::compute_rtt_stats;

const IP_HEADER_SIZE: usize = 20;
const ICMP_HEADER_SIZE: usize = 8;

const ICMP_ECHO_REQUEST: u8 = 8;
const ICMP_ECHO_REPLY: u8 = 0;
const ICMP6_ECHO_REQUEST: u8 = 128;
const ICMP6_ECHO_REPLY: u8 = 129;

/// `ReplyTimedOut` means the reply deadline expired after a successful send.
/// All other errors remain `Err` values.
#[derive(Debug)]
enum ProbeOutcome<T> {
    Reply(T),
    ReplyTimedOut,
}

impl<T> ProbeOutcome<T> {
    fn map<U>(self, f: impl FnOnce(T) -> U) -> ProbeOutcome<U> {
        match self {
            Self::Reply(reply) => ProbeOutcome::Reply(f(reply)),
            Self::ReplyTimedOut => ProbeOutcome::ReplyTimedOut,
        }
    }

    /// Convert to the public low-level timeout representation.
    fn into_result(self) -> std::io::Result<T> {
        match self {
            Self::Reply(reply) => Ok(reply),
            Self::ReplyTimedOut => Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "timed out",
            )),
        }
    }
}

/// Send one complete datagram before starting the reply deadline.
async fn send_request(socket: &IcmpSocket, buf: &[u8]) -> std::io::Result<()> {
    let sent = socket.send(buf).await?;
    if sent != buf.len() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::WriteZero,
            "socket did not send the complete ICMP request",
        ));
    }
    Ok(())
}

/// Called after a successful send. A deadline expiry maps to `ReplyTimedOut`;
/// receive errors propagate unchanged.
async fn wait_for_reply<T>(
    tout: Duration,
    receive: impl Future<Output = std::io::Result<T>>,
) -> std::io::Result<ProbeOutcome<T>> {
    match timeout(tout, receive).await {
        Ok(result) => result.map(ProbeOutcome::Reply),
        Err(_) => Ok(ProbeOutcome::ReplyTimedOut),
    }
}

// Seed `REQ_ID` from PID mixed with the low bits of the current wall-clock
// time, spreading starting points around the 16-bit space.
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
/// Packet counts and round-trip time statistics across all replied probes.
#[derive(Clone, Copy, Debug)]
pub struct PingStats {
    /// Number of complete ICMP echo requests accepted by the local socket,
    /// including requests whose reply deadline expired.
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
/// Selects ICMPv4 or ICMPv6 from the resolved address family of `dest`.
/// The socket is bound to `src` (typically `UNSPECIFIED`) before connecting.
/// IPv6 scope (zone) identifiers are preserved end to end.
///
/// # Arguments
///
/// * `src` - Local address to bind the raw socket to (e.g. `Ipv4Addr::UNSPECIFIED`).
/// * `dest` - Destination host; any type that implements [`ToHostAddr`] is accepted
///   (IP address, scoped IPv6 literal such as `"fe80::1%eth0"`, hostname string, etc.).
///   Note: [`IpAddr`](std::net::IpAddr) and [`Ipv6Addr`] cannot carry a scope id -
///   use a `&str` or `(Ipv6Addr, u32)` tuple for link-local destinations.
/// * `count` - Number of ICMP echo requests to send.
/// * `interval` - How long to wait between sending successive echo requests.
/// * `size` - Total ICMP payload size in bytes. The first 8 bytes are reserved
///   for an internal timestamp; must be greater than 8.
///
/// # Errors
///
/// * [`std::io::ErrorKind::InvalidInput`] - `size` is 8 or fewer bytes.
/// * Address resolution, socket creation, binding, connecting, sending, or
///   receiving errors are returned immediately, without partial statistics.
/// * Expiry of a probe's reply deadline after a successful send is counted
///   as packet loss. OS-reported I/O errors are propagated even if their kind
///   is [`std::io::ErrorKind::TimedOut`].
pub async fn ping<S: ToHostAddr, D: ToHostAddr>(
    src: S,
    dest: D,
    count: u32,
    interval: Duration,
    size: u16,
) -> std::io::Result<PingStats> {
    let dest = dest.to_host_addr().await?;
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

    run_probes(count, interval, |seq| {
        let socket = &socket;
        let payload = &payload;
        async move {
            match dest {
                HostAddr::V4(_) => probe_icmp_echo_v4(socket, payload, seq, tout)
                    .await
                    .map(|outcome| outcome.map(|r| r.rtt)),
                HostAddr::V6 { .. } => probe_icmp_echo_v6(socket, payload, seq, tout)
                    .await
                    .map(|outcome| outcome.map(|r| r.rtt)),
            }
        }
    })
    .await
}

/// Aggregate completed probes. A reply deadline expiry counts as packet loss;
/// any other error aborts the run instead of returning partial statistics.
async fn run_probes<F, Fut>(
    count: u32,
    interval: Duration,
    mut probe: F,
) -> std::io::Result<PingStats>
where
    F: FnMut(u16) -> Fut,
    Fut: Future<Output = std::io::Result<ProbeOutcome<Duration>>>,
{
    let mut packets_tx: u32 = 0;
    let mut packets_rx: u32 = 0;
    let mut rtts: Vec<Duration> = Vec::with_capacity(count as usize);

    for seq in 1..=count {
        let outcome = probe(seq as u16).await?;
        packets_tx += 1;
        if let ProbeOutcome::Reply(rtt) = outcome {
            packets_rx += 1;
            rtts.push(rtt);
        }
        if seq < count {
            tokio::time::sleep(interval).await;
        }
    }

    let stats = compute_rtt_stats(&rtts);
    Ok(PingStats {
        packets_tx,
        packets_rx,
        rtt_min: stats.rtt_min,
        rtt_avg: stats.rtt_avg,
        rtt_max: stats.rtt_max,
        rtt_std_dev: stats.rtt_std_dev,
    })
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
/// * `socket` - A bound and connected [`IcmpSocket`] for IPv4.
/// * `payload` - Application data appended after the ICMP header and timestamp.
/// * `seq` - Sequence number embedded in the ICMP echo request.
/// * `tout` - Maximum time to wait for a matching reply before returning
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
    probe_icmp_echo_v4(socket, payload, seq, tout)
        .await?
        .into_result()
}

async fn probe_icmp_echo_v4(
    socket: &IcmpSocket,
    payload: &[u8],
    seq: u16,
    tout: Duration,
) -> std::io::Result<ProbeOutcome<IcmpEchoReply>> {
    let sock_type = socket.sock_type();
    let ts_len = time::Timestamp::len();

    // On Linux `SOCK_DGRAM` sockets, the request id is the socket's
    // pre-bound ident when available.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    let req_id = match socket.dgram_ident() {
        Some(id) => id,
        None => REQ_ID.fetch_add(1, Ordering::Relaxed),
    };
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    let req_id = REQ_ID.fetch_add(1, Ordering::Relaxed);

    // On Linux/Android, `SOCK_DGRAM` sockets strip the IP header and deliver
    // TTL via an `IP_TTL` control message. On other platforms the full IP
    // header is present, including on Apple `SOCK_DGRAM` sockets.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    let dgram_strips_ip_header = true;
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    let dgram_strips_ip_header = false;
    let use_dgram_recv = sock_type == SocketType::Dgram && dgram_strips_ip_header;

    // Single buffer for send and receive. When received data includes the IP
    // header (`Raw` sockets and Apple `DGRAM` sockets), add 20 bytes.
    let icmp_len = ICMP_HEADER_SIZE + ts_len + payload.len();
    let buf_cap = if use_dgram_recv {
        icmp_len
    } else {
        IP_HEADER_SIZE + icmp_len
    };
    let mut buf: Vec<u8> = Vec::with_capacity(buf_cap);

    add_icmp_header(&mut buf, ICMP_ECHO_REQUEST, req_id, seq);
    let sent_ts_bytes = time::Timestamp::now().as_bytes();
    buf.extend_from_slice(&sent_ts_bytes);
    buf.extend_from_slice(payload);

    let checksum = calculate_checksum(&buf);
    buf[2] = (checksum >> 8) as u8;
    buf[3] = (checksum & 0xff) as u8;

    send_request(socket, &buf).await?;

    // On header-stripping DGRAM sockets, receive via recvmsg to read TTL from
    // the `IP_TTL` cmsg. Otherwise recv and parse the IP header.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    if use_dgram_recv {
        return send_icmp_echo_v4_dgram(socket, req_id, seq, sent_ts_bytes, buf, tout).await;
    }

    send_icmp_echo_v4_raw(socket, req_id, seq, sent_ts_bytes, buf, tout).await
}

/// Receive path for `SOCK_RAW`: IP header is present in the data.
async fn send_icmp_echo_v4_raw(
    socket: &IcmpSocket,
    req_id: u16,
    seq: u16,
    sent_ts_bytes: [u8; 8],
    mut buf: Vec<u8>,
    tout: Duration,
) -> std::io::Result<ProbeOutcome<IcmpEchoReply>> {
    let ts_len = time::Timestamp::len();

    wait_for_reply(tout, async {
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
    })
    .await
}

/// Receive path for header-stripping `SOCK_DGRAM` ping sockets (Linux/Android):
/// no IP header; TTL via `IP_TTL` cmsg.
#[cfg(any(target_os = "linux", target_os = "android"))]
async fn send_icmp_echo_v4_dgram(
    socket: &IcmpSocket,
    req_id: u16,
    seq: u16,
    sent_ts_bytes: [u8; 8],
    mut buf: Vec<u8>,
    tout: Duration,
) -> std::io::Result<ProbeOutcome<IcmpEchoReply>> {
    let ts_len = time::Timestamp::len();

    // Source address arrives in `msg_name`; TTL arrives in an `IP_TTL`
    // control message. Storage exceeds `CMSG_SPACE(sizeof(int))` with `u64`
    // alignment; `MSG_CTRUNC` is checked below.
    let mut control_storage: [MaybeUninit<u64>; 8] = [MaybeUninit::uninit(); 8];
    let mut from: SockAddr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0u16).into();

    wait_for_reply(tout, async {
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
            // Without an `IP_TTL` cmsg, fall back to 0 instead of dropping
            // the reply.
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
    })
    .await
}

/// Send an ICMPv6 echo request and wait for the matching echo reply.
///
/// # Arguments
///
/// * `socket` - A bound and connected [`IcmpSocket`] for IPv6.
/// * `payload` - Application data appended after the ICMPv6 header and timestamp.
/// * `seq` - Sequence number embedded in the ICMPv6 echo request.
/// * `tout` - Maximum time to wait for a matching reply before returning
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
    probe_icmp_echo_v6(socket, payload, seq, tout)
        .await?
        .into_result()
}

async fn probe_icmp_echo_v6(
    socket: &IcmpSocket,
    payload: &[u8],
    seq: u16,
    tout: Duration,
) -> std::io::Result<ProbeOutcome<IcmpV6EchoReply>> {
    let mut buf: Vec<u8> =
        Vec::with_capacity(ICMP_HEADER_SIZE + time::Timestamp::len() + payload.len());
    // On Linux `SOCK_DGRAM` sockets, the request id is the socket's
    // pre-bound ident when available.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    let req_id = match socket.dgram_ident() {
        Some(id) => id,
        None => REQ_ID.fetch_add(1, Ordering::Relaxed),
    };
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    let req_id = REQ_ID.fetch_add(1, Ordering::Relaxed);
    add_icmp_header(&mut buf, ICMP6_ECHO_REQUEST, req_id, seq);
    let sent_ts_bytes = time::Timestamp::now().as_bytes();
    buf.extend_from_slice(&sent_ts_bytes);
    buf.extend_from_slice(payload);

    send_request(socket, &buf).await?;

    let mut from: SockAddr = SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0u16, 0, 0).into();

    // Ancillary data buffer for `IPV6_HOPLIMIT`. Sized above
    // `CMSG_SPACE(sizeof(int))` (about 20-24 bytes) with `u64` alignment.
    // `MSG_CTRUNC` is checked below.
    let mut control_storage: [MaybeUninit<u64>; 8] = [MaybeUninit::uninit(); 8];

    wait_for_reply(tout, async {
        loop {
            buf.clear();

            // Receive into `buf` + `control_storage` via a `MsgHdrMut`. The
            // wrapper drops at the end of this block, releasing borrows of
            // `buf` / `from` / `control_storage`.
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

            // On truncated ancillary data, return an error rather than a
            // possibly wrong hop limit.
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
            // The echoed timestamp must match the sent timestamp.
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
    })
    .await
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
    buf.extend_from_slice(&id.to_be_bytes());

    // sequence
    buf.extend_from_slice(&seq.to_be_bytes());
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

/// Extract the `IP_TTL` ancillary value from a received message.
///
/// Returns `None` when no matching cmsg is present or the value does not fit
/// in a `u8`.
#[cfg(any(target_os = "linux", target_os = "android"))]
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
/// Returns `None` when no matching cmsg is present or the value does not fit
/// in a `u8`.
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

    #[tokio::test]
    async fn reply_deadline_preserves_public_timeout_behavior() {
        let outcome = wait_for_reply(
            Duration::ZERO,
            std::future::pending::<std::io::Result<()>>(),
        )
        .await
        .unwrap();
        assert!(matches!(outcome, ProbeOutcome::ReplyTimedOut));
        let error = outcome.into_result().unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        assert_eq!(error.raw_os_error(), None);
    }

    #[tokio::test]
    async fn reply_deadline_preserves_successful_reply() {
        let outcome = wait_for_reply(
            Duration::from_secs(1),
            std::future::ready(Ok(Duration::from_millis(10))),
        )
        .await
        .unwrap();
        assert_eq!(outcome.into_result().unwrap(), Duration::from_millis(10));
    }

    #[tokio::test]
    async fn reply_deadline_does_not_swallow_receive_errors() {
        for code in [libc::ETIMEDOUT, libc::ECONNREFUSED] {
            let error = wait_for_reply(
                Duration::from_secs(1),
                std::future::ready::<std::io::Result<()>>(Err(std::io::Error::from_raw_os_error(
                    code,
                ))),
            )
            .await
            .unwrap_err();
            assert_eq!(error.raw_os_error(), Some(code));
        }

        let error = wait_for_reply(
            Duration::from_secs(1),
            std::future::ready::<std::io::Result<()>>(Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid reply metadata",
            ))),
        )
        .await
        .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(error.to_string(), "invalid reply metadata");
    }

    #[tokio::test]
    async fn run_probes_counts_replies_and_deadlines_separately() {
        let mut sequences = Vec::new();
        let stats = run_probes(3, Duration::ZERO, |seq| {
            sequences.push(seq);
            std::future::ready(Ok(match seq {
                1 => ProbeOutcome::Reply(Duration::from_millis(10)),
                2 => ProbeOutcome::ReplyTimedOut,
                3 => ProbeOutcome::Reply(Duration::from_millis(30)),
                _ => panic!("unexpected probe"),
            }))
        })
        .await
        .unwrap();

        assert_eq!(sequences, [1, 2, 3]);
        assert_eq!(stats.packets_tx, 3);
        assert_eq!(stats.packets_rx, 2);
        assert_eq!(stats.rtt_min, Duration::from_millis(10));
        assert_eq!(stats.rtt_avg, Duration::from_millis(20));
        assert_eq!(stats.rtt_max, Duration::from_millis(30));
        assert_eq!(stats.rtt_std_dev, Duration::from_millis(10));
    }

    #[tokio::test]
    async fn run_probes_all_deadlines_expire() {
        let stats = run_probes(3, Duration::ZERO, |_| {
            wait_for_reply(
                Duration::ZERO,
                std::future::pending::<std::io::Result<Duration>>(),
            )
        })
        .await
        .unwrap();

        assert_eq!(stats.packets_tx, 3);
        assert_eq!(stats.packets_rx, 0);
        assert_eq!(stats.rtt_min, Duration::ZERO);
        assert_eq!(stats.rtt_avg, Duration::ZERO);
        assert_eq!(stats.rtt_max, Duration::ZERO);
        assert_eq!(stats.rtt_std_dev, Duration::ZERO);
    }

    #[tokio::test]
    async fn run_probes_aborts_on_io_errors_without_partial_statistics() {
        for code in [libc::EMSGSIZE, libc::ENETUNREACH, libc::ETIMEDOUT] {
            for fail_at in [1, 3] {
                let mut calls = 0;
                let error = run_probes(5, Duration::ZERO, |_| {
                    calls += 1;
                    std::future::ready(if calls == fail_at {
                        Err(std::io::Error::from_raw_os_error(code))
                    } else if calls == 1 {
                        Ok(ProbeOutcome::Reply(Duration::from_millis(10)))
                    } else {
                        Ok(ProbeOutcome::ReplyTimedOut)
                    })
                })
                .await
                .unwrap_err();

                assert_eq!(calls, fail_at, "must not send another probe after an error");
                assert_eq!(error.raw_os_error(), Some(code));
            }
        }
    }

    #[tokio::test]
    async fn run_probes_zero_count_sends_nothing() {
        let mut calls = 0;
        let stats = run_probes(0, Duration::ZERO, |_| {
            calls += 1;
            std::future::ready(Ok(ProbeOutcome::ReplyTimedOut))
        })
        .await
        .unwrap();

        assert_eq!(calls, 0);
        assert_eq!(stats.packets_tx, 0);
        assert_eq!(stats.packets_rx, 0);
        assert_eq!(stats.rtt_avg, Duration::ZERO);
    }

    #[tokio::test]
    async fn test_send_icmp_errors_precede_reply_deadlines() {
        // With no peer, the send fails even when the reply timeout is zero.
        let v4 = IcmpSocket::bind(Ipv4Addr::LOCALHOST).await.unwrap();
        let error = send_icmp_echo_v4(&v4, &[], 1, Duration::ZERO)
            .await
            .unwrap_err();
        assert!(error.raw_os_error().is_some());

        let v6 = IcmpSocket::bind(Ipv6Addr::LOCALHOST).await.unwrap();
        let error = send_icmp_echo_v6(&v6, &[], 1, Duration::ZERO)
            .await
            .unwrap_err();
        assert!(error.raw_os_error().is_some());
    }

    #[tokio::test]
    async fn test_send_icmp_ping_propagates_oversized_send_errors() {
        for host in ["127.0.0.1", "::1"] {
            let error = ping(host, host, 1, Duration::ZERO, u16::MAX)
                .await
                .unwrap_err();
            assert_eq!(error.raw_os_error(), Some(libc::EMSGSIZE));
        }
    }

    #[tokio::test]
    async fn test_send_icmp_ping_loopback_counts() {
        for host in ["127.0.0.1", "::1"] {
            let stats = ping(host, host, 3, Duration::ZERO, 64).await.unwrap();
            assert_eq!(stats.packets_tx, 3);
            assert_eq!(stats.packets_rx, 3);
            assert!(stats.rtt_min > Duration::ZERO);
            assert!(stats.rtt_min <= stats.rtt_avg);
            assert!(stats.rtt_avg <= stats.rtt_max);
        }
    }

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
        // 10ms, 20ms, 30ms -> mean 20ms, population std dev sqrt(200/3) ms.
        let rtts = vec![
            Duration::from_millis(10),
            Duration::from_millis(20),
            Duration::from_millis(30),
        ];
        let stats = compute_rtt_stats(&rtts);
        assert_eq!(stats.rtt_min, Duration::from_millis(10));
        assert_eq!(stats.rtt_max, Duration::from_millis(30));
        assert_eq!(stats.rtt_avg, Duration::from_millis(20));
        assert_eq!(stats.rtt_std_dev, Duration::from_nanos(8_164_966));
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

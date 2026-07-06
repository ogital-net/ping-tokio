# ping-tokio

Async ICMP ping library for Rust, built on [Tokio](https://tokio.rs/).

Supports ICMPv4 and ICMPv6. On Linux and macOS it can run **without elevated
privileges** by using unprivileged ICMP datagram sockets, automatically falling
back to raw sockets where required. See [Permissions](#permissions) for details.

---

## Library

### Cargo.toml

```toml
[dependencies]
ping-tokio = "0.4"
tokio = { version = "1", features = ["rt", "macros"] }
```

### High-level API

`ping` resolves the destination, opens the appropriate raw socket, sends `count` ICMP echo requests, and returns aggregate statistics.

```rust,no_run
use std::time::Duration;
use ping_tokio::ping;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let stats = ping("0.0.0.0", "8.8.8.8", 5, Duration::from_secs(1), 64).await?;
    println!(
        "{} tx / {} rx, rtt min/avg/max = {:.3}/{:.3}/{:.3} ms",
        stats.packets_tx,
        stats.packets_rx,
        stats.rtt_min.as_secs_f64() * 1000.0,
        stats.rtt_avg.as_secs_f64() * 1000.0,
        stats.rtt_max.as_secs_f64() * 1000.0,
    );
    Ok(())
}
```

`ping` accepts any type that implements `ToIpAddr` for both `src` and `dest`: `Ipv4Addr`, `Ipv6Addr`, `IpAddr`, `&str`, or `String`.

The `size` parameter is the total ICMP payload size in bytes. The first 8 bytes of the payload are reserved for an internal timestamp used to measure RTT; `size` must therefore be greater than 8.

#### PingStats fields

| Field          | Description                                      |
|----------------|--------------------------------------------------|
| `packets_tx`   | Number of echo requests sent                     |
| `packets_rx`   | Number of echo replies received                  |
| `rtt_min`      | Minimum RTT across received replies              |
| `rtt_avg`      | Mean RTT                                         |
| `rtt_max`      | Maximum RTT                                      |
| `rtt_std_dev`  | Population standard deviation of RTT samples     |

Probes that time out are counted in `packets_tx` but not `packets_rx`. They do not cause the function to return an error.

---

### Low-level API

For per-probe control, use `IcmpSocket` together with `send_icmp_echo_v4` / `send_icmp_echo_v6` directly.

```rust,no_run
use std::{net::Ipv4Addr, time::Duration};
use ping_tokio::{IcmpSocket, generate_payload, send_icmp_echo_v4};

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let sock = IcmpSocket::bind(Ipv4Addr::UNSPECIFIED).await?;
    sock.connect("8.8.8.8").await?;

    let payload = generate_payload(56); // 56 bytes of application data
    let reply = send_icmp_echo_v4(&sock, &payload, 1, Duration::from_secs(5)).await?;

    println!(
        "reply from {}: seq={} ttl={} rtt={:.3} ms",
        reply.src_addr,
        reply.seq,
        reply.ttl,
        reply.rtt.as_secs_f64() * 1000.0
    );
    Ok(())
}
```

`send_icmp_echo_v4` / `send_icmp_echo_v6` each:
1. Build and send an ICMP echo request with an embedded timestamp.
2. Loop reading from the socket, filtering by type, ID, and sequence, until a matching reply arrives or the timeout elapses.
3. Return the reply metadata on success, or `ErrorKind::TimedOut` on timeout.

---

## Binary (`ping`)

A command-line ping utility is included behind the `bin` feature flag.

### Build

```sh
cargo build --release --features bin
```

The binary is placed at `target/release/ping`.

### Usage

```text
ping <destination> [-c count] [-s size] [-W timeout_secs]
```

| Flag | Default | Description                          |
|------|---------|--------------------------------------|
| `-c` | 5       | Number of echo requests to send      |
| `-s` | 56      | Total ICMP payload size (must be > 8)|
| `-W` | 1       | Per-probe timeout in seconds         |

### Example output

```text
$ ping 127.0.0.1 -c 5 -s 1500
PING 127.0.0.1 (127.0.0.1): 1500 data bytes
1508 bytes from 127.0.0.1: icmp_seq=0 ttl=64 time=0.106 ms
1508 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.139 ms
1508 bytes from 127.0.0.1: icmp_seq=2 ttl=64 time=0.102 ms
1508 bytes from 127.0.0.1: icmp_seq=3 ttl=64 time=0.152 ms
1508 bytes from 127.0.0.1: icmp_seq=4 ttl=64 time=0.132 ms

--- 127.0.0.1 ping statistics ---
5 packets transmitted, 5 packets received, 0.0% packet loss
round-trip min/avg/max/stddev = 0.102/0.126/0.152/0.019 ms
```

The reported byte count (`1508`) is ICMP header (8) + payload (`size`).

---

## Permissions

This crate picks the least-privileged socket type available on each platform,
so in the common case **no elevated privileges are required**.

**Linux** — an unprivileged ICMP datagram socket (`SOCK_DGRAM` +
`IPPROTO_ICMP`/`IPPROTO_ICMPV6`) is tried first. This works out of the box as
long as your group id is within the kernel's `net.ipv4.ping_group_range`
sysctl (on most distributions this already covers all users):

```sh
# Check the currently allowed group range (default on many distros: 0 .. 2^31-1)
cat /proc/sys/net/ipv4/ping_group_range

# Widen it for the current session if needed (e.g. allow all groups)
sudo sysctl -w net.ipv4.ping_group_range="0 2147483647"
```

If the ping socket is denied (group not in range, or the kernel lacks
support), the crate automatically falls back to a raw socket (`SOCK_RAW`),
which requires `CAP_NET_RAW`:

```sh
sudo setcap cap_net_raw+ep target/release/ping
```

Or simply run with `sudo`.

**macOS** — an unprivileged ICMP datagram socket is used automatically when
not running as root (matching the system `ping(8)` / `ping6(8)`), so no
special setup is needed. Running as root uses a raw socket.

**Other BSDs / Unix** — raw sockets are used, which require running as root or
`sudo`.

---

## Platform support

CI exercises the crate on **Linux** and **macOS**. Most Unix-like platforms
that provide POSIX raw sockets and the `recvmsg` / `cmsghdr` ancillary-data
APIs (the BSDs, illumos, etc.) are expected to work, though they are not
covered by automated tests. **Windows is not supported** — the implementation
relies on POSIX socket semantics (`AsyncFd`, `IPV6_RECVHOPLIMIT`, `CMSG_*`)
that have no direct Windows equivalent.

---

## Implementation notes

This implementation derives from BSD `ping`, originally written by Mike Muuss in 1983, and follows several of its design choices:

- **Embedded timestamps.** The send time is written into the first 8 bytes of the echo payload and read back from the reply. This avoids maintaining a hashtable (or similar side data) keyed on sequence number to compute RTT — the timing information travels with the packet itself.
- **Unprivileged ICMP sockets with a raw-socket fallback.** On Linux and
  macOS the crate first opens an unprivileged ICMP datagram socket
  (`SOCK_DGRAM` + `IPPROTO_ICMP`/`IPPROTO_ICMPV6`) so it can run without
  `CAP_NET_RAW` or root. If the kernel denies it (e.g. the group is outside
  `net.ipv4.ping_group_range`, or on other Unix platforms), it transparently
  falls back to a raw socket (`SOCK_RAW`). This mirrors the strategy used by
  iputils `ping(8)`.
- **Datagram vs. raw receive paths.** On a raw socket the kernel delivers the
  full IP packet and the reply TTL is read from the IP header. On a datagram
  ping socket the IP header is stripped, so the TTL is recovered from an
  `IP_TTL` ancillary control message (`IP_RECVTTL`) instead. The Linux kernel
  also derives the ICMP echo identifier from the socket's bound port on
  datagram sockets, so the crate binds a unique port per socket and matches
  replies against it.
- **IPv6 hop limit exposure.** For IPv6 the received hop limit is not present in the ICMPv6 payload, so the socket is configured with `IPV6_RECVHOPLIMIT` and the value is recovered from the `recvmsg` ancillary data (`cmsghdr` / `CMSG_*`). This mirrors `ping6` and surfaces a TTL-equivalent field for network diagnostics.

---

## Dependencies

| Crate      | Purpose                                              |
|------------|------------------------------------------------------|
| `tokio`    | Async runtime, `AsyncFd` for non-blocking socket I/O |
| `socket2`  | Raw socket creation and `recvmsg` for ancillary data |
| `libc`     | `cmsghdr` / `CMSG_*` for IPv6 hop-limit extraction   |

## Minimum Rust version

1.84

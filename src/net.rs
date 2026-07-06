use std::mem::MaybeUninit;
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::fd::AsRawFd;

use socket2::{Domain, MsgHdrMut, Protocol, Socket, Type};
use tokio::io::unix::{AsyncFd, AsyncFdReadyGuard};
use tokio::io::Interest;

use crate::addr::ToIpAddr;

/// Whether the ICMP socket was created via `SOCK_DGRAM` or `SOCK_RAW`.
///
/// This determines how received data is interpreted:
/// - `Raw`: The kernel delivers the full IP packet; an IP header precedes the
///   ICMP message. TTL is read from the IP header directly.
/// - `Dgram`: The kernel strips the IP header; the ICMP message starts at
///   byte 0. TTL must be retrieved via `IP_RECVTTL` / `IP_TTL` control
///   messages.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SocketType {
    Raw,
    Dgram,
}

/// The result of creating an ICMP socket: the raw socket plus its type.
struct NewSocket {
    socket: Socket,
    sock_type: SocketType,
}

/// Create a socket suitable for ICMP communication.
///
/// On **Linux**, tries `SOCK_DGRAM` (ping socket) first. If that fails with
/// `EACCES` (user not in `net.ipv4.ping_group_range`), `EAFNOSUPPORT`, or
/// `EPROTONOSUPPORT`, falls back to `SOCK_RAW`. This mirrors the strategy
/// used by iputils `ping(8)`.
///
/// On **Apple platforms**, uses `SOCK_DGRAM` when running without root
/// privileges and `SOCK_RAW` when running as root — matching macOS
/// `ping(8)` and `ping6(8)`. `SOCK_DGRAM` with `IPPROTO_ICMP`/`IPPROTO_ICMPV6`
/// works for all users on macOS.
///
/// On all other platforms, `SOCK_RAW` is used unconditionally.
fn new_icmp_socket(domain: Domain, protocol: Protocol) -> std::io::Result<NewSocket> {
    #[cfg(any(target_os = "linux", target_os = "android",))]
    {
        let sock = Socket::new(domain, Type::DGRAM, Some(protocol));
        match sock {
            Ok(socket) => {
                return Ok(NewSocket {
                    socket,
                    sock_type: SocketType::Dgram,
                });
            }
            Err(e) => {
                let fallback = matches!(
                    e.raw_os_error(),
                    Some(libc::EACCES | libc::EAFNOSUPPORT | libc::EPROTONOSUPPORT)
                );
                if fallback {
                    let raw = Socket::new(domain, Type::RAW, Some(protocol))?;
                    return Ok(NewSocket {
                        socket: raw,
                        sock_type: SocketType::Raw,
                    });
                }
                return Err(e);
            }
        }
    }

    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "tvos",
        target_os = "watchos",
        target_os = "visionos",
    ))]
    if !is_root() {
        return Ok(NewSocket {
            socket: Socket::new(domain, Type::DGRAM, Some(protocol))?,
            sock_type: SocketType::Dgram,
        });
    }

    // All platforms: fallback / default path uses SOCK_RAW.
    #[cfg_attr(
        any(target_os = "linux", target_os = "android",),
        allow(unreachable_code)
    )]
    {
        Ok(NewSocket {
            socket: Socket::new(domain, Type::RAW, Some(protocol))?,
            sock_type: SocketType::Raw,
        })
    }
}

/// Returns `true` if the current process is running as root (uid 0).
#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "tvos",
    target_os = "watchos",
    target_os = "visionos",
))]
fn is_root() -> bool {
    // SAFETY: `getuid()` is always safe to call.
    unsafe { libc::getuid() == 0 }
}

/// Asynchronous, non-blocking ICMP socket.
///
/// Wraps a [`socket2::Socket`] in [`tokio::io::unix::AsyncFd`] so that send
/// and receive operations integrate with the Tokio runtime. Supports both
/// ICMPv4 and ICMPv6; the protocol is selected by the address family of the
/// bind address.
///
/// # Platform-specific privileges
///
/// Creating an `IcmpSocket` for ICMP typically requires elevated privileges:
///
/// | Platform | ICMPv4 | ICMPv6 |
/// |---|---|---|
/// | **macOS** | No privileges needed (`SOCK_DGRAM`) | No privileges needed (`SOCK_DGRAM`) |
/// | **Linux** | `net.ipv4.ping_group_range` or `CAP_NET_RAW` | Same |
/// | **FreeBSD** / **NetBSD** / **OpenBSD** | Root | Root |
///
/// On **Apple platforms**, this library automatically uses a datagram
/// (`SOCK_DGRAM`) socket when not running as root — the same approach used
/// by macOS `ping(8)` and `ping6(8)`. When running as root, `SOCK_RAW` is
/// used.
///
/// On **Linux**, a `SOCK_DGRAM` (ping) socket is tried first. If the user's
/// group is not in the kernel's `net.ipv4.ping_group_range` sysctl, the
/// kernel returns `EACCES` and the library falls back to `SOCK_RAW` (which
/// requires `CAP_NET_RAW`). This mirrors the strategy used by iputils
/// `ping(8)`.
pub struct IcmpSocket {
    io: AsyncFd<Socket>,
    sock_type: SocketType,
    /// On `SOCK_DGRAM` (ping) sockets on Linux, the kernel uses the bound
    /// port as the ICMP echo identifier. This field stores that port so the
    /// receive path can check it. `None` on `SOCK_RAW` sockets where the
    /// identifier is written directly into the ICMP packet header.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    dgram_ident: Option<u16>,
}

impl IcmpSocket {
    /// Create a new ICMP socket bound to `addr`.
    ///
    /// The address family of `addr` (after resolution) determines whether an
    /// ICMPv4 or ICMPv6 socket is created. The socket is placed in
    /// non-blocking mode and registered with the current Tokio runtime.
    ///
    /// On **Apple platforms** when not running as root, uses `SOCK_DGRAM` for
    /// both ICMPv4 and ICMPv6 (matching macOS `ping(8)` / `ping6(8)`).
    /// When running as root, `SOCK_RAW` is used.
    ///
    /// On **Linux**, a `SOCK_DGRAM` (ping) socket is tried first, with
    /// automatic fallback to `SOCK_RAW` if the kernel denies the ping socket
    /// (e.g. the user is not in `net.ipv4.ping_group_range`).
    pub async fn bind<A: ToIpAddr>(addr: A) -> std::io::Result<IcmpSocket> {
        let ip_addr = addr.to_ip_addr().await?;
        let (domain, protocol) = match ip_addr {
            std::net::IpAddr::V4(_) => (Domain::IPV4, Protocol::ICMPV4),
            std::net::IpAddr::V6(_) => (Domain::IPV6, Protocol::ICMPV6),
        };
        let NewSocket { socket, sock_type } = new_icmp_socket(domain, protocol)?;
        socket.set_nonblocking(true)?;

        // On `SOCK_DGRAM` ping sockets on Linux, the kernel uses the bound
        // port as the ICMP echo identifier — the id field in the packet
        // header is ignored. We must bind with a specific non-zero port
        // so we can recognise our own replies. This mirrors iputils ping's
        // `sin_port = rts->ident` / `sin6_port = rts->ident` logic in
        // `ping4_run()` / `ping6_run()`.
        //
        // On Apple platforms, the kernel correctly uses the packet's id
        // field, so the port doesn't matter — we keep port 0 and rely on
        // the `req_id` written into the ICMP header by the caller.
        //
        // We use the same `REQ_ID` counter that `send_icmp_echo_v4` /
        // `send_icmp_echo_v6` will write into the packet header, keeping
        // the two in sync.
        #[cfg(any(target_os = "linux", target_os = "android"))]
        let dgram_ident = if sock_type == SocketType::Dgram {
            use std::sync::atomic::Ordering;
            // SAFETY: `REQ_ID` is a global lazily-initialized atomic; safe to
            // access from any async context. The counter wraps naturally at 2^16.
            //
            // Skip id 0: the kernel interprets a bind port of 0 as "pick a
            // random port", which defeats the purpose. We fetch the next
            // value rather than mapping 0 -> 1 so we don't bias id 1 (which
            // would otherwise be produced both naturally and by remapping).
            let ident = loop {
                let candidate = crate::REQ_ID.fetch_add(1, Ordering::Relaxed);
                if candidate != 0 {
                    break candidate;
                }
            };
            Some(ident)
        } else {
            None
        };

        // On non-Linux platforms, DGRAM sockets use the packet's id field
        // for matching, not the port.
        //
        // On datagram (ping) sockets on Linux, request TTL via ancillary data
        // since the kernel strips the IP header. On macOS DGRAM sockets this
        // is a no-op (harmless setsockopt that returns an error we ignore).
        if sock_type == SocketType::Dgram && domain == Domain::IPV4 {
            let hold: libc::c_int = 1;
            let _ = unsafe {
                libc::setsockopt(
                    socket.as_raw_fd(),
                    libc::IPPROTO_IP,
                    libc::IP_RECVTTL,
                    (&raw const hold).cast(),
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                )
            };
        }

        if domain == Domain::IPV6 {
            socket.set_recv_hoplimit_v6(true)?;
        }
        // `IP_DONTFRAG` / `IPV6_DONTFRAG`. On Apple platforms, `IP_DONTFRAG`
        // works on an unprivileged `SOCK_DGRAM` ICMPv4 socket — macOS `ping(8)`
        // likewise sets `IP_DONTFRAG` in its non-root path. Empirically,
        // `IPV6_DONTFRAG` returns an error on an unprivileged `SOCK_DGRAM`
        // ICMPv6 socket on macOS, so we skip it there. (Note: macOS `ping6(8)`
        // itself applies `IPV6_DONTFRAG` unconditionally; this skip is our own
        // workaround for the DGRAM-socket limitation, not a mirror of ping6.)
        let skip_dontfrag = {
            #[cfg(any(
                target_os = "macos",
                target_os = "ios",
                target_os = "tvos",
                target_os = "watchos",
                target_os = "visionos",
            ))]
            {
                domain == Domain::IPV6 && !is_root()
            }
            #[cfg(not(any(
                target_os = "macos",
                target_os = "ios",
                target_os = "tvos",
                target_os = "watchos",
                target_os = "visionos",
            )))]
            {
                false
            }
        };
        if !skip_dontfrag {
            set_dont_fragment(&socket, domain, true)?;
        }

        // Build the bind address. On Linux `SOCK_DGRAM` ping sockets the port
        // carries the ICMP identifier (see `dgram_ident` above); everywhere
        // else the port is 0 and the identifier lives in the packet header.
        #[cfg(any(target_os = "linux", target_os = "android"))]
        let bind_port = dgram_ident.unwrap_or(0);
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        let bind_port = 0u16;
        let sock_addr = match ip_addr {
            std::net::IpAddr::V4(ipv4_addr) => {
                SocketAddr::V4(SocketAddrV4::new(ipv4_addr, bind_port))
            }
            std::net::IpAddr::V6(ipv6_addr) => {
                SocketAddr::V6(SocketAddrV6::new(ipv6_addr, bind_port, 0, 0))
            }
        };
        socket.bind(&sock_addr.into())?;
        let io = AsyncFd::new(socket)?;
        Ok(Self {
            io,
            sock_type,
            #[cfg(any(target_os = "linux", target_os = "android"))]
            dgram_ident,
        })
    }

    /// Connect this socket to `addr` so that subsequent `send`/`recv` calls
    /// communicate with that peer only.
    pub async fn connect<A: ToIpAddr>(&self, addr: A) -> std::io::Result<()> {
        let ip_addr = addr.to_ip_addr().await?;
        let socket_addr = match ip_addr {
            std::net::IpAddr::V4(ipv4_addr) => SocketAddr::V4(SocketAddrV4::new(ipv4_addr, 0u16)),
            std::net::IpAddr::V6(ipv6_addr) => {
                SocketAddr::V6(SocketAddrV6::new(ipv6_addr, 0u16, 0, 0))
            }
        };
        self.io.get_ref().connect(&socket_addr.into())
    }

    /// Returns the socket type (`Raw` or `Dgram`) used for this ICMP socket.
    ///
    /// When `Dgram`, the receive path must skip IP-header parsing and retrieve
    /// TTL/hop-limit from ancillary data instead.
    pub(crate) fn sock_type(&self) -> SocketType {
        self.sock_type
    }

    /// Returns the ICMP identifier bound to this socket's datagram port.
    ///
    /// On Linux `SOCK_DGRAM` ping sockets, the kernel derives the ICMP echo
    /// identifier from the bound port, ignoring the id field in the packet
    /// header. This returns that port (ident). On `SOCK_RAW` sockets, returns
    /// `None`.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub(crate) fn dgram_ident(&self) -> Option<u16> {
        self.dgram_ident
    }

    /// Wait for the socket to become ready for the given [`Interest`].
    pub async fn ready(
        &self,
        interest: Interest,
    ) -> std::io::Result<AsyncFdReadyGuard<'_, Socket>> {
        self.io.ready(interest).await
    }

    /// Wait for the socket to become writable.
    pub async fn writable(&self) -> std::io::Result<()> {
        let _ = self.ready(Interest::WRITABLE).await?;
        Ok(())
    }

    /// Send `buf` on the socket. Requires that the socket has been connected.
    pub async fn send(&self, buf: &[u8]) -> std::io::Result<usize> {
        self.io.async_io(Interest::WRITABLE, |s| s.send(buf)).await
    }

    /// Wait for the socket to become readable.
    pub async fn readable(&self) -> std::io::Result<()> {
        let _ = self.ready(Interest::READABLE).await?;
        Ok(())
    }

    /// Receive a datagram into `buf`, returning the number of bytes received.
    pub async fn recv(&self, buf: &mut [MaybeUninit<u8>]) -> std::io::Result<usize> {
        self.io.async_io(Interest::READABLE, |s| s.recv(buf)).await
    }

    pub(crate) async fn recvmsg(&self, msg: &mut MsgHdrMut<'_, '_, '_>) -> std::io::Result<usize> {
        self.io
            .async_io(Interest::READABLE, |s| s.recvmsg(msg, 0))
            .await
    }
}

#[cfg(any(
    target_os = "linux",
    target_os = "l4re",
    target_os = "android",
    target_os = "emscripten"
))]
fn set_dont_fragment(socket: &Socket, domain: Domain, dont_fragment: bool) -> std::io::Result<()> {
    match domain {
        Domain::IPV4 => {
            let payload = if dont_fragment {
                libc::IP_PMTUDISC_DO
            } else {
                libc::IP_PMTUDISC_DONT
            };

            unsafe { setsockopt(socket, libc::IPPROTO_IP, libc::IP_MTU_DISCOVER, payload) }
        }
        Domain::IPV6 => {
            let payload = if dont_fragment {
                libc::IPV6_PMTUDISC_DO
            } else {
                libc::IPV6_PMTUDISC_DONT
            };
            unsafe { setsockopt(socket, libc::IPPROTO_IPV6, libc::IPV6_MTU_DISCOVER, payload) }
        }
        _ => Ok(()),
    }
}

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "tvos",
    target_os = "watchos",
    target_os = "visionos",
    target_os = "freebsd",
    target_os = "dragonfly",
    target_os = "openbsd",
    target_os = "netbsd"
))]
fn set_dont_fragment(socket: &Socket, domain: Domain, dont_fragment: bool) -> std::io::Result<()> {
    match domain {
        Domain::IPV4 => unsafe {
            setsockopt(
                socket,
                libc::IPPROTO_IP,
                libc::IP_DONTFRAG,
                dont_fragment as libc::c_int,
            )
        },
        Domain::IPV6 => unsafe {
            setsockopt(
                socket,
                libc::IPPROTO_IPV6,
                libc::IPV6_DONTFRAG,
                dont_fragment as libc::c_int,
            )
        },
        _ => Ok(()),
    }
}

// `payload` is taken by value so we can take its address with `&raw const`
// for `setsockopt`; the caller's value would otherwise need to outlive the
// call. The borrow lint doesn't model this.
#[allow(clippy::needless_pass_by_value)]
unsafe fn setsockopt<T>(
    socket: &Socket,
    opt: libc::c_int,
    val: libc::c_int,
    payload: T,
) -> std::io::Result<()> {
    let payload = (&raw const payload).cast();
    let res = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            opt,
            val,
            payload,
            std::mem::size_of::<T>() as libc::socklen_t,
        )
    };
    if res != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use super::IcmpSocket;

    #[tokio::test]
    async fn bind_accepts_str_literal() {
        IcmpSocket::bind("127.0.0.1").await.unwrap();
    }

    #[tokio::test]
    async fn bind_accepts_owned_string() {
        IcmpSocket::bind(String::from("127.0.0.1")).await.unwrap();
    }

    #[tokio::test]
    async fn bind_accepts_ipv4addr() {
        IcmpSocket::bind(Ipv4Addr::LOCALHOST).await.unwrap();
    }

    #[tokio::test]
    async fn bind_accepts_ipv6addr() {
        IcmpSocket::bind(Ipv6Addr::LOCALHOST).await.unwrap();
    }

    #[tokio::test]
    async fn bind_accepts_ip_addr() {
        IcmpSocket::bind(IpAddr::V4(Ipv4Addr::LOCALHOST))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn connect_accepts_str_literal() {
        let sock = IcmpSocket::bind(Ipv4Addr::LOCALHOST).await.unwrap();
        sock.connect("127.0.0.1").await.unwrap();
    }

    #[tokio::test]
    async fn connect_accepts_owned_string() {
        let sock = IcmpSocket::bind(Ipv4Addr::LOCALHOST).await.unwrap();
        sock.connect(String::from("127.0.0.1")).await.unwrap();
    }

    #[tokio::test]
    async fn connect_accepts_ipv4addr() {
        let sock = IcmpSocket::bind(Ipv4Addr::LOCALHOST).await.unwrap();
        sock.connect(Ipv4Addr::LOCALHOST).await.unwrap();
    }

    #[tokio::test]
    async fn connect_accepts_ipv6addr() {
        let sock = IcmpSocket::bind(Ipv6Addr::LOCALHOST).await.unwrap();
        sock.connect(Ipv6Addr::LOCALHOST).await.unwrap();
    }

    #[tokio::test]
    async fn connect_accepts_ip_addr() {
        let sock = IcmpSocket::bind(Ipv4Addr::LOCALHOST).await.unwrap();
        sock.connect(IpAddr::V4(Ipv4Addr::LOCALHOST)).await.unwrap();
    }
}

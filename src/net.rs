use std::mem::MaybeUninit;
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::fd::AsRawFd;

use socket2::{Domain, MsgHdrMut, Protocol, Socket, Type};
use tokio::io::unix::{AsyncFd, AsyncFdReadyGuard};
use tokio::io::Interest;

use crate::addr::{HostAddr, ToHostAddr};

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
/// On Linux, tries `SOCK_DGRAM` first and falls back to `SOCK_RAW` on
/// `EACCES`, `EAFNOSUPPORT`, or `EPROTONOSUPPORT`.
///
/// On Apple platforms, uses `SOCK_DGRAM` when not running as root and
/// `SOCK_RAW` when running as root.
///
/// On all other platforms, `SOCK_RAW` is used.
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
/// | Platform | ICMPv4 | ICMPv6 |
/// |---|---|---|
/// | **macOS** | No privileges needed (`SOCK_DGRAM`) | No privileges needed (`SOCK_DGRAM`) |
/// | **Linux** | `net.ipv4.ping_group_range` or `CAP_NET_RAW` | Same |
/// | **FreeBSD** / **NetBSD** / **OpenBSD** | Root | Root |
///
/// On Apple platforms, a datagram (`SOCK_DGRAM`) socket is used when not
/// running as root; `SOCK_RAW` is used when running as root.
///
/// On Linux, a `SOCK_DGRAM` socket is tried first with fallback to `SOCK_RAW`.
pub struct IcmpSocket {
    io: AsyncFd<Socket>,
    sock_type: SocketType,
    /// Identifier from the bound port on Linux `SOCK_DGRAM` sockets.
    /// `None` on `SOCK_RAW` sockets.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    dgram_ident: Option<u16>,
}

impl IcmpSocket {
    /// Create a new ICMP socket bound to `addr`.
    ///
    /// The address family of `addr` (after resolution) determines whether an
    /// ICMPv4 or ICMPv6 socket is created. The socket is placed in
    /// non-blocking mode and registered with the current Tokio runtime.
    /// The resolved IPv6 scope (zone) id is used for bind.
    ///
    /// On Apple platforms, `SOCK_DGRAM` is used when not running as root and
    /// `SOCK_RAW` when running as root.
    ///
    /// On Linux, a `SOCK_DGRAM` socket is tried first with fallback to
    /// `SOCK_RAW`.
    pub async fn bind<A: ToHostAddr>(addr: A) -> std::io::Result<IcmpSocket> {
        let host = addr.to_host_addr().await?;
        let (domain, protocol) = match host {
            HostAddr::V4(_) => (Domain::IPV4, Protocol::ICMPV4),
            HostAddr::V6 { .. } => (Domain::IPV6, Protocol::ICMPV6),
        };
        let NewSocket { socket, sock_type } = new_icmp_socket(domain, protocol)?;
        socket.set_nonblocking(true)?;

        // Bind port for Linux `SOCK_DGRAM` sockets; 0 elsewhere.
        #[cfg(any(target_os = "linux", target_os = "android"))]
        let dgram_ident = if sock_type == SocketType::Dgram {
            use std::sync::atomic::Ordering;
            // SAFETY: `REQ_ID` is a global atomic; safe from any async context.
            // Skip id 0.
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

        // Request IPv4 TTL via ancillary data on `SOCK_DGRAM` sockets.
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
        // Set `IP_DONTFRAG` / `IPV6_DONTFRAG`, except IPv6 on Apple
        // platforms when not running as root.
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

        // Bind address with the DGRAM ident as port on Linux, else port 0.
        // The resolved IPv6 scope id is preserved.
        #[cfg(any(target_os = "linux", target_os = "android"))]
        let bind_port = dgram_ident.unwrap_or(0);
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        let bind_port = 0u16;
        let bind_addr = match host {
            HostAddr::V4(ip) => SocketAddr::V4(SocketAddrV4::new(ip, bind_port)),
            HostAddr::V6 { ip, scope_id } => {
                SocketAddr::V6(SocketAddrV6::new(ip, bind_port, 0, scope_id))
            }
        };
        socket.bind(&bind_addr.into())?;
        let io = AsyncFd::new(socket)?;
        Ok(Self {
            io,
            sock_type,
            #[cfg(any(target_os = "linux", target_os = "android"))]
            dgram_ident,
        })
    }

    /// Connect this socket to `addr`.
    ///
    /// The IPv6 scope (zone) id is preserved. The connect port is always `0`.
    pub async fn connect<A: ToHostAddr>(&self, addr: A) -> std::io::Result<()> {
        let host = addr.to_host_addr().await?;
        let socket_addr = match host {
            HostAddr::V4(ip) => SocketAddr::V4(SocketAddrV4::new(ip, 0)),
            HostAddr::V6 { ip, scope_id } => SocketAddr::V6(SocketAddrV6::new(ip, 0, 0, scope_id)),
        };
        self.io.get_ref().connect(&socket_addr.into())
    }

    /// Returns the socket type (`Raw` or `Dgram`) used for this ICMP socket.
    pub(crate) fn sock_type(&self) -> SocketType {
        self.sock_type
    }

    /// Returns the bound datagram port identifier on Linux.
    ///
    /// Returns `None` on `SOCK_RAW` sockets.
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

    /// Loopback interface name: `lo` on Linux/Android, `lo0` elsewhere.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    const LOOPBACK: &str = "lo";
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    const LOOPBACK: &str = "lo0";

    /// Scope (zone) id of the loopback interface on this host.
    fn loopback_scope_id() -> u32 {
        let name = std::ffi::CString::new(LOOPBACK).unwrap();
        // SAFETY: `name` is a valid NUL-terminated C string.
        let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
        assert_ne!(index, 0, "loopback interface {LOOPBACK} must exist");
        index
    }

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
    async fn bind_accepts_scoped_ipv6_str() {
        // There is no portable named-zone bind target: Linux loopback has
        // no link-local address, and glibc's getaddrinfo rejects named
        // zones on non-link-local addresses such as `::1`. A numeric zone
        // still exercises scope-id plumbing into the bind address; named
        // zone resolution is covered by `addr::tests`.
        IcmpSocket::bind(format!("::1%{}", loopback_scope_id()))
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

    #[tokio::test]
    async fn connect_accepts_scoped_tuple() {
        // Linux loopback has no link-local address, so connecting `fe80::1`
        // fails there with ENETUNREACH. Scoped `::1` connects on all
        // platforms while still plumbing the scope id into the sockaddr.
        let scoped = (Ipv6Addr::LOCALHOST, loopback_scope_id());
        let sock = IcmpSocket::bind(Ipv6Addr::UNSPECIFIED).await.unwrap();
        sock.connect(scoped).await.unwrap();
    }
}

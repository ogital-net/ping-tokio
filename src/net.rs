use std::mem::MaybeUninit;
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::fd::AsRawFd;

use socket2::{Domain, MsgHdrMut, Protocol, Socket, Type};
use tokio::io::unix::{AsyncFd, AsyncFdReadyGuard};
use tokio::io::Interest;

use crate::addr::ToIpAddr;

/// Asynchronous, non-blocking ICMP raw socket.
///
/// Wraps a [`socket2::Socket`] in [`tokio::io::unix::AsyncFd`] so that send
/// and receive operations integrate with the Tokio runtime. Supports both
/// ICMPv4 and ICMPv6; the protocol is selected by the address family of the
/// bind address.
///
/// Creating an `IcmpSocket` requires permission to open raw sockets
/// (e.g. `CAP_NET_RAW` on Linux, or running as root).
pub struct IcmpSocket {
    io: AsyncFd<Socket>,
}

impl IcmpSocket {
    /// Create a new ICMP raw socket bound to `addr`.
    ///
    /// The address family of `addr` (after resolution) determines whether an
    /// ICMPv4 or ICMPv6 socket is created. The socket is placed in
    /// non-blocking mode and registered with the current Tokio runtime.
    pub async fn bind<A: ToIpAddr>(addr: A) -> std::io::Result<IcmpSocket> {
        let ip_addr = addr.to_ip_addr().await?;
        let (sock_addr, domain, protocol) = match ip_addr {
            std::net::IpAddr::V4(ipv4_addr) => (
                SocketAddr::V4(SocketAddrV4::new(ipv4_addr, 0u16)),
                Domain::IPV4,
                Protocol::ICMPV4,
            ),
            std::net::IpAddr::V6(ipv6_addr) => (
                SocketAddr::V6(SocketAddrV6::new(ipv6_addr, 0u16, 0, 0)),
                Domain::IPV6,
                Protocol::ICMPV6,
            ),
        };
        let socket = Socket::new(domain, Type::RAW, Some(protocol))?;
        socket.set_nonblocking(true)?;
        if domain == Domain::IPV6 {
            socket.set_recv_hoplimit_v6(true)?;
        }
        // options not exposed by socket2
        set_dont_fragment(&socket, domain, true)?;

        socket.bind(&sock_addr.into())?;
        let io = AsyncFd::new(socket)?;
        Ok(Self { io })
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

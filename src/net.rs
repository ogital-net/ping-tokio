use std::fmt;
use std::marker::PhantomData;
use std::mem::MaybeUninit;
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::fd::AsRawFd;

use socket2::{Domain, Protocol, Socket, Type};
use socket2::{MaybeUninitSlice, SockAddr};
use tokio::io::unix::{AsyncFd, AsyncFdReadyGuard};
use tokio::io::Interest;

use crate::addr::ToIpAddr;

/// Configuration of a `recvmsg(2)` system call.
///
/// This wraps `msghdr` on Unix and `WSAMSG` on Windows. Also see [`MsgHdr`] for
/// the variant used by `sendmsg(2)`.
#[repr(transparent)]
pub(crate) struct MsgHdrMut<'addr, 'bufs, 'control> {
    inner: libc::msghdr,
    #[allow(clippy::type_complexity)]
    _lifetimes: PhantomData<(
        &'addr mut SockAddr,
        &'bufs mut MaybeUninitSlice<'bufs>,
        &'control mut [u8],
    )>,
}

#[cfg(not(any(target_os = "redox", target_os = "wasi")))]
impl<'addr, 'bufs, 'control> MsgHdrMut<'addr, 'bufs, 'control> {
    /// Create a new `MsgHdrMut` with all empty/zero fields.
    #[allow(clippy::new_without_default)]
    pub fn new() -> MsgHdrMut<'addr, 'bufs, 'control> {
        // SAFETY: all zero is valid for `msghdr` and `WSAMSG`.
        MsgHdrMut {
            inner: unsafe { std::mem::zeroed() },
            _lifetimes: PhantomData,
        }
    }

    /// Set the mutable address (name) of the message.
    ///
    /// Corresponds to setting `msg_name` and `msg_namelen` on Unix and `name`
    /// and `namelen` on Windows.
    #[allow(clippy::needless_pass_by_ref_mut)]
    pub fn with_addr(mut self, addr: &'addr mut SockAddr) -> Self {
        Self::set_msghdr_name(&mut self.inner, addr);
        self
    }

    /// Set the mutable buffer(s) of the message.
    ///
    /// Corresponds to setting `msg_iov` and `msg_iovlen` on Unix and `lpBuffers`
    /// and `dwBufferCount` on Windows.
    pub fn with_buffers(mut self, bufs: &'bufs mut [MaybeUninitSlice<'_>]) -> Self {
        Self::set_msghdr_iov(&mut self.inner, bufs.as_mut_ptr().cast(), bufs.len());
        self
    }

    /// Set the mutable control buffer of the message.
    ///
    /// Corresponds to setting `msg_control` and `msg_controllen` on Unix and
    /// `Control` on Windows.
    pub fn with_control(mut self, buf: &'control mut [MaybeUninit<u8>]) -> Self {
        Self::set_msghdr_control(&mut self.inner, buf.as_mut_ptr().cast(), buf.len());
        self
    }

    /// Gets the message flags written by `recvmsg(2)` (e.g. `MSG_CTRUNC`,
    /// `MSG_TRUNC`).
    pub fn flags(&self) -> libc::c_int {
        self.inner.msg_flags
    }

    /// Returns a reference to the underlying `msghdr`.
    ///
    /// Provided so callers can use kernel macros like `CMSG_FIRSTHDR` /
    /// `CMSG_NXTHDR`, which take a `*const msghdr` and use `msg_control` /
    /// `msg_controllen` from it.
    pub fn as_msghdr(&self) -> &libc::msghdr {
        &self.inner
    }

    fn set_msghdr_name(msg: &mut libc::msghdr, name: &SockAddr) {
        msg.msg_name = name.as_ptr() as *mut _;
        msg.msg_namelen = name.len();
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
    fn set_msghdr_iov(msg: &mut libc::msghdr, ptr: *mut libc::iovec, len: usize) {
        msg.msg_iov = ptr;
        msg.msg_iovlen = std::cmp::min(len, libc::c_int::MAX as usize) as libc::c_int;
    }

    #[cfg(any(
        target_os = "linux",
        target_os = "l4re",
        target_os = "android",
        target_os = "emscripten"
    ))]
    fn set_msghdr_iov(msg: &mut libc::msghdr, ptr: *mut libc::iovec, len: usize) {
        msg.msg_iov = ptr;
        msg.msg_iovlen = len;
    }

    fn set_msghdr_control(msg: &mut libc::msghdr, ptr: *mut libc::c_void, len: usize) {
        msg.msg_control = ptr;
        msg.msg_controllen = len as _;
    }
}

unsafe impl Send for MsgHdrMut<'_, '_, '_> {}

impl fmt::Debug for MsgHdrMut<'_, '_, '_> {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        "MsgHdrMut".fmt(fmt)
    }
}

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
            .async_io(Interest::READABLE, |s| recvmsg(s, msg, 0))
            .await
    }
}

fn recvmsg(
    socket: &Socket,
    msg: &mut MsgHdrMut<'_, '_, '_>,
    flags: libc::c_int,
) -> std::io::Result<usize> {
    let fd = socket.as_raw_fd();
    let res = unsafe { libc::recvmsg(fd, &raw mut msg.inner, flags) };
    if res == -1 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(res as usize)
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

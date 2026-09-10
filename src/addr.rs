use std::{
    fmt,
    future::Future,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    task::{ready, Poll},
};

/// An IP address with an optional IPv6 scope (zone) identifier, and no port.
///
/// IPv4 holds just an address; IPv6 holds an address plus a `scope_id`
/// (`0` means "no scope"). ICMP has no ports, so [`SocketAddr`] is not
/// accepted; use the [`ToHostAddr`] conversion to obtain one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HostAddr {
    /// IPv4 host address.
    V4(Ipv4Addr),
    /// IPv6 host address with a scope (zone) id; `0` means "no scope".
    V6 {
        /// The IPv6 address.
        ip: Ipv6Addr,
        /// The scope (zone) id identifying the interface for link-local
        /// addresses. `0` means "no scope".
        scope_id: u32,
    },
}

impl HostAddr {
    /// The IP address without scope information.
    pub fn ip(&self) -> IpAddr {
        match *self {
            Self::V4(ip) => IpAddr::V4(ip),
            Self::V6 { ip, .. } => IpAddr::V6(ip),
        }
    }

    /// The IPv6 scope (zone) id.
    pub fn scope_id(&self) -> u32 {
        match *self {
            Self::V4(_) => 0,
            Self::V6 { scope_id, .. } => scope_id,
        }
    }

    /// Returns `true` if this is an IPv4 address.
    pub fn is_ipv4(&self) -> bool {
        matches!(self, Self::V4(_))
    }

    /// Returns `true` if this is an IPv6 address.
    pub fn is_ipv6(&self) -> bool {
        matches!(self, Self::V6 { .. })
    }
}

impl From<Ipv4Addr> for HostAddr {
    fn from(ip: Ipv4Addr) -> Self {
        Self::V4(ip)
    }
}

impl From<Ipv6Addr> for HostAddr {
    fn from(ip: Ipv6Addr) -> Self {
        Self::V6 { ip, scope_id: 0 }
    }
}

impl From<IpAddr> for HostAddr {
    fn from(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(ip) => Self::V4(ip),
            IpAddr::V6(ip) => Self::V6 { ip, scope_id: 0 },
        }
    }
}

impl From<SocketAddr> for HostAddr {
    fn from(addr: SocketAddr) -> Self {
        match addr {
            SocketAddr::V4(v4) => Self::V4(*v4.ip()),
            SocketAddr::V6(v6) => Self::V6 {
                ip: *v6.ip(),
                scope_id: v6.scope_id(),
            },
        }
    }
}

impl fmt::Display for HostAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::V4(ip) => write!(f, "{ip}"),
            Self::V6 { ip, scope_id } => {
                if scope_id == 0 {
                    write!(f, "{ip}")
                } else {
                    write!(f, "{ip}%{scope_id}")
                }
            }
        }
    }
}

mod private {
    pub trait Sealed {}

    impl Sealed for super::HostAddr {}
    impl Sealed for std::net::IpAddr {}
    impl Sealed for std::net::Ipv4Addr {}
    impl Sealed for std::net::Ipv6Addr {}
    impl Sealed for (std::net::Ipv6Addr, u32) {}
    impl Sealed for str {}
    impl Sealed for &str {}
    impl Sealed for String {}
}

/// Conversion to a [`HostAddr`], possibly via an asynchronous DNS lookup.
///
/// This trait is sealed and cannot be implemented outside of this crate. It is
/// implemented for [`HostAddr`], `IpAddr`, `Ipv4Addr`, `Ipv6Addr`,
/// `(Ipv6Addr, u32)`, `&str`, `str`, and `String`. String inputs that do not
/// parse as literal addresses resolve on Tokio's blocking pool via
/// [`std::net::ToSocketAddrs`].
///
/// The resolved [`HostAddr`] preserves the IPv6 scope (zone) identifier.
/// [`IpAddr`] and [`Ipv6Addr`] cannot represent a scope id; use a `&str`
/// (`"fe80::1%eth0"`) or an `(Ipv6Addr, u32)` tuple for link-local
/// addresses.
pub trait ToHostAddr: private::Sealed {
    /// Future yielding the resolved [`HostAddr`].
    type Future: Future<Output = std::io::Result<HostAddr>> + Send + 'static;

    /// Begin resolving `self` to a [`HostAddr`].
    fn to_host_addr(&self) -> Self::Future;
}

impl ToHostAddr for HostAddr {
    type Future = std::future::Ready<std::io::Result<HostAddr>>;

    fn to_host_addr(&self) -> Self::Future {
        std::future::ready(Ok(*self))
    }
}

impl ToHostAddr for IpAddr {
    type Future = std::future::Ready<std::io::Result<HostAddr>>;

    fn to_host_addr(&self) -> Self::Future {
        std::future::ready(Ok(HostAddr::from(*self)))
    }
}

impl ToHostAddr for Ipv4Addr {
    type Future = std::future::Ready<std::io::Result<HostAddr>>;

    fn to_host_addr(&self) -> Self::Future {
        std::future::ready(Ok(HostAddr::V4(*self)))
    }
}

impl ToHostAddr for Ipv6Addr {
    type Future = std::future::Ready<std::io::Result<HostAddr>>;

    fn to_host_addr(&self) -> Self::Future {
        std::future::ready(Ok(HostAddr::V6 {
            ip: *self,
            scope_id: 0,
        }))
    }
}

impl ToHostAddr for (Ipv6Addr, u32) {
    type Future = std::future::Ready<std::io::Result<HostAddr>>;

    fn to_host_addr(&self) -> Self::Future {
        std::future::ready(Ok(HostAddr::V6 {
            ip: self.0,
            scope_id: self.1,
        }))
    }
}

/// Future returned by [`ToHostAddr::to_host_addr`] for inputs (such as strings)
/// that may require a blocking DNS lookup.
pub struct MaybeReady(State);

enum State {
    Ready(Option<HostAddr>),
    Blocking(tokio::task::JoinHandle<std::io::Result<HostAddr>>),
}

impl Future for MaybeReady {
    type Output = std::io::Result<HostAddr>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        match self.0 {
            State::Ready(mut host) => Poll::Ready(Ok(host
                .take()
                .expect("`MaybeReady` polled after completion"))),
            State::Blocking(ref mut rx) => Poll::Ready(Ok(ready!(Pin::new(rx).poll(cx))??)),
        }
    }
}

impl ToHostAddr for &str {
    type Future = MaybeReady;

    fn to_host_addr(&self) -> Self::Future {
        (**self).to_host_addr()
    }
}

impl ToHostAddr for String {
    type Future = MaybeReady;

    fn to_host_addr(&self) -> Self::Future {
        self.as_str().to_host_addr()
    }
}

impl ToHostAddr for str {
    type Future = MaybeReady;

    fn to_host_addr(&self) -> Self::Future {
        // Plain IP literal.
        if let Ok(ip_addr) = self.parse::<IpAddr>() {
            return MaybeReady(State::Ready(Some(HostAddr::from(ip_addr))));
        }

        // IPv6 literal with a numeric zone (`fe80::1%2`).
        if let Some((addr_part, zone)) = self.rsplit_once('%') {
            if let (Ok(ip), Ok(scope_id)) = (addr_part.parse::<Ipv6Addr>(), zone.parse::<u32>()) {
                return MaybeReady(State::Ready(Some(HostAddr::V6 { ip, scope_id })));
            }
        }

        // DNS lookup on Tokio's blocking pool.
        let s = self.to_owned();
        MaybeReady(State::Blocking(tokio::task::spawn_blocking(move || {
            let addr = std::net::ToSocketAddrs::to_socket_addrs(&(s, 0u16))?
                .next()
                .map(HostAddr::from)
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "could not resolve to any address",
                    )
                })?;
            Ok(addr)
        })))
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use super::{HostAddr, ToHostAddr};

    #[tokio::test]
    async fn host_addr_returns_same_value() {
        let addr = HostAddr::V6 {
            ip: Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
            scope_id: 7,
        };
        let result = addr.to_host_addr().await.unwrap();
        assert_eq!(result, addr);
        assert_eq!(result.scope_id(), 7);
    }

    #[tokio::test]
    async fn tuple_preserves_scope_id() {
        let ip = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let result = (ip, 7u32).to_host_addr().await.unwrap();
        assert_eq!(result, HostAddr::V6 { ip, scope_id: 7 });
    }

    #[tokio::test]
    async fn ip_addr_to_host_addr_returns_same_ip() {
        let ip: IpAddr = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        let result = ip.to_host_addr().await.unwrap();
        assert_eq!(result.ip(), ip);
    }

    #[tokio::test]
    async fn ip_addr_v6_to_host_addr_has_zero_scope() {
        let ip: IpAddr = IpAddr::V6(Ipv6Addr::LOCALHOST);
        let result = ip.to_host_addr().await.unwrap();
        assert_eq!(result.ip(), ip);
        assert_eq!(result.scope_id(), 0);
    }

    #[tokio::test]
    async fn ipv4_addr_wraps_without_scope() {
        let ip = Ipv4Addr::new(10, 0, 0, 1);
        let result = ip.to_host_addr().await.unwrap();
        assert_eq!(result, HostAddr::V4(ip));
    }

    #[tokio::test]
    async fn ipv6_addr_wraps_with_zero_scope() {
        let ip = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let result = ip.to_host_addr().await.unwrap();
        assert_eq!(result.ip(), IpAddr::V6(ip));
        assert_eq!(result.scope_id(), 0);
    }

    #[tokio::test]
    async fn str_with_ipv4_address_parses_directly() {
        let result = "192.168.1.1".to_host_addr().await.unwrap();
        assert_eq!(result, HostAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
    }

    #[tokio::test]
    async fn str_with_ipv6_address_parses_directly() {
        let result = "::1".to_host_addr().await.unwrap();
        assert_eq!(result.ip(), IpAddr::V6(Ipv6Addr::LOCALHOST));
    }

    #[tokio::test]
    async fn str_with_scoped_ipv6_literal_preserves_scope_id() {
        let result = "fe80::1%1".to_host_addr().await.unwrap();
        match result {
            HostAddr::V6 { ip, scope_id } => {
                assert_eq!(ip, Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1));
                assert_eq!(scope_id, 1);
            }
            HostAddr::V4(v4) => panic!("expected IPv6, got {v4}"),
        }
    }

    #[tokio::test]
    async fn str_with_named_zone_resolves_scope_id() {
        // The zone name is resolved by `getaddrinfo` via `if_nametoindex`,
        // so it must be a real interface. Loopback is `lo` on Linux/Android
        // and `lo0` on macOS and the BSDs.
        #[cfg(any(target_os = "linux", target_os = "android"))]
        let scoped = "fe80::1%lo";
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        let scoped = "fe80::1%lo0";
        let result = scoped.to_host_addr().await.unwrap();
        match result {
            HostAddr::V6 { ip, scope_id } => {
                assert_eq!(ip, Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1));
                assert_ne!(scope_id, 0);
            }
            HostAddr::V4(v4) => panic!("expected IPv6, got {v4}"),
        }
    }

    #[tokio::test]
    async fn scoped_display_round_trips() {
        let addr = HostAddr::V6 {
            ip: Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
            scope_id: 3,
        };
        assert_eq!(addr.to_string(), "fe80::1%3");
        let reparsed = addr.to_string().to_host_addr().await.unwrap();
        assert_eq!(reparsed, addr);
    }

    #[tokio::test]
    async fn str_with_unresolvable_host_returns_error() {
        let result = "nonexistent.invalid".to_host_addr().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn str_with_hostname_resolves_via_dns() {
        let result = "localhost".to_host_addr().await.unwrap();
        assert!(
            result.ip().is_loopback(),
            "expected a loopback address, got {result}"
        );
    }
}

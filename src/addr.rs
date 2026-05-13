use std::{
    future::Future,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    task::{ready, Poll},
};

mod private {
    pub trait Sealed {}

    impl Sealed for std::net::IpAddr {}
    impl Sealed for std::net::Ipv4Addr {}
    impl Sealed for std::net::Ipv6Addr {}
    impl Sealed for str {}
    impl Sealed for &str {}
    impl Sealed for String {}
}

/// Conversion to an [`IpAddr`], possibly via an asynchronous DNS lookup.
///
/// This trait is sealed and cannot be implemented outside of this crate. It is
/// implemented for `IpAddr`, `Ipv4Addr`, `Ipv6Addr`, `&str`, `str`, and
/// `String`. String inputs that don't parse as a literal IP address are
/// resolved on Tokio's blocking pool via [`std::net::ToSocketAddrs`].
pub trait ToIpAddr: private::Sealed {
    /// Future yielding the resolved [`IpAddr`].
    type Future: Future<Output = std::io::Result<IpAddr>> + Send + 'static;

    /// Begin resolving `self` to an [`IpAddr`].
    fn to_ip_addr(&self) -> Self::Future;
}

impl ToIpAddr for IpAddr {
    type Future = std::future::Ready<std::io::Result<IpAddr>>;

    fn to_ip_addr(&self) -> Self::Future {
        std::future::ready(Ok(*self))
    }
}

impl ToIpAddr for Ipv4Addr {
    type Future = std::future::Ready<std::io::Result<IpAddr>>;

    fn to_ip_addr(&self) -> Self::Future {
        std::future::ready(Ok(IpAddr::V4(*self)))
    }
}

impl ToIpAddr for Ipv6Addr {
    type Future = std::future::Ready<std::io::Result<IpAddr>>;

    fn to_ip_addr(&self) -> Self::Future {
        std::future::ready(Ok(IpAddr::V6(*self)))
    }
}

/// Future returned by [`ToIpAddr::to_ip_addr`] for inputs (such as strings)
/// that may require a blocking DNS lookup.
pub struct MaybeReady(State);

enum State {
    Ready(Option<IpAddr>),
    Blocking(tokio::task::JoinHandle<std::io::Result<std::vec::IntoIter<SocketAddr>>>),
}

impl Future for MaybeReady {
    type Output = std::io::Result<IpAddr>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        match self.0 {
            State::Ready(mut ip_addr) => Poll::Ready(Ok(ip_addr
                .take()
                .expect("`MaybeReady` polled after completion"))),
            State::Blocking(ref mut rx) => {
                let res = ready!(Pin::new(rx).poll(cx))?.map(|mut v| v.next().unwrap());

                Poll::Ready(res.map(|s| s.ip()))
            }
        }
    }
}

impl ToIpAddr for &str {
    type Future = MaybeReady;

    fn to_ip_addr(&self) -> Self::Future {
        (**self).to_ip_addr()
    }
}

impl ToIpAddr for String {
    type Future = MaybeReady;

    fn to_ip_addr(&self) -> Self::Future {
        self.as_str().to_ip_addr()
    }
}

impl ToIpAddr for str {
    type Future = MaybeReady;

    fn to_ip_addr(&self) -> Self::Future {
        if let Ok(ip_addr) = self.parse::<IpAddr>() {
            return MaybeReady(State::Ready(Some(ip_addr)));
        }

        // Run DNS lookup on the blocking pool
        let s = self.to_owned();
        MaybeReady(State::Blocking(tokio::task::spawn_blocking(move || {
            std::net::ToSocketAddrs::to_socket_addrs(&(s, 0u16))
        })))
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use super::ToIpAddr;

    #[tokio::test]
    async fn ip_addr_to_ip_addr_returns_same_value() {
        let ip: IpAddr = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        let result = ip.to_ip_addr().await.unwrap();
        assert_eq!(result, ip);
    }

    #[tokio::test]
    async fn ip_addr_v6_to_ip_addr_returns_same_value() {
        let ip: IpAddr = IpAddr::V6(Ipv6Addr::LOCALHOST);
        let result = ip.to_ip_addr().await.unwrap();
        assert_eq!(result, ip);
    }

    #[tokio::test]
    async fn ipv4_addr_wraps_in_ip_addr_v4() {
        let ip = Ipv4Addr::new(10, 0, 0, 1);
        let result = ip.to_ip_addr().await.unwrap();
        assert_eq!(result, IpAddr::V4(ip));
    }

    #[tokio::test]
    async fn ipv6_addr_wraps_in_ip_addr_v6() {
        let ip = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let result = ip.to_ip_addr().await.unwrap();
        assert_eq!(result, IpAddr::V6(ip));
    }

    #[tokio::test]
    async fn str_with_ipv4_address_parses_directly() {
        let result = "192.168.1.1".to_ip_addr().await.unwrap();
        assert_eq!(result, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
    }

    #[tokio::test]
    async fn str_with_ipv6_address_parses_directly() {
        let result = "::1".to_ip_addr().await.unwrap();
        assert_eq!(result, IpAddr::V6(Ipv6Addr::LOCALHOST));
    }

    #[tokio::test]
    async fn str_with_hostname_resolves_via_dns() {
        let result = "localhost".to_ip_addr().await.unwrap();
        assert!(
            result.is_loopback(),
            "expected a loopback address, got {result}"
        );
    }
}

//! Adopt a listening socket handed down by the mount helper.
//!
//! The mount helper binds the proxy's listen port to reserve it. If it closed that
//! socket and the proxy then bound the port again, another process could take the
//! port in between, and the NFS mount would be attached to that process. Instead the
//! helper passes its bound socket to the proxy as an inherited file descriptor
//! (`--listen-fd`), so the port stays bound from the moment it is chosen until the
//! proxy exits.

use socket2::{SockRef, Type};
use std::net::{SocketAddr, TcpListener as StdTcpListener};
use std::os::fd::{FromRawFd, OwnedFd, RawFd};
use tokio::net::TcpListener;

/// Same backlog `tokio::net::TcpListener::bind` uses.
pub const LISTEN_BACKLOG: i32 = 1024;

/// Take ownership of `fd`, check that it is a TCP socket bound to `expected_addr`,
/// and return it as a listening Tokio listener.
///
/// The socket may already be listening; `listen` is called either way, which is
/// allowed on a listening socket. Must be called from within a Tokio runtime.
pub fn adopt_listener(fd: RawFd, expected_addr: &str) -> Result<TcpListener, String> {
    // 0-2 are stdin, stdout and stderr, never a socket handed over for listening.
    if fd < 3 {
        return Err(format!(
            "--listen-fd {fd} is a standard stream, not a socket"
        ));
    }
    // SAFETY: F_GETFD only reads the descriptor flags; it has no effect on `fd`.
    if unsafe { libc::fcntl(fd, libc::F_GETFD) } == -1 {
        return Err(format!("--listen-fd {fd} is not an open file descriptor"));
    }
    let expected: SocketAddr = expected_addr
        .parse()
        .map_err(|e| format!("Invalid listen address {expected_addr}: {e}"))?;

    // SAFETY: `fd` is open (checked above) and was handed to this process for its
    // sole use; ownership moves here and the raw descriptor is not used again. If a
    // check below fails, dropping `listener` closes it.
    let listener = StdTcpListener::from(unsafe { OwnedFd::from_raw_fd(fd) });
    let socket = SockRef::from(&listener);

    let socket_type = socket
        .r#type()
        .map_err(|e| format!("--listen-fd {fd} is not a socket: {e}"))?;
    if socket_type != Type::STREAM {
        return Err(format!("--listen-fd {fd} is not a TCP socket"));
    }
    let local_addr = listener
        .local_addr()
        .map_err(|e| format!("--listen-fd {fd} is not a bound TCP socket: {e}"))?;
    if local_addr != expected {
        return Err(format!(
            "--listen-fd {fd} is bound to {local_addr}, expected {expected}"
        ));
    }

    socket
        .listen(LISTEN_BACKLOG)
        .map_err(|e| format!("Failed to listen on {local_addr}: {e}"))?;
    // The helper binds without SO_REUSEADDR, so that concurrent helpers cannot both
    // bind the port. Set it now, as `TcpListener::bind` does for a proxy that binds
    // the port itself: accepted connections take the flag from the listener, and a
    // connection left over when this proxy dies would otherwise block the proxy the
    // watchdog restarts from binding the port until that connection times out.
    // Set after listen(), so no other socket can bind the port meanwhile.
    socket
        .set_reuse_address(true)
        .map_err(|e| format!("Failed to set SO_REUSEADDR on {local_addr}: {e}"))?;
    // Not inherited by anything this process starts.
    socket
        .set_cloexec(true)
        .map_err(|e| format!("Failed to set close-on-exec on {local_addr}: {e}"))?;
    listener
        .set_nonblocking(true)
        .map_err(|e| format!("Failed to make {local_addr} non-blocking: {e}"))?;
    TcpListener::from_std(listener).map_err(|e| format!("Failed to adopt {local_addr}: {e}"))
}

/// The listener for `listen_addr`: the inherited socket when `listen_fd` is set,
/// otherwise a newly bound one. Panics, like the bind it replaces, when neither
/// works, so the mount helper sees the proxy exit with the reason on stderr.
pub async fn listener_for(listen_fd: Option<RawFd>, listen_addr: &str) -> TcpListener {
    match listen_fd {
        Some(fd) => match adopt_listener(fd, listen_addr) {
            Ok(listener) => listener,
            Err(e) => panic!("Failed to use inherited listen socket for {listen_addr}: {e}"),
        },
        None => match TcpListener::bind(listen_addr).await {
            Ok(listener) => listener,
            Err(_) => panic!("Failed to bind {}", listen_addr),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use socket2::{Domain, Socket};
    use std::os::fd::IntoRawFd;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// A TCP socket bound to a free loopback port but not listening, as the mount
    /// helper hands it over. Returns the raw descriptor and the bound address.
    fn bound_socket() -> (RawFd, SocketAddr) {
        let socket = Socket::new(Domain::IPV4, Type::STREAM, None).unwrap();
        socket
            .bind(&"127.0.0.1:0".parse::<SocketAddr>().unwrap().into())
            .unwrap();
        let addr = socket.local_addr().unwrap().as_socket().unwrap();
        (socket.into_raw_fd(), addr)
    }

    #[tokio::test]
    async fn adopts_bound_socket_and_accepts_connections() {
        let (fd, addr) = bound_socket();
        let listener = adopt_listener(fd, &addr.to_string()).unwrap();
        assert_eq!(addr, listener.local_addr().unwrap());

        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (mut server, _) = listener.accept().await.unwrap();
        client.write_all(b"x").await.unwrap();
        let mut buf = [0u8; 1];
        server.read_exact(&mut buf).await.unwrap();
        assert_eq!(b"x", &buf);
    }

    #[tokio::test]
    async fn port_stays_bound_from_handover_to_adoption() {
        let (fd, addr) = bound_socket();
        // Before and after adoption, nothing else can bind the port.
        assert!(std::net::TcpListener::bind(addr).is_err());
        let _listener = adopt_listener(fd, &addr.to_string()).unwrap();
        assert!(std::net::TcpListener::bind(addr).is_err());
    }

    #[tokio::test]
    async fn port_can_be_bound_again_after_proxy_with_connections_exits() {
        // A proxy that served a connection dies; the watchdog restarts it, and the
        // restarted proxy binds the port itself.
        let (fd, addr) = bound_socket();
        let listener = adopt_listener(fd, &addr.to_string()).unwrap();
        let client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        // The proxy side closes first, as when it is killed, leaving its end of the
        // connection open in the kernel.
        drop(server);
        drop(listener);

        let restarted = TcpListener::bind(addr).await;
        assert!(restarted.is_ok(), "restarted proxy could not bind {addr}");
        drop(client);
    }

    #[tokio::test]
    async fn adopts_already_listening_socket() {
        let std_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = std_listener.local_addr().unwrap();
        let listener = adopt_listener(std_listener.into_raw_fd(), &addr.to_string()).unwrap();
        let _client = tokio::net::TcpStream::connect(addr).await.unwrap();
        listener.accept().await.unwrap();
    }

    #[tokio::test]
    async fn rejects_socket_bound_to_other_address() {
        let (fd, addr) = bound_socket();
        let other = SocketAddr::new(addr.ip(), addr.port().wrapping_add(1).max(1));
        let err = adopt_listener(fd, &other.to_string()).unwrap_err();
        assert!(err.contains("expected"), "{err}");
    }

    #[tokio::test]
    async fn rejects_udp_socket() {
        let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = udp.local_addr().unwrap();
        let err = adopt_listener(udp.into_raw_fd(), &addr.to_string()).unwrap_err();
        assert!(err.contains("not a TCP socket"), "{err}");
    }

    #[tokio::test]
    async fn rejects_non_socket_descriptor() {
        let file = std::fs::File::open("/dev/null").unwrap();
        let err = adopt_listener(file.into_raw_fd(), "127.0.0.1:20049").unwrap_err();
        assert!(err.contains("not a socket"), "{err}");
    }

    #[tokio::test]
    async fn rejects_closed_descriptor() {
        let (fd, addr) = bound_socket();
        // SAFETY: closes the descriptor this test just created and owns.
        unsafe { libc::close(fd) };
        let err = adopt_listener(fd, &addr.to_string()).unwrap_err();
        assert!(err.contains("not an open file descriptor"), "{err}");
    }

    #[tokio::test]
    async fn rejects_standard_streams() {
        for fd in 0..3 {
            let err = adopt_listener(fd, "127.0.0.1:20049").unwrap_err();
            assert!(err.contains("standard stream"), "{err}");
        }
    }

    #[tokio::test]
    async fn rejects_invalid_listen_address() {
        let (fd, _) = bound_socket();
        let err = adopt_listener(fd, "not-an-address").unwrap_err();
        assert!(err.contains("Invalid listen address"), "{err}");
    }

    #[tokio::test]
    async fn listener_for_binds_without_fd() {
        let addr = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        let listener = listener_for(None, &addr.to_string()).await;
        assert_eq!(addr, listener.local_addr().unwrap());
    }

    #[tokio::test]
    async fn listener_for_adopts_fd() {
        let (fd, addr) = bound_socket();
        let listener = listener_for(Some(fd), &addr.to_string()).await;
        assert_eq!(addr, listener.local_addr().unwrap());
    }

    #[tokio::test]
    #[should_panic(expected = "Failed to use inherited listen socket")]
    async fn listener_for_panics_on_bad_fd() {
        let (fd, addr) = bound_socket();
        let other = SocketAddr::new(addr.ip(), addr.port().wrapping_add(1).max(1));
        listener_for(Some(fd), &other.to_string()).await;
    }

    #[tokio::test]
    #[should_panic(expected = "Failed to bind")]
    async fn listener_for_panics_when_port_taken() {
        let taken = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = taken.local_addr().unwrap();
        listener_for(None, &addr.to_string()).await;
    }
}

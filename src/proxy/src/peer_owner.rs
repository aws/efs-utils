//! Admit only the local kernel NFS client on the efs-proxy loopback port.
//!
//! The kernel client's socket is owned by uid 0. The owner is read with INET_DIAG on
//! Linux and the `net.inet.tcp.pcblist_n` sysctl on macOS; an owner that cannot be
//! read is rejected.

use std::io;
#[cfg(target_os = "linux")]
use std::net::IpAddr;
use std::net::SocketAddr;
#[cfg(target_os = "linux")]
use std::os::fd::RawFd;

#[cfg(any(target_os = "macos", test))]
mod pcblist;

/// Where the owner is read from, for reject messages.
#[cfg(target_os = "linux")]
const OWNER_SOURCE: &str = "INET_DIAG";
#[cfg(target_os = "macos")]
const OWNER_SOURCE: &str = "net.inet.tcp.pcblist_n";
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
const OWNER_SOURCE: &str = "the socket owner lookup";

#[cfg(target_os = "linux")]
const NETLINK_SOCK_DIAG: libc::c_int = 4;
#[cfg(target_os = "linux")]
const SOCK_DIAG_BY_FAMILY: u16 = 20;
#[cfg(target_os = "linux")]
const NLMSG_ERROR: u16 = 2;
#[cfg(target_os = "linux")]
const NLMSG_DONE: u16 = 3;
#[cfg(target_os = "linux")]
const NLM_F_REQUEST: u16 = 0x001;
// Established sockets only.
#[cfg(target_os = "linux")]
const TCP_STATES_ESTABLISHED: u32 = 1 << 1;
// Match by 4-tuple, not by cookie.
#[cfg(target_os = "linux")]
const INET_DIAG_NOCOOKIE: u32 = 0xffff_ffff;

/// The owner of a live TCP socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SocketOwner {
    /// The socket credential's uid: `idiag_uid` on Linux, `so_uid` on macOS.
    pub uid: u32,
}

/// Whether to admit a peer accepted on the loopback listener.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerVerdict {
    /// The peer is the local kernel NFS client.
    Admit,
    /// The peer is not the kernel NFS client, or its owner could not be read.
    Reject(String),
}

/// Decide whether `peer`, accepted on `listen`, is the kernel NFS client. Blocking;
/// call from `spawn_blocking`.
pub fn verify_loopback_peer(peer: SocketAddr, listen: SocketAddr) -> PeerVerdict {
    decide(peer, || socket_owner(peer, listen))
}

/// Admit only a loopback peer whose socket is found and owned by uid 0.
fn decide(
    peer: SocketAddr,
    lookup: impl FnOnce() -> io::Result<Option<SocketOwner>>,
) -> PeerVerdict {
    if !peer.ip().is_loopback() {
        return PeerVerdict::Reject(format!("peer {peer} is not a loopback address"));
    }
    match lookup() {
        Ok(Some(owner)) if owner.uid == 0 => PeerVerdict::Admit,
        Ok(Some(owner)) => PeerVerdict::Reject(format!(
            "peer {peer} socket is owned by uid {}, not the kernel (uid 0)",
            owner.uid
        )),
        Ok(None) => PeerVerdict::Reject(format!("peer {peer} was not found by {OWNER_SOURCE}")),
        Err(e) => PeerVerdict::Reject(format!("{OWNER_SOURCE} query failed: {e}")),
    }
}

/// Look up the TCP socket from `peer` to `listen`. `Ok(None)` means no such socket.
#[cfg(target_os = "linux")]
fn socket_owner(peer: SocketAddr, listen: SocketAddr) -> io::Result<Option<SocketOwner>> {
    let fd = NetlinkFd::open()?;
    query_with(&mut |q| fd.send(q), &mut |b| fd.recv(b), peer, listen)
}

/// Look up the TCP socket from `peer` to `listen`. `Ok(None)` means no such socket.
#[cfg(target_os = "macos")]
fn socket_owner(peer: SocketAddr, listen: SocketAddr) -> io::Result<Option<SocketOwner>> {
    pcblist::socket_owner(peer, listen)
}

/// No owner lookup on this platform, so every peer is rejected.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn socket_owner(_peer: SocketAddr, _listen: SocketAddr) -> io::Result<Option<SocketOwner>> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "no socket owner lookup on this platform",
    ))
}

/// Send the query and parse the reply. Fails on a closed socket or an oversized
/// reply.
#[cfg(target_os = "linux")]
fn query_with(
    send: &mut dyn FnMut(&[u8]) -> io::Result<()>,
    recv: &mut dyn FnMut(&mut [u8]) -> io::Result<usize>,
    peer: SocketAddr,
    listen: SocketAddr,
) -> io::Result<Option<SocketOwner>> {
    send(&build_query(peer, listen))?;
    let mut buf = [0u8; 8192];
    let n = recv(&mut buf)?;
    if n == 0 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "netlink socket closed before a reply",
        ));
    }
    // With MSG_TRUNC, `n` is the full reply size.
    if n > buf.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "netlink reply larger than the receive buffer",
        ));
    }
    parse_query_response(&buf[..n], peer, listen)
}

/// Build an `inet_diag_req_v2` exact lookup for this 4-tuple.
#[cfg(target_os = "linux")]
fn build_query(peer: SocketAddr, listen: SocketAddr) -> Vec<u8> {
    let family = match peer.ip() {
        IpAddr::V4(_) => libc::AF_INET as u8,
        IpAddr::V6(_) => libc::AF_INET6 as u8,
    };
    let mut req = Vec::with_capacity(72);
    // nlmsghdr
    req.extend_from_slice(&72u32.to_ne_bytes()); // nlmsg_len
    req.extend_from_slice(&SOCK_DIAG_BY_FAMILY.to_ne_bytes()); // nlmsg_type
    req.extend_from_slice(&NLM_F_REQUEST.to_ne_bytes()); // nlmsg_flags
    req.extend_from_slice(&1u32.to_ne_bytes()); // nlmsg_seq
    req.extend_from_slice(&0u32.to_ne_bytes()); // nlmsg_pid
                                                // inet_diag_req_v2
    req.push(family); // sdiag_family
    req.push(libc::IPPROTO_TCP as u8); // sdiag_protocol
    req.push(0); // idiag_ext
    req.push(0); // pad
    req.extend_from_slice(&TCP_STATES_ESTABLISHED.to_ne_bytes()); // idiag_states
                                                                  // inet_diag_sockid
    req.extend_from_slice(&peer.port().to_be_bytes()); // idiag_sport
    req.extend_from_slice(&listen.port().to_be_bytes()); // idiag_dport
    req.extend_from_slice(&ip_to_16(peer.ip())); // idiag_src
    req.extend_from_slice(&ip_to_16(listen.ip())); // idiag_dst
    req.extend_from_slice(&0u32.to_ne_bytes()); // idiag_if
    req.extend_from_slice(&INET_DIAG_NOCOOKIE.to_ne_bytes()); // idiag_cookie[0]
    req.extend_from_slice(&INET_DIAG_NOCOOKIE.to_ne_bytes()); // idiag_cookie[1]
    debug_assert_eq!(req.len(), 72);
    req
}

/// An IP address as INET_DIAG's 16-byte field.
#[cfg(target_os = "linux")]
fn ip_to_16(ip: IpAddr) -> [u8; 16] {
    let mut out = [0u8; 16];
    match ip {
        IpAddr::V4(v4) => out[..4].copy_from_slice(&v4.octets()),
        IpAddr::V6(v6) => out.copy_from_slice(&v6.octets()),
    }
    out
}

/// Parse the reply: the owner, or `None` if the socket does not exist.
#[cfg(target_os = "linux")]
fn parse_query_response(
    mut data: &[u8],
    peer: SocketAddr,
    listen: SocketAddr,
) -> io::Result<Option<SocketOwner>> {
    while data.len() >= 16 {
        // nlmsghdr: len(u32) type(u16) flags(u16) seq(u32) pid(u32)
        let len = u32::from_ne_bytes([data[0], data[1], data[2], data[3]]) as usize;
        let mtype = u16::from_ne_bytes([data[4], data[5]]);
        if len < 16 || len > data.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "truncated netlink message",
            ));
        }
        match mtype {
            NLMSG_DONE => return Ok(None),
            NLMSG_ERROR => {
                if len < 20 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "truncated netlink error message",
                    ));
                }
                // 0 is an ACK with no record; otherwise -errno.
                let e = i32::from_ne_bytes([data[16], data[17], data[18], data[19]]);
                if e == 0 || -e == libc::ENOENT {
                    return Ok(None);
                }
                return Err(io::Error::from_raw_os_error(-e));
            }
            SOCK_DIAG_BY_FAMILY => {
                return Ok(parse_inet_diag_msg(&data[16..len], peer, listen));
            }
            _ => {}
        }
        let aligned = (len + 3) & !3;
        if aligned >= data.len() {
            break;
        }
        data = &data[aligned..];
    }
    Ok(None)
}

/// Return the owner of one `inet_diag_msg` if it is the live socket for this
/// 4-tuple.
#[cfg(target_os = "linux")]
fn parse_inet_diag_msg(msg: &[u8], peer: SocketAddr, listen: SocketAddr) -> Option<SocketOwner> {
    // inet_diag_msg:
    //   family(u8) state(u8) timer(u8) retrans(u8)
    //   id: sport(be16) dport(be16) src[16] dst[16] if(u32) cookie[8]
    //   expires(u32) rqueue(u32) wqueue(u32) uid(u32) inode(u32)
    if msg.len() < 72 {
        return None;
    }
    let sport = u16::from_be_bytes([msg[4], msg[5]]);
    let dport = u16::from_be_bytes([msg[6], msg[7]]);
    if sport != peer.port() || dport != listen.port() {
        return None;
    }
    if !addr_matches(&msg[8..24], peer.ip()) || !addr_matches(&msg[24..40], listen.ip()) {
        return None;
    }
    let uid = u32::from_ne_bytes([msg[64], msg[65], msg[66], msg[67]]);
    let inode = u32::from_ne_bytes([msg[68], msg[69], msg[70], msg[71]]);
    // Inode 0 is not a live socket.
    if inode == 0 {
        return None;
    }
    Some(SocketOwner { uid })
}

/// Whether INET_DIAG's 16-byte address field `raw` equals `ip`.
#[cfg(target_os = "linux")]
fn addr_matches(raw: &[u8], ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => raw.len() >= 4 && raw[..4] == v4.octets(),
        IpAddr::V6(v6) => raw.len() >= 16 && raw[..16] == v6.octets(),
    }
}

/// A NETLINK_SOCK_DIAG socket that closes on drop.
#[cfg(target_os = "linux")]
struct NetlinkFd(RawFd);

#[cfg(target_os = "linux")]
impl NetlinkFd {
    fn open() -> io::Result<Self> {
        // SAFETY: socket() takes scalar arguments and returns a new fd or -1.
        let fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                NETLINK_SOCK_DIAG,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let sock = NetlinkFd(fd);
        // Bound recv so a lost reply fails instead of blocking forever.
        let tv = libc::timeval {
            tv_sec: 5,
            tv_usec: 0,
        };
        // SAFETY: setsockopt reads size_of::<timeval>() bytes from &tv.
        let rc = unsafe {
            libc::setsockopt(
                sock.0,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &tv as *const libc::timeval as *const libc::c_void,
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(sock)
    }

    fn send(&self, bytes: &[u8]) -> io::Result<()> {
        retry_on_eintr(|| {
            // SAFETY: send() reads `bytes.len()` bytes from `bytes`.
            syscall_result(unsafe {
                libc::send(
                    self.0,
                    bytes.as_ptr() as *const libc::c_void,
                    bytes.len(),
                    0,
                )
            })
        })
        .map(|_| ())
    }

    fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        // MSG_TRUNC returns the full datagram size so truncation is detectable.
        retry_on_eintr(|| {
            // SAFETY: recv() writes at most `buf.len()` bytes into `buf`.
            syscall_result(unsafe {
                libc::recv(
                    self.0,
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                    libc::MSG_TRUNC,
                )
            })
        })
    }
}

#[cfg(target_os = "linux")]
impl Drop for NetlinkFd {
    fn drop(&mut self) {
        // SAFETY: self.0 is a valid fd this type owns; closed exactly once.
        unsafe { libc::close(self.0) };
    }
}

/// A syscall return value as a result; negative means the error is in `errno`.
#[cfg(target_os = "linux")]
fn syscall_result(ret: isize) -> io::Result<usize> {
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret as usize)
    }
}

/// Retry `op` while it fails with EINTR.
#[cfg(target_os = "linux")]
fn retry_on_eintr(mut op: impl FnMut() -> io::Result<usize>) -> io::Result<usize> {
    loop {
        match op() {
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            other => return other,
        }
    }
}

// GRCOV_BEGIN_COVERAGE
#[cfg(test)]
mod test {
    use super::*;
    use std::io::Write;
    use std::net::{TcpListener, TcpStream};

    #[test]
    fn rejects_a_non_root_peer() {
        // Run as root, this test peer is uid 0 and is admitted by design.
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(listen).unwrap();
        let (_server, _) = listener.accept().unwrap();
        let peer = client.local_addr().unwrap();

        let verdict = verify_loopback_peer(peer, listen);
        assert!(matches!(verdict, PeerVerdict::Reject(_)), "{verdict:?}");
        let _ = client.write(b"x");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn build_query_is_well_formed() {
        let peer: SocketAddr = "127.0.0.1:50000".parse().unwrap();
        let listen: SocketAddr = "127.0.0.1:20049".parse().unwrap();
        let q = build_query(peer, listen);
        assert_eq!(q.len(), 72);
        assert_eq!(u32::from_ne_bytes([q[0], q[1], q[2], q[3]]), 72);
        assert_eq!(u16::from_ne_bytes([q[4], q[5]]), SOCK_DIAG_BY_FAMILY);
        assert_eq!(u16::from_ne_bytes([q[6], q[7]]), NLM_F_REQUEST);
        assert_eq!(q[16], libc::AF_INET as u8);
        assert_eq!(q[17], libc::IPPROTO_TCP as u8);
        assert_eq!(u16::from_be_bytes([q[24], q[25]]), 50000);
        assert_eq!(u16::from_be_bytes([q[26], q[27]]), 20049);
        assert_eq!(&q[28..32], &[127, 0, 0, 1]);
        assert_eq!(
            u32::from_ne_bytes([q[64], q[65], q[66], q[67]]),
            INET_DIAG_NOCOOKIE
        );
        assert_eq!(
            u32::from_ne_bytes([q[68], q[69], q[70], q[71]]),
            INET_DIAG_NOCOOKIE
        );
    }

    #[cfg(target_os = "linux")]
    fn fake_msg(peer: SocketAddr, listen: SocketAddr, uid: u32, inode: u32) -> [u8; 72] {
        let mut m = [0u8; 72];
        m[4..6].copy_from_slice(&peer.port().to_be_bytes());
        m[6..8].copy_from_slice(&listen.port().to_be_bytes());
        if let IpAddr::V4(v4) = peer.ip() {
            m[8..12].copy_from_slice(&v4.octets());
        }
        if let IpAddr::V4(v4) = listen.ip() {
            m[24..28].copy_from_slice(&v4.octets());
        }
        m[64..68].copy_from_slice(&uid.to_ne_bytes());
        m[68..72].copy_from_slice(&inode.to_ne_bytes());
        m
    }

    #[cfg(target_os = "linux")]
    // Wrap a payload in an nlmsghdr, padded to 4 bytes.
    fn nlmsg(mtype: u16, payload: &[u8]) -> Vec<u8> {
        let len = 16 + payload.len();
        let mut m = Vec::new();
        m.extend_from_slice(&(len as u32).to_ne_bytes());
        m.extend_from_slice(&mtype.to_ne_bytes());
        m.extend_from_slice(&0u16.to_ne_bytes());
        m.extend_from_slice(&0u32.to_ne_bytes());
        m.extend_from_slice(&0u32.to_ne_bytes());
        m.extend_from_slice(payload);
        while m.len() % 4 != 0 {
            m.push(0);
        }
        m
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parse_response_returns_the_owner() {
        let peer: SocketAddr = "127.0.0.1:50000".parse().unwrap();
        let listen: SocketAddr = "127.0.0.1:20049".parse().unwrap();
        let reply = nlmsg(SOCK_DIAG_BY_FAMILY, &fake_msg(peer, listen, 0, 4242));
        assert_eq!(
            parse_query_response(&reply, peer, listen).unwrap(),
            Some(SocketOwner { uid: 0 })
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parse_response_skips_inode_zero_record() {
        let peer: SocketAddr = "127.0.0.1:50000".parse().unwrap();
        let listen: SocketAddr = "127.0.0.1:20049".parse().unwrap();
        let reply = nlmsg(SOCK_DIAG_BY_FAMILY, &fake_msg(peer, listen, 0, 0));
        assert_eq!(parse_query_response(&reply, peer, listen).unwrap(), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parse_response_treats_enoent_as_not_found() {
        let peer: SocketAddr = "127.0.0.1:50000".parse().unwrap();
        let listen: SocketAddr = "127.0.0.1:20049".parse().unwrap();
        let reply = nlmsg(NLMSG_ERROR, &(-libc::ENOENT).to_ne_bytes());
        assert_eq!(parse_query_response(&reply, peer, listen).unwrap(), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parse_response_surfaces_other_errors() {
        let peer: SocketAddr = "127.0.0.1:50000".parse().unwrap();
        let listen: SocketAddr = "127.0.0.1:20049".parse().unwrap();
        let reply = nlmsg(NLMSG_ERROR, &(-libc::EPERM).to_ne_bytes());
        assert!(parse_query_response(&reply, peer, listen).is_err());
    }

    fn owner(uid: u32) -> io::Result<Option<SocketOwner>> {
        Ok(Some(SocketOwner { uid }))
    }

    #[test]
    fn decide_admits_only_a_uid0_loopback_socket() {
        let lo: SocketAddr = "127.0.0.1:50000".parse().unwrap();
        let remote: SocketAddr = "10.0.0.5:50000".parse().unwrap();

        assert_eq!(decide(lo, || owner(0)), PeerVerdict::Admit);
        let rejected = [
            decide(remote, || owner(0)),
            decide(lo, || Ok(None)),
            decide(lo, || Err(io::Error::from_raw_os_error(libc::EACCES))),
            decide(lo, || owner(1000)),
        ];
        for verdict in rejected {
            assert!(matches!(verdict, PeerVerdict::Reject(_)), "{verdict:?}");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn query_sends_the_request_and_fails_closed_on_bad_replies() {
        let peer: SocketAddr = "127.0.0.1:50000".parse().unwrap();
        let listen: SocketAddr = "127.0.0.1:20049".parse().unwrap();
        let reply = nlmsg(SOCK_DIAG_BY_FAMILY, &fake_msg(peer, listen, 0, 4242));

        let mut sent = Vec::new();
        let mut send = |q: &[u8]| {
            sent = q.to_vec();
            Ok(())
        };
        let mut recv = |b: &mut [u8]| {
            b[..reply.len()].copy_from_slice(&reply);
            Ok(reply.len())
        };
        assert_eq!(
            query_with(&mut send, &mut recv, peer, listen).unwrap(),
            Some(SocketOwner { uid: 0 })
        );
        assert_eq!(sent, build_query(peer, listen));

        // A closed socket, and an oversized reply.
        for n in [0usize, 70000] {
            let mut send = |_: &[u8]| Ok(());
            let mut recv = |_: &mut [u8]| Ok(n);
            assert!(query_with(&mut send, &mut recv, peer, listen).is_err());
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parse_response_handles_malformed_and_unrelated_messages() {
        let peer: SocketAddr = "127.0.0.1:50000".parse().unwrap();
        let listen: SocketAddr = "127.0.0.1:20049".parse().unwrap();
        let other_port: SocketAddr = "127.0.0.1:50001".parse().unwrap();
        let other_ip: SocketAddr = "127.0.0.2:50000".parse().unwrap();

        let mut bad = nlmsg(NLMSG_DONE, &[]);
        bad[0..4].copy_from_slice(&999u32.to_ne_bytes());
        assert!(parse_query_response(&bad, peer, listen).is_err());
        assert!(parse_query_response(&nlmsg(NLMSG_ERROR, &[]), peer, listen).is_err());
        assert_eq!(
            parse_query_response(&nlmsg(NLMSG_DONE, &[]), peer, listen).unwrap(),
            None
        );
        let ack = nlmsg(NLMSG_ERROR, &0i32.to_ne_bytes());
        assert_eq!(parse_query_response(&ack, peer, listen).unwrap(), None);
        let short = nlmsg(SOCK_DIAG_BY_FAMILY, &[0u8; 8]);
        assert_eq!(parse_query_response(&short, peer, listen).unwrap(), None);
        for wrong in [other_port, other_ip] {
            let reply = nlmsg(SOCK_DIAG_BY_FAMILY, &fake_msg(wrong, listen, 0, 9));
            assert_eq!(parse_query_response(&reply, peer, listen).unwrap(), None);
        }
        let mut two = nlmsg(0x10, &[1, 2, 3]);
        two.extend_from_slice(&nlmsg(SOCK_DIAG_BY_FAMILY, &fake_msg(peer, listen, 0, 5)));
        assert_eq!(
            parse_query_response(&two, peer, listen).unwrap(),
            Some(SocketOwner { uid: 0 })
        );
        assert_eq!(
            parse_query_response(&nlmsg(0x10, &[1]), peer, listen).unwrap(),
            None
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn ipv6_peer_is_encoded_and_matched() {
        let peer: SocketAddr = "[::1]:50000".parse().unwrap();
        let listen: SocketAddr = "[::1]:20049".parse().unwrap();
        let q = build_query(peer, listen);
        assert_eq!(q[16], libc::AF_INET6 as u8);
        assert_eq!(&q[28..44], &std::net::Ipv6Addr::LOCALHOST.octets());

        let mut m = [0u8; 72];
        m[4..6].copy_from_slice(&peer.port().to_be_bytes());
        m[6..8].copy_from_slice(&listen.port().to_be_bytes());
        m[8..24].copy_from_slice(&std::net::Ipv6Addr::LOCALHOST.octets());
        m[24..40].copy_from_slice(&std::net::Ipv6Addr::LOCALHOST.octets());
        m[68..72].copy_from_slice(&11u32.to_ne_bytes());
        assert_eq!(
            parse_inet_diag_msg(&m, peer, listen),
            Some(SocketOwner { uid: 0 })
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn syscalls_retry_on_eintr_and_report_errors() {
        let mut calls = 0;
        let r = retry_on_eintr(|| {
            calls += 1;
            if calls < 3 {
                Err(io::Error::from(io::ErrorKind::Interrupted))
            } else {
                Ok(7)
            }
        });
        assert_eq!((r.unwrap(), calls), (7, 3));
        assert!(retry_on_eintr(|| Err(io::Error::from_raw_os_error(libc::EBADF))).is_err());
        assert_eq!(syscall_result(5).unwrap(), 5);
        assert!(syscall_result(-1).is_err());
    }
}

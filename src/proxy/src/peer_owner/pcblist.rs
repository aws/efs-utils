//! The TCP socket owner from macOS's `net.inet.tcp.pcblist_n` sysctl, the table
//! `netstat` reads. Offsets are XNU's `xinpgen`, `xinpcb_n`, `xsocket_n` and
//! `xtcpcb_n`, which the kernel packs to 4 bytes and emits 8-byte aligned. Each
//! record carries its own length; a length other than the one these offsets
//! were taken from fails the lookup, so a layout change rejects every peer.

use std::io;
use std::net::{IpAddr, SocketAddr};

use super::SocketOwner;

const XINPGEN_LEN: usize = 24;
const XSO_SOCKET: u32 = 0x001;
const XSO_INPCB: u32 = 0x010;
const XSO_TCPCB: u32 = 0x020;
const INP_IPV4: u8 = 0x1;
const INP_IPV6: u8 = 0x2;
const TCPS_ESTABLISHED: i32 = 4;

// xinpcb_n
const INP_FPORT: usize = 16;
const INP_LPORT: usize = 18;
const INP_VFLAG: usize = 44;
const INP_FADDR: usize = 48;
const INP_LADDR: usize = 64;
const XINPCB_LEN: usize = 104;
// xsocket_n
const XSO_SO: usize = 8;
const SO_UID: usize = 64;
const XSOCKET_LEN: usize = 104;
// xtcpcb_n
const T_STATE: usize = 36;
const XTCPCB_LEN: usize = 204;

/// Read the table and return the owner of the live socket from `peer` to `listen`.
#[cfg(target_os = "macos")]
pub(super) fn socket_owner(
    peer: SocketAddr,
    listen: SocketAddr,
) -> io::Result<Option<SocketOwner>> {
    parse_pcblist(&read_pcblist()?, peer, listen)
}

/// The raw `net.inet.tcp.pcblist_n` table.
#[cfg(target_os = "macos")]
fn read_pcblist() -> io::Result<Vec<u8>> {
    const NAME: &[u8] = b"net.inet.tcp.pcblist_n\0";
    // The table can grow between the size probe and the read, which fails with ENOMEM.
    for _ in 0..3 {
        let mut len: libc::size_t = 0;
        // SAFETY: NAME is NUL-terminated; a null oldp only asks for the size.
        let rc = unsafe {
            libc::sysctlbyname(
                NAME.as_ptr().cast(),
                std::ptr::null_mut(),
                &mut len,
                std::ptr::null_mut(),
                0,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        len += len / 4;
        let mut buf = vec![0u8; len];
        // SAFETY: the kernel writes at most `len` bytes into `buf` and stores the count in `len`.
        let rc = unsafe {
            libc::sysctlbyname(
                NAME.as_ptr().cast(),
                buf.as_mut_ptr().cast(),
                &mut len,
                std::ptr::null_mut(),
                0,
            )
        };
        if rc == 0 {
            buf.truncate(len);
            return Ok(buf);
        }
        let err = io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::ENOMEM) {
            return Err(err);
        }
    }
    Err(io::Error::other("net.inet.tcp.pcblist_n kept growing"))
}

/// One pcb's fields, from its `xinpcb_n`, `xsocket_n` and `xtcpcb_n` records.
#[derive(Default)]
struct Pcb {
    matches: bool,
    so: u64,
    uid: u32,
    state: Option<i32>,
}

impl Pcb {
    /// The owner if this is the live, established socket for the 4-tuple.
    fn owner(&self) -> Option<SocketOwner> {
        // A pcb with no socket, or a userland flow, reports xso_so and so_uid as
        // 0, so its uid says nothing about the owner.
        (self.matches && self.so != 0 && self.state == Some(TCPS_ESTABLISHED))
            .then_some(SocketOwner { uid: self.uid })
    }
}

/// Parse the table: the owner of the socket from `peer` to `listen`, or `None` if
/// there is none. A malformed table, or more than one live match, is an error.
fn parse_pcblist(
    data: &[u8],
    peer: SocketAddr,
    listen: SocketAddr,
) -> io::Result<Option<SocketOwner>> {
    if data.len() < XINPGEN_LEN || u32_at(data, 0) as usize != XINPGEN_LEN {
        return Err(invalid("pcblist_n reply has no xinpgen header"));
    }
    // An empty table has no closing xinpgen.
    if u32_at(data, 4) == 0 {
        return Ok(None);
    }
    let mut found = None;
    let mut pcb: Option<Pcb> = None;
    let mut off = XINPGEN_LEN;
    loop {
        if off + 8 > data.len() {
            return Err(invalid("pcblist_n reply has no closing xinpgen"));
        }
        let len = u32_at(data, off) as usize;
        // The closing xinpgen; no record has its length.
        if len == XINPGEN_LEN {
            break;
        }
        if len < 8 || len > data.len() - off {
            return Err(invalid("truncated pcblist_n record"));
        }
        let rec = &data[off..off + len];
        match u32_at(rec, 4) {
            XSO_INPCB => {
                add_owner(&mut found, pcb.take())?;
                if len != XINPCB_LEN {
                    return Err(invalid("unexpected xinpcb_n length"));
                }
                pcb = Some(Pcb {
                    matches: inpcb_matches(rec, peer, listen),
                    ..Pcb::default()
                });
            }
            XSO_SOCKET => {
                if len != XSOCKET_LEN {
                    return Err(invalid("unexpected xsocket_n length"));
                }
                if let Some(p) = pcb.as_mut() {
                    p.so = u64_at(rec, XSO_SO);
                    p.uid = u32_at(rec, SO_UID);
                }
            }
            XSO_TCPCB => {
                if len != XTCPCB_LEN {
                    return Err(invalid("unexpected xtcpcb_n length"));
                }
                if let Some(p) = pcb.as_mut() {
                    p.state = Some(u32_at(rec, T_STATE) as i32);
                }
            }
            _ => {}
        }
        off += (len + 7) & !7;
    }
    add_owner(&mut found, pcb.take())?;
    Ok(found)
}

/// Record `pcb`'s owner in `found`. Two live sockets for one 4-tuple is an error.
fn add_owner(found: &mut Option<SocketOwner>, pcb: Option<Pcb>) -> io::Result<()> {
    if let Some(owner) = pcb.and_then(|p| p.owner()) {
        if found.replace(owner).is_some() {
            return Err(invalid("more than one live socket matches the peer"));
        }
    }
    Ok(())
}

/// Whether an `xinpcb_n` is the socket whose local end is `peer` and foreign end is
/// `listen`. Ports are in network byte order.
fn inpcb_matches(rec: &[u8], peer: SocketAddr, listen: SocketAddr) -> bool {
    let fport = u16::from_be_bytes([rec[INP_FPORT], rec[INP_FPORT + 1]]);
    let lport = u16::from_be_bytes([rec[INP_LPORT], rec[INP_LPORT + 1]]);
    let vflag = rec[INP_VFLAG];
    lport == peer.port()
        && fport == listen.port()
        && addr_matches(&rec[INP_LADDR..INP_LADDR + 16], vflag, peer.ip())
        && addr_matches(&rec[INP_FADDR..INP_FADDR + 16], vflag, listen.ip())
}

/// Whether a 16-byte `xinpcb_n` address equals `ip`. An IPv4 address sits in the
/// last 4 bytes (`in_addr_4in6`).
fn addr_matches(raw: &[u8], vflag: u8, ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => vflag & INP_IPV4 != 0 && raw[12..16] == v4.octets(),
        IpAddr::V6(v6) => vflag & INP_IPV6 != 0 && raw[..16] == v6.octets(),
    }
}

fn u32_at(b: &[u8], off: usize) -> u32 {
    u32::from_ne_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

fn u64_at(b: &[u8], off: usize) -> u64 {
    let mut v = [0u8; 8];
    v.copy_from_slice(&b[off..off + 8]);
    u64::from_ne_bytes(v)
}

fn invalid(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.to_string())
}

// GRCOV_BEGIN_COVERAGE
#[cfg(test)]
mod test {
    use super::*;

    const PEER: &str = "127.0.0.1:50000";
    const LISTEN: &str = "127.0.0.1:20049";

    fn addrs() -> (SocketAddr, SocketAddr) {
        (PEER.parse().unwrap(), LISTEN.parse().unwrap())
    }

    fn header(count: u32) -> Vec<u8> {
        let mut h = vec![0u8; XINPGEN_LEN];
        h[0..4].copy_from_slice(&(XINPGEN_LEN as u32).to_ne_bytes());
        h[4..8].copy_from_slice(&count.to_ne_bytes());
        h
    }

    fn record(kind: u32, len: usize) -> Vec<u8> {
        let mut r = vec![0u8; (len + 7) & !7];
        r[0..4].copy_from_slice(&(len as u32).to_ne_bytes());
        r[4..8].copy_from_slice(&kind.to_ne_bytes());
        r
    }

    fn put_addr(r: &mut [u8], at: usize, ip: IpAddr) {
        match ip {
            IpAddr::V4(v4) => r[at + 12..at + 16].copy_from_slice(&v4.octets()),
            IpAddr::V6(v6) => r[at..at + 16].copy_from_slice(&v6.octets()),
        }
    }

    /// The records the kernel emits for one TCP pcb: xinpcb_n, xsocket_n, two
    /// xsockbuf_n, xsockstat_n and xtcpcb_n.
    fn pcb(local: SocketAddr, foreign: SocketAddr, so: u64, uid: u32, state: i32) -> Vec<u8> {
        let mut inp = record(XSO_INPCB, XINPCB_LEN);
        inp[INP_FPORT..INP_FPORT + 2].copy_from_slice(&foreign.port().to_be_bytes());
        inp[INP_LPORT..INP_LPORT + 2].copy_from_slice(&local.port().to_be_bytes());
        inp[INP_VFLAG] = if local.is_ipv4() { INP_IPV4 } else { INP_IPV6 };
        put_addr(&mut inp, INP_FADDR, foreign.ip());
        put_addr(&mut inp, INP_LADDR, local.ip());
        let mut xso = record(XSO_SOCKET, XSOCKET_LEN);
        xso[XSO_SO..XSO_SO + 8].copy_from_slice(&so.to_ne_bytes());
        xso[SO_UID..SO_UID + 4].copy_from_slice(&uid.to_ne_bytes());
        let mut xt = record(XSO_TCPCB, XTCPCB_LEN);
        xt[T_STATE..T_STATE + 4].copy_from_slice(&state.to_ne_bytes());
        [
            inp,
            xso,
            record(0x002, 32),
            record(0x004, 32),
            record(0x008, 136),
            xt,
        ]
        .concat()
    }

    fn table(pcbs: &[Vec<u8>]) -> Vec<u8> {
        [
            header(pcbs.len() as u32),
            pcbs.concat(),
            header(pcbs.len() as u32),
        ]
        .concat()
    }

    #[test]
    fn returns_the_owner_of_the_matching_socket() {
        let (peer, listen) = addrs();
        let other: SocketAddr = "127.0.0.1:50001".parse().unwrap();
        // The proxy's own accepted socket is the same connection, reversed.
        let data = table(&[
            pcb(other, listen, 0x10, 1000, TCPS_ESTABLISHED),
            pcb(listen, peer, 0x20, 0, TCPS_ESTABLISHED),
            pcb(peer, listen, 0x30, 501, TCPS_ESTABLISHED),
        ]);
        assert_eq!(
            parse_pcblist(&data, peer, listen).unwrap(),
            Some(SocketOwner { uid: 501 })
        );
    }

    #[test]
    fn skips_socketless_and_unestablished_pcbs() {
        let (peer, listen) = addrs();
        // TIME_WAIT and userland flows report xso_so 0 and uid 0.
        for p in [
            pcb(peer, listen, 0, 0, TCPS_ESTABLISHED),
            pcb(peer, listen, 0x30, 0, 10),
        ] {
            assert_eq!(parse_pcblist(&table(&[p]), peer, listen).unwrap(), None);
        }
        let data = table(&[
            pcb(peer, listen, 0, 0, TCPS_ESTABLISHED),
            pcb(peer, listen, 0x30, 1000, TCPS_ESTABLISHED),
        ]);
        assert_eq!(
            parse_pcblist(&data, peer, listen).unwrap(),
            Some(SocketOwner { uid: 1000 })
        );
    }

    #[test]
    fn two_live_matches_fail_closed() {
        let (peer, listen) = addrs();
        let data = table(&[
            pcb(peer, listen, 0x30, 0, TCPS_ESTABLISHED),
            pcb(peer, listen, 0x40, 0, TCPS_ESTABLISHED),
        ]);
        assert!(parse_pcblist(&data, peer, listen).is_err());
    }

    #[test]
    fn matches_ipv6_and_rejects_family_and_address_mismatches() {
        let peer: SocketAddr = "[::1]:50000".parse().unwrap();
        let listen: SocketAddr = "[::1]:20049".parse().unwrap();
        let data = table(&[pcb(peer, listen, 0x30, 0, TCPS_ESTABLISHED)]);
        assert_eq!(
            parse_pcblist(&data, peer, listen).unwrap(),
            Some(SocketOwner { uid: 0 })
        );

        let mut v4flag = pcb(peer, listen, 0x30, 0, TCPS_ESTABLISHED);
        v4flag[INP_VFLAG] = INP_IPV4;
        // Differs from ::1 only in the high bytes, which an IPv4-style compare skips.
        let link_local: SocketAddr = "[fe80::1]:50000".parse().unwrap();
        for p in [v4flag, pcb(link_local, listen, 0x30, 0, TCPS_ESTABLISHED)] {
            assert_eq!(parse_pcblist(&table(&[p]), peer, listen).unwrap(), None);
        }

        let (peer4, listen4) = addrs();
        let mut v6flag = pcb(peer4, listen4, 0x30, 0, TCPS_ESTABLISHED);
        v6flag[INP_VFLAG] = INP_IPV6;
        let other_ip: SocketAddr = "127.0.0.2:50000".parse().unwrap();
        for p in [v6flag, pcb(other_ip, listen4, 0x30, 0, TCPS_ESTABLISHED)] {
            assert_eq!(parse_pcblist(&table(&[p]), peer4, listen4).unwrap(), None);
        }
    }

    #[test]
    fn foreign_end_must_be_the_listener() {
        let (peer, listen) = addrs();
        let other_port: SocketAddr = "127.0.0.1:20050".parse().unwrap();
        let other_ip: SocketAddr = "127.0.0.2:20049".parse().unwrap();
        for foreign in [other_port, other_ip] {
            let data = table(&[pcb(peer, foreign, 0x30, 0, TCPS_ESTABLISHED)]);
            assert_eq!(parse_pcblist(&data, peer, listen).unwrap(), None);
        }
    }

    // Checks the struct offsets against the running kernel: both ends of a real
    // loopback connection are owned by this process. Run as root the uid is 0, so
    // only a non-root run checks the so_uid offset.
    #[cfg(target_os = "macos")]
    #[test]
    fn live_table_reports_this_process_uid() {
        use std::net::{TcpListener, TcpStream};

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen = listener.local_addr().unwrap();
        let client = TcpStream::connect(listen).unwrap();
        let (_server, _) = listener.accept().unwrap();
        let peer = client.local_addr().unwrap();
        // SAFETY: geteuid has no preconditions.
        let uid = unsafe { libc::geteuid() };

        assert_eq!(
            socket_owner(peer, listen).unwrap(),
            Some(SocketOwner { uid })
        );
        assert_eq!(
            socket_owner(listen, peer).unwrap(),
            Some(SocketOwner { uid })
        );
        // Nothing connects from port 1 to this listener's fresh port.
        let unused: SocketAddr = "127.0.0.1:1".parse().unwrap();
        assert_eq!(socket_owner(unused, listen).unwrap(), None);
    }

    #[test]
    fn empty_table_has_no_owner() {
        let (peer, listen) = addrs();
        assert_eq!(parse_pcblist(&header(0), peer, listen).unwrap(), None);
    }

    #[test]
    fn malformed_tables_fail_closed() {
        let (peer, listen) = addrs();
        let good = table(&[pcb(peer, listen, 0x30, 0, TCPS_ESTABLISHED)]);

        let mut bad_header = good.clone();
        bad_header[0..4].copy_from_slice(&16u32.to_ne_bytes());
        let no_trailer = good[..good.len() - XINPGEN_LEN].to_vec();
        let mut overlong = good.clone();
        overlong[XINPGEN_LEN..XINPGEN_LEN + 4].copy_from_slice(&100_000u32.to_ne_bytes());
        let mut zero_len = good.clone();
        zero_len[XINPGEN_LEN..XINPGEN_LEN + 4].copy_from_slice(&0u32.to_ne_bytes());
        let short_inpcb = table(&[record(XSO_INPCB, 40)]);
        let short_socket =
            table(&[[record(XSO_INPCB, XINPCB_LEN), record(XSO_SOCKET, 40)].concat()]);
        let short_tcpcb = table(&[[record(XSO_INPCB, XINPCB_LEN), record(XSO_TCPCB, 16)].concat()]);
        // A grown record means the layout changed, even if this socket's uid reads 0.
        let mut grown = Vec::new();
        for (kind, len) in [
            (XSO_INPCB, XINPCB_LEN),
            (XSO_SOCKET, XSOCKET_LEN),
            (XSO_TCPCB, XTCPCB_LEN),
        ] {
            let mut p = pcb(peer, listen, 0x30, 0, TCPS_ESTABLISHED);
            let mut off = 0;
            while u32_at(&p, off + 4) != kind {
                off += (u32_at(&p, off) as usize + 7) & !7;
            }
            p[off..off + 4].copy_from_slice(&(len as u32 + 8).to_ne_bytes());
            p.splice(off + len..off + len, [0u8; 8]);
            grown.push(table(&[p]));
        }

        for data in [
            vec![0u8; 8],
            bad_header,
            no_trailer,
            overlong,
            zero_len,
            short_inpcb,
            short_socket,
            short_tcpcb,
        ]
        .into_iter()
        .chain(grown)
        {
            assert!(parse_pcblist(&data, peer, listen).is_err());
        }
    }

    #[test]
    fn records_before_the_first_inpcb_are_ignored() {
        let (peer, listen) = addrs();
        let data = table(&[[
            record(XSO_SOCKET, XSOCKET_LEN),
            record(XSO_TCPCB, XTCPCB_LEN),
            pcb(peer, listen, 0x30, 0, TCPS_ESTABLISHED),
        ]
        .concat()]);
        assert_eq!(
            parse_pcblist(&data, peer, listen).unwrap(),
            Some(SocketOwner { uid: 0 })
        );
    }
}

use log::debug;
use pnet::packet::tcp::TcpFlags::SYN;
use pnet::packet::tcp::TcpPacket;

fn from_client(tcp: &TcpPacket) -> bool {
    tcp.get_flags() & SYN == SYN
}

pub fn extract_from_ipv4(tcp: &TcpPacket, ipv4_header_len: u8, mss: u16) -> Option<u16> {
    if from_client(tcp) {
        let ip_header_len = (ipv4_header_len as u16) * 4; // convert to bytes
        let mut tcp_header_len = (tcp.get_data_offset() as u16) * 4; // convert to bytes
        if tcp_header_len > 20 {
            // If TCP header contains options
            tcp_header_len -= 20;
        }
        let mtu = mss + ip_header_len + tcp_header_len;
        debug!(
            "MTU ipv4 {} - mss: {} - ip_header_len: {} - tcp_header_len: {}",
            mtu, mss, ip_header_len, tcp_header_len
        );
        Some(mtu)
    } else {
        None
    }
}

pub fn extract_from_ipv6(tcp: &TcpPacket, ipv6_header_len: u8, mss: u16) -> Option<u16> {
    if from_client(tcp) {
        let ip_header_len = ipv6_header_len as u16; // ipv6_header_len is in bytes already
        let mut tcp_header_len = (tcp.get_data_offset() as u16) * 4; // convert to bytes
        if tcp_header_len > 20 {
            // If TCP header contains options
            tcp_header_len -= 20;
        }
        let mtu = mss + ip_header_len + tcp_header_len;
        debug!(
            "MTU ipv6 {} - mss: {} - ip_header_len: {} - tcp_header_len: {}",
            mtu, mss, ip_header_len, tcp_header_len
        );
        Some(mtu)
    } else {
        None
    }
}

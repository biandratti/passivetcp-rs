use crate::error::HuginnNetError;
use crate::ip_options::IpOptions;
use crate::observable_signals::ObservableMtu;
use crate::observable_signals::ObservableTcp;
use crate::observable_signals::ObservableUptime;
use crate::tcp::{IpVersion, PayloadSize, Quirk, TcpOption, Ttl, WindowSize};
use crate::uptime::check_ts_tcp;
use crate::uptime::{Connection, SynData};
use crate::window_size::detect_win_multiplicator;
use crate::{mtu, ttl};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::{
    ipv4::{Ipv4Flags, Ipv4Packet},
    ipv6::Ipv6Packet,
    tcp::{TcpFlags, TcpOptionNumbers::*, TcpOptionPacket, TcpPacket},
    Packet, PacketSize,
};
use std::convert::TryInto;
use std::net::IpAddr;
use ttl_cache::TtlCache;

/// Congestion encountered
const IP_TOS_CE: u8 = 0x01;
/// ECN supported
const IP_TOS_ECT: u8 = 0x02;
/// Must be zero
const IP4_MBZ: u8 = 0b0100;

// Internal representation of a TCP package
pub struct ObservableTCPPackage {
    pub tcp_request: Option<ObservableTcp>,
    pub tcp_response: Option<ObservableTcp>,
    pub mtu: Option<ObservableMtu>,
    pub uptime: Option<ObservableUptime>,
}

fn from_client(tcp_flags: u8) -> bool {
    use TcpFlags::*;
    tcp_flags & SYN != 0 && tcp_flags & ACK == 0
}

fn from_server(tcp_flags: u8) -> bool {
    use TcpFlags::*;
    tcp_flags & SYN != 0 && tcp_flags & ACK != 0
}

fn is_valid(tcp_flags: u8, tcp_type: u8) -> bool {
    use TcpFlags::*;

    !(((tcp_flags & SYN) == SYN && (tcp_flags & (FIN | RST)) != 0)
        || (tcp_flags & (FIN | RST)) == (FIN | RST)
        || tcp_type == 0)
}

pub fn process_tcp_ipv4(
    packet: &Ipv4Packet,
    cache: &mut TtlCache<Connection, SynData>,
) -> Result<ObservableTCPPackage, HuginnNetError> {
    if packet.get_next_level_protocol() != IpNextHeaderProtocols::Tcp {
        return Err(HuginnNetError::UnsupportedProtocol("IPv4".to_string()));
    }

    if packet.get_fragment_offset() > 0
        || (packet.get_flags() & Ipv4Flags::MoreFragments) == Ipv4Flags::MoreFragments
    {
        return Err(HuginnNetError::UnexpectedPackage("IPv4".to_string()));
    }

    let version = IpVersion::V4;
    let ttl_observed: u8 = packet.get_ttl();
    let ttl: Ttl = ttl::calculate_ttl(ttl_observed);
    let olen: u8 = IpOptions::calculate_ipv4_length(packet);
    let mut quirks = vec![];

    if (packet.get_ecn() & (IP_TOS_CE | IP_TOS_ECT)) != 0 {
        quirks.push(Quirk::Ecn);
    }

    if (packet.get_flags() & IP4_MBZ) != 0 {
        quirks.push(Quirk::MustBeZero);
    }

    if (packet.get_flags() & Ipv4Flags::DontFragment) != 0 {
        quirks.push(Quirk::Df);

        if packet.get_identification() != 0 {
            quirks.push(Quirk::NonZeroID);
        }
    } else if packet.get_identification() == 0 {
        quirks.push(Quirk::ZeroID);
    }

    let source_ip: IpAddr = IpAddr::V4(packet.get_source());
    let destination_ip = IpAddr::V4(packet.get_destination());

    let tcp_payload = packet.payload(); // Get a reference to the payload without moving `packet`

    let ip_package_header_length: u8 = packet.get_header_length();

    TcpPacket::new(tcp_payload)
        .ok_or_else(|| HuginnNetError::UnexpectedPackage("TCP packet too short".to_string()))
        .and_then(|tcp_packet| {
            visit_tcp(
                cache,
                &tcp_packet,
                version,
                ttl,
                ip_package_header_length,
                olen,
                quirks,
                source_ip,
                destination_ip,
            )
        })
}

pub fn process_tcp_ipv6(
    packet: &Ipv6Packet,
    cache: &mut TtlCache<Connection, SynData>,
) -> Result<ObservableTCPPackage, HuginnNetError> {
    if packet.get_next_header() != IpNextHeaderProtocols::Tcp {
        return Err(HuginnNetError::UnsupportedProtocol("IPv6".to_string()));
    }
    let version = IpVersion::V6;
    let ttl_observed: u8 = packet.get_hop_limit();
    let ttl: Ttl = ttl::calculate_ttl(ttl_observed);
    let olen: u8 = IpOptions::calculate_ipv6_length(packet);
    let mut quirks = vec![];

    if packet.get_flow_label() != 0 {
        quirks.push(Quirk::FlowID);
    }
    if (packet.get_traffic_class() & (IP_TOS_CE | IP_TOS_ECT)) != 0 {
        quirks.push(Quirk::Ecn);
    }

    let source_ip: IpAddr = IpAddr::V6(packet.get_source());
    let destination_ip = IpAddr::V6(packet.get_destination());

    let ip_package_header_length: u8 = 40; //IPv6 header is always 40 bytes

    TcpPacket::new(packet.payload())
        .ok_or_else(|| HuginnNetError::UnexpectedPackage("TCP packet too short".to_string()))
        .and_then(|tcp_packet| {
            visit_tcp(
                cache,
                &tcp_packet,
                version,
                ttl,
                ip_package_header_length,
                olen,
                quirks,
                source_ip,
                destination_ip,
            )
        })
}

#[allow(clippy::too_many_arguments)]
fn visit_tcp(
    cache: &mut TtlCache<Connection, SynData>,
    tcp: &TcpPacket,
    version: IpVersion,
    ittl: Ttl,
    ip_package_header_length: u8,
    olen: u8,
    mut quirks: Vec<Quirk>,
    source_ip: IpAddr,
    destination_ip: IpAddr,
) -> Result<ObservableTCPPackage, HuginnNetError> {
    use TcpFlags::*;

    let flags: u8 = tcp.get_flags();
    let from_client: bool = from_client(flags);
    let from_server: bool = from_server(flags);

    if !from_client && !from_server {
        return Ok(ObservableTCPPackage {
            tcp_request: None,
            tcp_response: None,
            mtu: None,
            uptime: None,
        });
    }
    let tcp_type: u8 = flags & (SYN | ACK | FIN | RST);
    if !is_valid(flags, tcp_type) {
        return Err(HuginnNetError::InvalidTcpFlags(flags));
    }

    if (flags & (ECE | CWR)) != 0 {
        quirks.push(Quirk::Ecn);
    }
    if tcp.get_sequence() == 0 {
        quirks.push(Quirk::SeqNumZero);
    }
    if flags & ACK == ACK {
        if tcp.get_acknowledgement() == 0 {
            quirks.push(Quirk::AckNumZero);
        }
    } else if tcp.get_acknowledgement() != 0 && flags & RST == 0 {
        quirks.push(Quirk::AckNumNonZero);
    }

    if flags & URG == URG {
        quirks.push(Quirk::Urg);
    } else if tcp.get_urgent_ptr() != 0 {
        quirks.push(Quirk::NonZeroURG);
    }

    if flags & PSH == PSH {
        quirks.push(Quirk::Push);
    }

    let mut buf = tcp.get_options_raw();
    let mut mss = None;
    let mut wscale = None;
    let mut olayout = vec![];
    let mut uptime: Option<ObservableUptime> = None;

    while let Some(opt) = TcpOptionPacket::new(buf) {
        buf = &buf[opt.packet_size().min(buf.len())..];

        let data: &[u8] = opt.payload();

        match opt.get_number() {
            EOL => {
                olayout.push(TcpOption::Eol(buf.len() as u8));

                if buf.iter().any(|&b| b != 0) {
                    quirks.push(Quirk::TrailinigNonZero);
                }
            }
            NOP => {
                olayout.push(TcpOption::Nop);
            }
            MSS => {
                olayout.push(TcpOption::Mss);
                if data.len() >= 2 {
                    let mss_value: u16 = u16::from_be_bytes([data[0], data[1]]);
                    //quirks.push(Quirk::mss);
                    mss = Some(mss_value);
                }

                /*if data.len() != 4 {
                    quirks.push(Quirk::OptBad);
                }*/
            }
            WSCALE => {
                olayout.push(TcpOption::Ws);

                wscale = Some(data[0]);

                if data[0] > 14 {
                    quirks.push(Quirk::ExcessiveWindowScaling);
                }
                /*if data.len() != 3 {
                    quirks.push(Quirk::OptBad);
                }*/
            }
            SACK_PERMITTED => {
                olayout.push(TcpOption::Sok);

                /*if data.len() != 2 {
                    quirks.push(Quirk::OptBad);
                }*/
            }
            SACK => {
                olayout.push(TcpOption::Sack);

                /*match data.len() {
                    10 | 18 | 26 | 34 => {}
                    _ => quirks.push(Quirk::OptBad),
                }*/
            }
            TIMESTAMPS => {
                olayout.push(TcpOption::TS);

                if data.len() >= 4 {
                    let ts_val_bytes: [u8; 4] = data[..4].try_into().map_err(|_| {
                        HuginnNetError::Parse(
                            "Failed to convert slice to array for timestamp value".to_string(),
                        )
                    })?;
                    if u32::from_ne_bytes(ts_val_bytes) == 0 {
                        quirks.push(Quirk::OwnTimestampZero);
                    }
                }

                if data.len() >= 8 && tcp_type == SYN {
                    let ts_peer_bytes: [u8; 4] = data[4..8].try_into().map_err(|_| {
                        HuginnNetError::Parse(
                            "Failed to convert slice to array for peer timestamp value".to_string(),
                        )
                    })?;
                    if u32::from_ne_bytes(ts_peer_bytes) != 0 {
                        quirks.push(Quirk::PeerTimestampNonZero);
                    }
                }

                if data.len() >= 8 {
                    let ts_val_bytes: [u8; 4] = data[..4].try_into().map_err(|_| {
                        HuginnNetError::Parse(
                            "Failed to convert slice to array for timestamp value".to_string(),
                        )
                    })?;
                    let ts_val: u32 = u32::from_ne_bytes(ts_val_bytes);
                    let connection: Connection = Connection {
                        src_ip: source_ip,
                        src_port: tcp.get_source(),
                        dst_ip: destination_ip,
                        dst_port: tcp.get_destination(),
                    };
                    uptime = check_ts_tcp(cache, &connection, from_client, ts_val);
                }

                /*if data.len() != 10 {
                    quirks.push(Quirk::OptBad);
                }*/
            }
            _ => {
                olayout.push(TcpOption::Unknown(opt.get_number().0));
            }
        }
    }

    let mtu: Option<ObservableMtu> = match (mss, &version) {
        (Some(mss_value), IpVersion::V4) => {
            mtu::extract_from_ipv4(tcp, ip_package_header_length, mss_value)
        }
        (Some(mss_value), IpVersion::V6) => {
            mtu::extract_from_ipv6(tcp, ip_package_header_length, mss_value)
        }
        _ => None,
    };

    let wsize: WindowSize = detect_win_multiplicator(
        tcp.get_window(),
        mss.unwrap_or(0),
        ip_package_header_length as u16,
        olayout.contains(&TcpOption::TS),
        &version,
    );

    let tcp_signature: ObservableTcp = ObservableTcp {
        version,
        ittl,
        olen,
        mss,
        wsize,
        wscale,
        olayout,
        quirks,
        pclass: if tcp.payload().is_empty() {
            PayloadSize::Zero
        } else {
            PayloadSize::NonZero
        },
    };

    Ok(ObservableTCPPackage {
        tcp_request: if from_client {
            Some(tcp_signature.clone())
        } else {
            None
        },
        tcp_response: if !from_client {
            Some(tcp_signature)
        } else {
            None
        },
        mtu: if from_client { mtu } else { None },
        uptime: if !from_client { uptime } else { None },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_client() {
        assert!(from_client(TcpFlags::SYN));
        assert!(!from_client(TcpFlags::SYN | TcpFlags::ACK));
        assert!(!from_client(TcpFlags::ACK));
    }

    #[test]
    fn test_from_server() {
        assert!(from_server(TcpFlags::SYN | TcpFlags::ACK));
        assert!(!from_server(TcpFlags::SYN));
        assert!(!from_server(TcpFlags::ACK));
        assert!(!from_server(TcpFlags::RST));
    }

    #[test]
    fn test_is_valid() {
        assert!(is_valid(TcpFlags::SYN, TcpFlags::SYN));
        assert!(!is_valid(TcpFlags::SYN | TcpFlags::FIN, TcpFlags::SYN));
        assert!(!is_valid(TcpFlags::SYN | TcpFlags::RST, TcpFlags::SYN));
        assert!(!is_valid(
            TcpFlags::FIN | TcpFlags::RST,
            TcpFlags::FIN | TcpFlags::RST
        ));
        assert!(!is_valid(TcpFlags::SYN, 0));
    }
}

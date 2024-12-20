use crate::mtu;
use crate::mtu::ObservableMtu;
use crate::process::{IpPort, ObservablePackage};
use crate::tcp;
use crate::tcp::{IpVersion, PayloadSize, Quirk, TcpOption, Ttl, WindowSize};
use crate::uptime::{check_ts_tcp, ObservableUptime};
use crate::uptime::{Connection, SynData};
use failure::{bail, err_msg, Error};
use pnet::packet::{
    ipv4::{Ipv4Flags, Ipv4Packet},
    ipv6::Ipv6Packet,
    tcp::{TcpFlags, TcpOptionNumbers::*, TcpOptionPacket, TcpPacket},
    Packet, PacketSize,
};
use std::convert::TryInto;
use std::net::IpAddr;
use ttl_cache::TtlCache;

#[derive(Clone)]
pub struct ObservableTcp {
    pub signature: tcp::Signature,
}

/// Congestion encountered
const IP_TOS_CE: u8 = 0x01;
/// ECN supported
const IP_TOS_ECT: u8 = 0x02;
/// Must be zero
const IP4_MBZ: u8 = 0b0100;

fn from_client(tcp_flags: u8) -> bool {
    tcp_flags & TcpFlags::SYN != 0 && tcp_flags & TcpFlags::ACK == 0
}

pub fn process_tcp_ipv4(
    cache: &mut TtlCache<Connection, SynData>,
    packet: &Ipv4Packet,
) -> Result<ObservablePackage, Error> {
    //if packet.get_next_header() == IpNextHeaderProtocols::Tcp {} //TODO: WIP
    if packet.get_fragment_offset() > 0
        || (packet.get_flags() & Ipv4Flags::MoreFragments) == Ipv4Flags::MoreFragments
    {
        bail!("unsupported IPv4 fragment");
    }

    let version = IpVersion::V4;
    let ttl_value: u8 = packet.get_ttl();
    let ttl = Ttl::Distance(ttl_value, guess_dist(ttl_value)); //TODO: WIP..
    let olen: u8 = packet.get_options_raw().len() as u8;
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
        .ok_or_else(|| err_msg("TCP packet too short"))
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
    cache: &mut TtlCache<Connection, SynData>,
    packet: &Ipv6Packet,
) -> Result<ObservablePackage, Error> {
    //if packet.get_next_header() == IpNextHeaderProtocols::Tcp {} //TODO: WIP
    let version = IpVersion::V6;
    let ttl_value: u8 = packet.get_hop_limit();
    let ttl = Ttl::Distance(ttl_value, guess_dist(ttl_value)); // TODO: WIP
    let olen = 0; // TODO handle extensions
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
        .ok_or_else(|| err_msg("TCP packet too short"))
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

fn guess_dist(ttl: u8) -> u8 {
    if ttl <= 32 {
        32 - ttl
    } else if ttl <= 64 {
        64 - ttl
    } else if ttl <= 128 {
        128 - ttl
    } else {
        255 - ttl
    }
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
) -> Result<ObservablePackage, Error> {
    use TcpFlags::*;

    let flags: u8 = tcp.get_flags();
    let from_client = from_client(flags);
    let tcp_type: u8 = flags & (SYN | ACK | FIN | RST);

    if ((flags & SYN) == SYN && (flags & (FIN | RST)) != 0)
        || (flags & (FIN | RST)) == (FIN | RST)
        || tcp_type == 0
    {
        bail!("invalid TCP flags: {}", flags);
    }

    if (flags & (ECE | CWR)) != 0 {
        //TODO:    if (flags & (ECE | CWR | NS)) != 0 {
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

                if data.len() >= 4 && u32::from_ne_bytes(data[..4].try_into()?) == 0 {
                    quirks.push(Quirk::OwnTimestampZero);
                }

                if data.len() >= 8
                    && tcp_type == SYN
                    && u32::from_ne_bytes(data[4..8].try_into()?) != 0
                {
                    quirks.push(Quirk::PeerTimestampNonZero);
                }

                if data.len() >= 8 {
                    let ts_val: u32 = u32::from_ne_bytes(data[..4].try_into()?);
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

    let source_port = tcp.get_source();
    let destination_port = tcp.get_destination();

    let wsize: WindowSize = match (tcp.get_window(), mss) {
        (wsize, Some(mss_value)) if wsize % mss_value == 0 => {
            WindowSize::Mss((wsize / mss_value) as u8)
        }
        (wsize, _) if mtu.as_ref().map_or(false, |mtu| wsize % mtu.value == 0) => {
            WindowSize::Mtu((wsize / mtu.as_ref().unwrap().value) as u8)
        }
        (wsize, _) => WindowSize::Value(wsize),
    };

    let tcp_signature: ObservableTcp = ObservableTcp {
        signature: tcp::Signature {
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
        },
    };

    Ok(ObservablePackage {
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
        source: IpPort {
            ip: source_ip,
            port: source_port,
        },
        destination: IpPort {
            ip: destination_ip,
            port: destination_port,
        },
        http_request: None,
    })
}

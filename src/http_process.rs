use crate::http;
use failure::Error;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::Packet;
use std::net::IpAddr;
use std::time::{Duration, Instant};
use ttl_cache::TtlCache;

pub type FlowKey = (IpAddr, IpAddr, u16, u16); // (Client IP, Server IP, Client Port, Server Port)

pub struct TcpFlow {
    client_ip: IpAddr,
    server_ip: IpAddr,
    client_port: u16,
    server_port: u16,
    client_seq: u32,
    server_seq: u32,
    client_data: Vec<u8>, // Aggregated HTTP request payload
    server_data: Vec<u8>, // Aggregated HTTP response payload
    last_seen: Instant,   // Timestamp for flow expiration
}

pub fn process_http_ipv4(
    packet: &Ipv4Packet,
    cache: &mut TtlCache<FlowKey, TcpFlow>,
) -> Result<ObservableHttpPackage, Error> {
    if packet.get_next_level_protocol() == IpNextHeaderProtocols::Tcp {
        if let Some(tcp) = TcpPacket::new(packet.payload()) {
            return process_tcp_packet(
                cache,
                tcp,
                IpAddr::V4(packet.get_source()),
                IpAddr::V4(packet.get_destination()),
            );
        }
    }
    Ok(ObservableHttpPackage { http_request: None })
}

pub fn process_http_ipv6(
    packet: &Ipv6Packet,
    cache: &mut TtlCache<FlowKey, TcpFlow>,
) -> Result<ObservableHttpPackage, Error> {
    if packet.get_next_header() == IpNextHeaderProtocols::Tcp {
        if let Some(tcp) = TcpPacket::new(packet.payload()) {
            return process_tcp_packet(
                cache,
                tcp,
                IpAddr::V6(packet.get_source()),
                IpAddr::V6(packet.get_destination()),
            );
        }
    }
    Ok(ObservableHttpPackage { http_request: None })
}

fn process_tcp_packet(
    cache: &mut TtlCache<FlowKey, TcpFlow>,
    tcp: TcpPacket,
    src_ip: IpAddr,
    dst_ip: IpAddr,
) -> Result<ObservableHttpPackage, Error> {
    let src_port = tcp.get_source();
    let dst_port = tcp.get_destination();
    let flow_key = (src_ip, dst_ip, src_port, dst_port);

    if tcp.get_flags() & pnet::packet::tcp::TcpFlags::SYN != 0 {
        //println!("New TCP flow detected: {}:{} -> {}:{}", src_ip, src_port, dst_ip, dst_port);
        let flow = TcpFlow {
            client_ip: src_ip,
            server_ip: dst_ip,
            client_port: src_port,
            server_port: dst_port,
            client_seq: tcp.get_sequence(),
            server_seq: 0,
            client_data: Vec::new(),
            server_data: Vec::new(),
            last_seen: Instant::now(),
        };
        cache.insert(flow_key, flow, Duration::new(60, 0));
        return Ok(ObservableHttpPackage { http_request: None }); //TODO: WIP
    }

    if let Some(flow) = cache.get_mut(&flow_key) {
        flow.last_seen = Instant::now();

        // Handle data payload
        if !tcp.payload().is_empty() {
            if src_ip == flow.client_ip && src_port == flow.client_port {
                flow.client_data.extend_from_slice(tcp.payload());
                if let Ok(request) = std::str::from_utf8(&flow.client_data) {
                    if request.contains("HTTP") {
                        println!("HTTP Request: {}", request);
                    }
                }
            } else {
                flow.server_data.extend_from_slice(tcp.payload());
                if let Ok(response) = std::str::from_utf8(&flow.server_data) {
                    if response.contains("HTTP") {
                        println!("HTTP Response: {}", response);
                    }
                }
            }
        }

        if let Some(flow) = cache.get_mut(&flow_key) {
            flow.last_seen = Instant::now();

            if !tcp.payload().is_empty() {
                //TODO: Process payload here...
            }

            // Check for termination flags
            let should_remove = tcp.get_flags()
                & (pnet::packet::tcp::TcpFlags::FIN | pnet::packet::tcp::TcpFlags::RST)
                != 0;

            if should_remove {
                /*println!(
                    "TCP flow closing or reset: {}:{} -> {}:{}",
                    flow.client_ip, flow.client_port, flow.server_ip, flow.server_port
                );*/
            }
        }

        if tcp.get_flags() & (pnet::packet::tcp::TcpFlags::FIN | pnet::packet::tcp::TcpFlags::RST)
            != 0
        {
            cache.remove(&flow_key);
        }
    } else {
        // TODO: Handle case where packet belongs to an untracked flow
        /*println!(
            "Untracked TCP flow: {}:{} -> {}:{}",
            src_ip, src_port, dst_ip, dst_port
        );*/
    }
    Ok(ObservableHttpPackage { http_request: None }) //TODO: WIP
}

pub struct ObservableHttpPackage {
    http_request: Option<ObservableHttpRequest>,
}

pub struct ObservableHttpRequest {
    pub lang: Option<String>,
    pub user_agent: Option<String>,
    pub signature: http::Signature,
}

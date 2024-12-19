use crate::mtu::ObservableMtu;
use crate::tcp_process::{visit_ipv4, visit_ipv6, ObservableTcp};
use crate::uptime::ObservableUptime;
use crate::uptime::{Connection, SynData};
use failure::{bail, err_msg, Error};
use pnet::packet::{
    ethernet::{EtherType, EtherTypes, EthernetPacket},
    ipv4::Ipv4Packet,
    ipv6::Ipv6Packet,
    vlan::VlanPacket,
    Packet,
};
use std::net::IpAddr;
use ttl_cache::TtlCache;
use crate::http_process::ObservableHttpRequest;

#[derive(Clone)]
pub struct IpPort {
    pub ip: IpAddr,
    pub port: u16,
}

pub struct ObservablePackage {
    pub source: IpPort,
    pub destination: IpPort,
    pub tcp_request: Option<ObservableTcp>,
    pub tcp_response: Option<ObservableTcp>,
    pub mtu: Option<ObservableMtu>,
    pub uptime: Option<ObservableUptime>,
    pub http_request: Option<ObservableHttpRequest>,
}
impl ObservablePackage {
    pub fn extract(
        packet: &[u8],
        cache: &mut TtlCache<Connection, SynData>,
    ) -> Result<Self, Error> {
        EthernetPacket::new(packet)
            .ok_or_else(|| err_msg("ethernet packet too short"))
            .and_then(|packet| visit_ethernet(packet.get_ethertype(), cache, packet.payload()))
    }
}

fn visit_ethernet(
    ethertype: EtherType,
    cache: &mut TtlCache<Connection, SynData>,
    payload: &[u8],
) -> Result<ObservablePackage, Error> {
    match ethertype {
        EtherTypes::Vlan => VlanPacket::new(payload)
            .ok_or_else(|| err_msg("vlan packet too short"))
            .and_then(|packet| visit_vlan(cache, packet)),

        EtherTypes::Ipv4 => Ipv4Packet::new(payload)
            .ok_or_else(|| err_msg("ipv4 packet too short"))
            .and_then(|packet| visit_ipv4(cache, packet)),

        EtherTypes::Ipv6 => Ipv6Packet::new(payload)
            .ok_or_else(|| err_msg("ipv6 packet too short"))
            .and_then(|packet| visit_ipv6(cache, packet)),

        ty => bail!("unsupported ethernet type: {}", ty),
    }
}

fn visit_vlan(
    cache: &mut TtlCache<Connection, SynData>,
    packet: VlanPacket,
) -> Result<ObservablePackage, Error> {
    visit_ethernet(packet.get_ethertype(), cache, packet.payload())
}

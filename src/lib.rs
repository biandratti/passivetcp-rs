pub mod db;
mod display;
mod http;
mod http_parser;
mod mtu;
mod p0f_output;
mod packet;
mod parse;
mod signature_matcher;
mod tcp;
mod uptime;

use crate::db::Database;
use crate::p0f_output::{
    HttpRequestOutput, MTUOutput, P0fOutput, SynAckTCPOutput, SynTCPOutput, UptimeOutput,
};
use crate::packet::ObservableSignature;
use crate::signature_matcher::SignatureMatcher;
use crate::uptime::{Connection, SynData};
use log::{debug, error};
use pnet::datalink;
use pnet::datalink::Config;
use std::sync::mpsc::Sender;
use ttl_cache::TtlCache;

pub struct P0f<'a> {
    pub matcher: SignatureMatcher<'a>,
    cache: TtlCache<Connection, SynData>,
}

/// A passive TCP fingerprinting engine inspired by `p0f`.
///
/// The `P0f` struct acts as the core component of the library, handling TCP packet
/// analysis and matching signatures using a database of known fingerprints.
impl<'a> P0f<'a> {
    /// Creates a new instance of `P0f`.
    ///
    /// # Parameters
    /// - `database`: A reference to the database containing known TCP/IP signatures.
    /// - `cache_capacity`: The maximum number of connections to maintain in the TTL cache.
    ///
    /// # Returns
    /// A new `P0f` instance initialized with the given database and cache capacity.
    pub fn new(database: &'a Database, cache_capacity: usize) -> Self {
        let matcher: SignatureMatcher = SignatureMatcher::new(database);
        let cache: TtlCache<Connection, SynData> = TtlCache::new(cache_capacity);
        Self { matcher, cache }
    }

    /// Captures and analyzes packets on the specified network interface.
    ///
    /// Sends `P0fOutput` through the provided channel.
    ///
    /// # Parameters
    /// - `interface_name`: The name of the network interface to analyze.
    /// - `sender`: A `Sender` to send `P0fOutput` objects back to the caller.
    ///
    /// # Panics
    /// - If the network interface cannot be found or a channel cannot be created.
    pub fn analyze_network(&mut self, interface_name: &str, sender: Sender<P0fOutput>) {
        let interfaces = datalink::interfaces();
        let interface = interfaces
            .into_iter()
            .find(|iface| iface.name == interface_name);

        match interface {
            Some(iface) => {
                debug!("Using network interface: {}", iface.name);

                let config = Config {
                    promiscuous: true,
                    ..Config::default()
                };

                let (_tx, mut rx) = match datalink::channel(&iface, config) {
                    Ok(datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
                    Ok(_) => {
                        error!("Unhandled channel type for interface: {}", iface.name);
                        return;
                    }
                    Err(e) => {
                        error!(
                            "Unable to create channel for interface {}: {}",
                            iface.name, e
                        );
                        return;
                    }
                };

                loop {
                    match rx.next() {
                        Ok(packet) => {
                            let output = self.analyze_tcp(packet);
                            if sender.send(output).is_err() {
                                error!("Receiver dropped, stopping packet capture");
                                break;
                            }
                        }
                        Err(e) => {
                            error!("Failed to read packet: {}", e);
                        }
                    }
                }
            }
            None => {
                error!("Could not find the network interface: {}", interface_name);
            }
        }
    }

    fn analyze_tcp(&mut self, packet: &[u8]) -> P0fOutput {
        match ObservableSignature::extract(packet, &mut self.cache) {
            Ok(observable_signature) => {
                let (syn, syn_ack, mtu, uptime, http_request) =
                    if observable_signature.from_client {
                        let mtu = observable_signature.mtu.and_then(|mtu| {
                            self.matcher
                                .matching_by_mtu(&mtu)
                                .map(|(link, _)| MTUOutput {
                                    source: observable_signature.source.clone(),
                                    destination: observable_signature.destination.clone(),
                                    link: link.clone(),
                                    mtu,
                                })
                        });

                        let syn = Some(SynTCPOutput {
                            source: observable_signature.source.clone(),
                            destination: observable_signature.destination.clone(),
                            label: self
                                .matcher
                                .matching_by_tcp_request(&observable_signature.signature)
                                .map(|(label, _)| label.clone()),
                            sig: observable_signature.signature,
                        });

                        let http_request = observable_signature.http_request.map(|http_request| {
                            HttpRequestOutput {
                                source: observable_signature.source.clone(),
                                destination: observable_signature.destination.clone(),
                                lang: http_request.lang,
                                user_agent: http_request.user_agent,
                                label: self
                                    .matcher
                                    .matching_by_http_request(&http_request.signature)
                                    .map(|(label, _)| label.clone()),
                                sig: http_request.signature,
                            }
                        });

                        (syn, None, mtu, None, http_request)
                    } else {
                        let syn_ack = Some(SynAckTCPOutput {
                            source: observable_signature.source.clone(),
                            destination: observable_signature.destination.clone(),
                            label: self
                                .matcher
                                .matching_by_tcp_response(&observable_signature.signature)
                                .map(|(label, _)| label.clone()),
                            sig: observable_signature.signature,
                        });

                        let uptime = observable_signature.uptime.map(|update| UptimeOutput {
                            source: observable_signature.source.clone(),
                            destination: observable_signature.destination.clone(),
                            days: update.days,
                            hours: update.hours,
                            min: update.min,
                            up_mod_days: update.up_mod_days,
                            freq: update.freq,
                        });

                        (None, syn_ack, None, uptime, None)
                    };

                P0fOutput {
                    syn,
                    syn_ack,
                    mtu,
                    uptime,
                    http_request,
                }
            }
            Err(error) => {
                debug!("Fail to process signature: {}", error);
                P0fOutput {
                    syn: None,
                    syn_ack: None,
                    mtu: None,
                    uptime: None,
                    http_request: None,
                }
            }
        }
    }
}

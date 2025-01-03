use crate::db::Label;
use crate::{http, http_languages};
use failure::{bail, Error};
use httparse::{Request, Response, EMPTY_HEADER};
use log::debug;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::Packet;
use std::net::IpAddr;
use std::time::Duration;
use ttl_cache::TtlCache;

/// Maximum number of HTTP headers
const HTTP_MAX_HDRS: usize = 32;

/// FlowKey: (Client IP, Server IP, Client Port, Server Port)
pub type FlowKey = (IpAddr, IpAddr, u16, u16);

#[derive(Clone)]
struct TcpData {
    sequence: u32,
    data: Vec<u8>,
}

pub struct TcpFlow {
    client_ip: IpAddr,
    server_ip: IpAddr,
    client_port: u16,
    server_port: u16,
    client_data: Vec<TcpData>,
    server_data: Vec<TcpData>,
}
impl TcpFlow {
    fn init(
        src_ip: IpAddr,
        src_port: u16,
        dst_ip: IpAddr,
        dst_port: u16,
        tcp_data: TcpData,
    ) -> TcpFlow {
        TcpFlow {
            client_ip: src_ip,
            server_ip: dst_ip,
            client_port: src_port,
            server_port: dst_port,
            client_data: vec![tcp_data.clone()],
            server_data: Vec::new(),
        }
    }
    /// Traversing all the data in sequence in the correct order to build the full data
    ///
    /// # Parameters
    /// - `is_client`: If the data comes from the client.
    fn get_full_data(&self, is_client: bool) -> Vec<u8> {
        let data: &Vec<TcpData> = if is_client {
            &self.client_data
        } else {
            &self.server_data
        };

        let mut sorted_data = data.clone();

        sorted_data.sort_by_key(|tcp_data| tcp_data.sequence);

        let mut full_data = Vec::new();
        for tcp_data in sorted_data {
            full_data.extend_from_slice(&tcp_data.data);
        }
        full_data
    }
}

pub fn process_http_ipv4(
    packet: &Ipv4Packet,
    cache: &mut TtlCache<FlowKey, TcpFlow>,
) -> Result<ObservableHttpPackage, Error> {
    if packet.get_next_level_protocol() != IpNextHeaderProtocols::Tcp {
        bail!("unsupported IPv4 protocol")
    }
    if let Some(tcp) = TcpPacket::new(packet.payload()) {
        process_tcp_packet(
            cache,
            tcp,
            IpAddr::V4(packet.get_source()),
            IpAddr::V4(packet.get_destination()),
        )
    } else {
        Ok(ObservableHttpPackage {
            http_request: None,
            http_response: None,
        })
    }
}

pub fn process_http_ipv6(
    packet: &Ipv6Packet,
    cache: &mut TtlCache<FlowKey, TcpFlow>,
) -> Result<ObservableHttpPackage, Error> {
    if packet.get_next_header() != IpNextHeaderProtocols::Tcp {
        bail!("unsupported IPv6 protocol")
    }
    if let Some(tcp) = TcpPacket::new(packet.payload()) {
        process_tcp_packet(
            cache,
            tcp,
            IpAddr::V6(packet.get_source()),
            IpAddr::V6(packet.get_destination()),
        )
    } else {
        Ok(ObservableHttpPackage {
            http_request: None,
            http_response: None,
        })
    }
}

fn process_tcp_packet(
    cache: &mut TtlCache<FlowKey, TcpFlow>,
    tcp: TcpPacket,
    src_ip: IpAddr,
    dst_ip: IpAddr,
) -> Result<ObservableHttpPackage, Error> {
    let src_port: u16 = tcp.get_source();
    let dst_port: u16 = tcp.get_destination();
    let mut observable_http_package = ObservableHttpPackage {
        http_request: None,
        http_response: None,
    };

    let flow_key: FlowKey = (src_ip, dst_ip, src_port, dst_port);
    let (tcp_flow, is_client) = {
        if let Some(flow) = cache.get_mut(&flow_key) {
            (Some(flow), true)
        } else {
            let reversed_key: FlowKey = (dst_ip, src_ip, dst_port, src_port);
            if let Some(flow) = cache.get_mut(&reversed_key) {
                (Some(flow), false)
            } else {
                (None, false)
            }
        }
    };

    if let Some(flow) = tcp_flow {
        if !tcp.payload().is_empty() {
            let tcp_data = TcpData {
                sequence: tcp.get_sequence(),
                data: Vec::from(tcp.payload()),
            };

            if is_client && src_ip == flow.client_ip && src_port == flow.client_port {
                flow.client_data.push(tcp_data);
                if let Ok(http_request_parsed) = parse_http_request(&flow.get_full_data(is_client))
                {
                    observable_http_package.http_request = http_request_parsed;
                }
            } else if src_ip == flow.server_ip && src_port == flow.server_port {
                flow.server_data.push(tcp_data);
                if let Ok(http_response_parsed) =
                    parse_http_response(&flow.get_full_data(is_client))
                {
                    observable_http_package.http_response = http_response_parsed;

                    if tcp.get_flags()
                        & (pnet::packet::tcp::TcpFlags::FIN | pnet::packet::tcp::TcpFlags::RST)
                        != 0
                    {
                        debug!("Connection closed or reset");
                        cache.remove(&flow_key);
                    }
                }
            }
        }
    } else if tcp.get_flags() & pnet::packet::tcp::TcpFlags::SYN != 0 {
        let tcp_data: TcpData = TcpData {
            sequence: tcp.get_sequence(),
            data: Vec::from(tcp.payload()),
        };
        let flow: TcpFlow = TcpFlow::init(src_ip, src_port, dst_ip, dst_port, tcp_data);
        cache.insert(flow_key, flow, Duration::new(60, 0));
    }

    Ok(observable_http_package)
}

fn parse_http_request(data: &[u8]) -> Result<Option<ObservableHttpRequest>, Error> {
    let mut headers = [EMPTY_HEADER; HTTP_MAX_HDRS];
    let mut req = Request::new(&mut headers);

    match req.parse(data) {
        Ok(httparse::Status::Complete(_)) => {
            let headers: &[httparse::Header] = req.headers;

            let headers_in_order: Vec<http::Header> = build_headers_in_order(headers, true);
            let headers_absent: Vec<http::Header> = build_headers_absent_in_order(headers, true);
            let user_agent: Option<String> = extract_header_by_name(headers, "User-Agent");
            let lang: Option<String> =
                extract_header_by_name(headers, "Accept-Language").and_then(|accept_language| {
                    http_languages::get_highest_quality_language(accept_language)
                });
            let http_version: http::Version = extract_http_version(req.version);

            Ok(Some(ObservableHttpRequest {
                lang,
                user_agent: user_agent.clone(),
                signature: http::Signature {
                    version: http_version,
                    horder: headers_in_order,
                    habsent: headers_absent,
                    expsw: extract_traffic_classification(user_agent),
                },
            }))
        }
        Ok(httparse::Status::Partial) => {
            debug!("Incomplete HTTP request data. Data: {:?}", data);
            Ok(None)
        }
        Err(e) => {
            debug!(
                "Failed to parse HTTP request with Data: {:?}. Error: {}",
                data, e
            );
            Err(failure::err_msg(format!(
                "Failed to parse HTTP request: {}",
                e
            )))
        }
    }
}

fn parse_http_response(data: &[u8]) -> Result<Option<ObservableHttpResponse>, Error> {
    let mut headers = [EMPTY_HEADER; HTTP_MAX_HDRS];
    let mut res = Response::new(&mut headers);

    match res.parse(data) {
        Ok(httparse::Status::Complete(_)) => {
            let headers: &[httparse::Header] = res.headers;

            let headers_in_order: Vec<http::Header> = build_headers_in_order(headers, false);
            let headers_absent: Vec<http::Header> = build_headers_absent_in_order(headers, false);
            let server: Option<String> = extract_header_by_name(headers, "Server");
            let http_version: http::Version = extract_http_version(res.version);

            Ok(Some(ObservableHttpResponse {
                signature: http::Signature {
                    version: http_version,
                    horder: headers_in_order,
                    habsent: headers_absent,
                    expsw: extract_traffic_classification(server),
                },
            }))
        }
        Ok(httparse::Status::Partial) => {
            debug!("Incomplete HTTP response data. Data: {:?}", data);
            Ok(None)
        }
        Err(e) => {
            debug!(
                "Failed to parse HTTP response with Data: {:?}. Error: {}",
                data, e
            );
            Err(failure::err_msg(format!(
                "Failed to parse HTTP response: {}",
                e
            )))
        }
    }
}

fn build_headers_in_order(headers: &[httparse::Header], is_request: bool) -> Vec<http::Header> {
    let mut headers_in_order: Vec<http::Header> = Vec::new();
    let optional_list = if is_request {
        http::request_optional_headers()
    } else {
        http::response_optional_headers()
    };
    let skip_value_list = if is_request {
        http::request_skip_value_headers()
    } else {
        http::response_skip_value_headers()
    };
    let common_list = if is_request {
        http::request_common_headers()
    } else {
        http::response_common_headers()
    };

    #[allow(clippy::if_same_then_else)]
    for header in headers {
        let value: Option<&str> = match std::str::from_utf8(header.value) {
            Ok(v) => Some(v),
            Err(_) => None,
        };

        if optional_list.contains(&header.name) {
            headers_in_order.push(http::Header::new(header.name).optional());
        } else if skip_value_list.contains(&header.name) {
            headers_in_order.push(http::Header::new(header.name));
        } else if common_list.contains(&header.name) {
            headers_in_order.push(http::Header::new(header.name).with_optional_value(value));
        } else {
            headers_in_order.push(http::Header::new(header.name).with_optional_value(value));
        }
    }

    headers_in_order
}

fn build_headers_absent_in_order(
    headers: &[httparse::Header],
    is_request: bool,
) -> Vec<http::Header> {
    let mut headers_absent: Vec<http::Header> = Vec::new();
    let common_list: Vec<&str> = if is_request {
        http::request_common_headers()
    } else {
        http::response_common_headers()
    };
    let current_headers: Vec<&str> = headers.iter().map(|h| h.name).collect();

    for header in &common_list {
        if !current_headers.contains(header) {
            headers_absent.push(http::Header::new(header));
        }
    }
    headers_absent
}

fn extract_header_by_name(headers: &[httparse::Header], name: &str) -> Option<String> {
    headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case(name))
        .map(|header| String::from_utf8_lossy(header.value).to_string())
}

fn extract_traffic_classification(value: Option<String>) -> String {
    value.unwrap_or_else(|| "???".to_string())
}

fn extract_http_version(version: Option<u8>) -> http::Version {
    match version {
        Some(0) => http::Version::V10,
        Some(1) => http::Version::V11,
        _ => http::Version::Any,
    }
}

pub fn get_diagnostic(
    user_agent: Option<String>,
    ua_matcher: Option<(&String, &Option<String>)>,
    signature_os_matcher: Option<&Label>,
) -> http::HttpDiagnosis {
    match user_agent {
        None => http::HttpDiagnosis::Anonymous,
        Some(_ua) => match (ua_matcher, signature_os_matcher) {
            (Some(ua_db), Some(signature_label_db)) => {
                if ua_db.0.eq_ignore_ascii_case(&signature_label_db.name) {
                    http::HttpDiagnosis::Generic
                } else {
                    http::HttpDiagnosis::Dishonest
                }
            }
            _ => http::HttpDiagnosis::None,
        },
    }
}

pub struct ObservableHttpPackage {
    pub http_request: Option<ObservableHttpRequest>,
    pub http_response: Option<ObservableHttpResponse>,
}

#[derive(Debug)]
pub struct ObservableHttpRequest {
    pub lang: Option<String>,
    pub user_agent: Option<String>,
    pub signature: http::Signature,
}
pub struct ObservableHttpResponse {
    pub signature: http::Signature,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_http_request() {
        let valid_request = b"GET / HTTP/1.1\r\n\
        Host: example.com\r\n\
        Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7\r\n\
        Accept-Language: en-US,en;q=0.9,es;q=0.8\r\n\
        Cache-Control: max-age=0\r\n\
        Connection: keep-alive\r\n\
        If-Modified-Since: Thu, 17 Oct 2019 07:18:26 GMT\r\n\
        If-None-Match: \"3147526947\"\r\n\
        Upgrade-Insecure-Requests: 1\r\n\
        User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36\r\n\
        \r\n";
        match parse_http_request(valid_request) {
            Ok(Some(request)) => {
                assert_eq!(request.lang, Some("English".to_string()));
                assert_eq!(request.user_agent, Some("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36".to_string()));
                assert_eq!(request.signature.version, http::Version::V11);

                let expected_horder = vec![
                    http::Header::new("Host"),
                    http::Header::new("Accept").with_value("text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"),
                    http::Header::new("Accept-Language").with_value("en-US,en;q=0.9,es;q=0.8"),
                    http::Header::new("Cache-Control").optional(),
                    http::Header::new("Connection").with_value("keep-alive"),
                    http::Header::new("If-Modified-Since").optional(),
                    http::Header::new("If-None-Match").optional(),
                    http::Header::new("Upgrade-Insecure-Requests").with_value("1"),
                    http::Header::new("User-Agent"),
                ];
                assert_eq!(request.signature.horder, expected_horder);

                let expected_habsent = vec![
                    http::Header::new("Accept-Encoding"),
                    http::Header::new("Accept-Charset"),
                    http::Header::new("Keep-Alive"),
                ];
                assert_eq!(request.signature.habsent, expected_habsent);

                assert_eq!(request.signature.expsw, "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36");
            }
            Ok(None) => panic!("Incomplete HTTP request"),
            Err(e) => panic!("Failed to parse HTTP request: {}", e),
        }
    }

    #[test]
    fn test_parse_http_response() {
        let valid_response = b"HTTP/1.1 200 OK\r\n\
        Server: Apache\r\n\
        Content-Type: text/html; charset=UTF-8\r\n\
        Content-Length: 112\r\n\
        Connection: keep-alive\r\n\
        \r\n\
        <html><body><h1>It works!</h1></body></html>";

        match parse_http_response(valid_response) {
            Ok(Some(response)) => {
                assert_eq!(response.signature.expsw, "Apache");
                assert_eq!(response.signature.version, http::Version::V11);

                let expected_horder = vec![
                    http::Header::new("Server"),
                    http::Header::new("Content-Type"),
                    http::Header::new("Content-Length").optional(),
                    http::Header::new("Connection").with_value("keep-alive"),
                ];
                assert_eq!(response.signature.horder, expected_horder);

                let expected_absent = vec![
                    http::Header::new("Keep-Alive"),
                    http::Header::new("Accept-Ranges"),
                    http::Header::new("Date"),
                ];
                assert_eq!(response.signature.habsent, expected_absent);
            }
            Ok(None) => panic!("Incomplete HTTP response"),
            Err(e) => panic!("Failed to parse HTTP response: {}", e),
        }
    }
}

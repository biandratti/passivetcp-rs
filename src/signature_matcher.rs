use crate::db::{Database, Label};
use crate::fingerprint_traits::{FingerprintDb, MatchQuality};
use crate::{http, tcp};

pub struct SignatureMatcher<'a> {
    database: &'a Database,
}

impl<'a> SignatureMatcher<'a> {
    pub fn new(database: &'a Database) -> Self {
        Self { database }
    }

    pub fn matching_by_tcp_request(
        &self,
        signature: &tcp::Signature,
    ) -> Option<(&'a Label, &'a tcp::Signature, MatchQuality)> {
        self.database.tcp_request.find_best_match(signature)
    }

    pub fn matching_by_tcp_response(
        &self,
        signature: &tcp::Signature,
    ) -> Option<(&'a Label, &'a tcp::Signature, MatchQuality)> {
        self.database.tcp_response.find_best_match(signature)
    }

    pub fn matching_by_mtu(&self, mtu: &u16) -> Option<(&'a String, &'a u16)> {
        for (link, db_mtus) in &self.database.mtu {
            for db_mtu in db_mtus {
                if mtu == db_mtu {
                    return Some((link, db_mtu));
                }
            }
        }
        None
    }

    pub fn matching_by_http_request(
        &self,
        signature: &http::Signature,
    ) -> Option<(&'a Label, &'a http::Signature, MatchQuality)> {
        self.database.http_request.find_best_match(signature)
    }

    pub fn matching_by_http_response(
        &self,
        signature: &http::Signature,
    ) -> Option<(&'a Label, &'a http::Signature, MatchQuality)> {
        self.database.http_response.find_best_match(signature)
    }

    pub fn matching_by_user_agent(
        &self,
        user_agent: String,
    ) -> Option<(&'a String, &'a Option<String>)> {
        for (ua, ua_family) in &self.database.ua_os {
            if user_agent.contains(ua) {
                return Some((ua, ua_family));
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Type;
    use crate::http::{Signature as HttpDbSignature, Version as HttpVersion};
    use crate::tcp::{
        IpVersion, PayloadSize, Quirk, Signature as TcpDbSignature, TcpOption, Ttl, WindowSize,
        WindowSizeType,
    };
    use crate::Database;

    #[test]
    fn matching_linux_by_tcp_request() {
        let db = Box::leak(Box::new(Database::default()));

        let linux_signature = TcpDbSignature {
            version: IpVersion::V4,
            ittl: Ttl::Value(64),
            olen: 0,
            mss: Some(1460),
            wsize: WindowSize {
                raw: None,
                ty: WindowSizeType::Mss(44),
            },
            wscale: Some(7),
            olayout: vec![
                TcpOption::Mss,
                TcpOption::Sok,
                TcpOption::TS,
                TcpOption::Nop,
                TcpOption::Ws,
            ],
            quirks: vec![Quirk::Df, Quirk::NonZeroID],
            pclass: PayloadSize::Zero,
            timestamp: None,
            ip_total_length: None,
            tcp_header_len_words: None,
            ip_id: None,
        };

        let matcher = SignatureMatcher::new(db);

        if let Some((label, _matched_db_sig, quality)) =
            matcher.matching_by_tcp_request(&linux_signature)
        {
            assert_eq!(label.name, "Linux");
            assert_eq!(label.class, Some("unix".to_string()));
            assert_eq!(label.flavor, Some("2.2.x-3.x".to_string()));
            assert_eq!(label.ty, Type::Generic);
            assert_eq!(quality, 1.0);
        } else {
            panic!("No match found");
        }
    }

    #[test]
    fn matching_android_by_tcp_request() {
        let db = Box::leak(Box::new(Database::default()));

        let android_signature = TcpDbSignature {
            version: IpVersion::V4,
            ittl: Ttl::Value(64),
            olen: 0,
            mss: Some(1460),
            wsize: WindowSize {
                raw: None,
                ty: WindowSizeType::Value(65535),
            },
            wscale: Some(3),
            olayout: vec![
                TcpOption::Mss,
                TcpOption::Sok,
                TcpOption::TS,
                TcpOption::Nop,
                TcpOption::Ws,
            ],
            quirks: vec![Quirk::Df, Quirk::NonZeroID],
            pclass: PayloadSize::Zero,
            timestamp: None,
            ip_total_length: None,
            tcp_header_len_words: None,
            ip_id: None,
        };

        let matcher = SignatureMatcher::new(db);

        if let Some((label, _matched_db_sig, quality)) =
            matcher.matching_by_tcp_request(&android_signature)
        {
            assert_eq!(label.name, "Linux");
            assert_eq!(label.class, Some("unix".to_string()));
            assert_eq!(label.flavor, Some("(Android)".to_string()));
            assert_eq!(label.ty, Type::Specified);
            assert_eq!(quality, 1.0);
        } else {
            panic!("No match found");
        }
    }

    #[test]
    fn matching_firefox2_by_http_request() {
        let db = Box::leak(Box::new(Database::default()));

        let firefox_signature = HttpDbSignature {
            version: HttpVersion::V10,
            horder: vec![
                http::Header::new("Host"),
                http::Header::new("User-Agent"),
                http::Header::new("Accept").with_value(",*/*;q="),
                http::Header::new("Accept-Language").optional(),
                http::Header::new("Accept-Encoding").with_value("gzip,deflate"),
                http::Header::new("Accept-Charset").with_value("utf-8;q=0.7,*;q=0.7"),
                http::Header::new("Keep-Alive").with_value("300"),
                http::Header::new("Connection").with_value("keep-alive"),
            ],
            habsent: vec![],
            expsw: "Firefox/".to_string(),
        };

        let matcher = SignatureMatcher::new(db);

        if let Some((label, _matched_db_sig, quality)) =
            matcher.matching_by_http_request(&firefox_signature)
        {
            assert_eq!(label.name, "Firefox");
            assert_eq!(label.class, None);
            assert_eq!(label.flavor, Some("2.x".to_string()));
            assert_eq!(label.ty, Type::Specified);
            assert_eq!(quality, 1.0);
        } else {
            panic!("No match found for Firefox 2.x HTTP signature");
        }
    }

    #[test]
    fn matching_apache_by_http_response() {
        let db = Box::leak(Box::new(Database::default()));

        let apache_signature = HttpDbSignature {
            version: HttpVersion::V11,
            horder: vec![
                http::Header::new("Date"),
                http::Header::new("Server"),
                http::Header::new("Last-Modified").optional(),
                http::Header::new("Accept-Ranges")
                    .optional()
                    .with_value("bytes"),
                http::Header::new("Content-Length").optional(),
                http::Header::new("Content-Range").optional(),
                http::Header::new("Keep-Alive").with_value("timeout"),
                http::Header::new("Connection").with_value("Keep-Alive"),
                http::Header::new("Transfer-Encoding")
                    .optional()
                    .with_value("chunked"),
                http::Header::new("Content-Type"),
            ],
            habsent: vec![],
            expsw: "Apache".to_string(),
        };

        let matcher = SignatureMatcher::new(db);

        if let Some((label, _matched_db_sig, quality)) =
            matcher.matching_by_http_response(&apache_signature)
        {
            assert_eq!(label.name, "Apache");
            assert_eq!(label.class, None);
            assert_eq!(label.flavor, Some("2.x".to_string()));
            assert_eq!(label.ty, Type::Specified);
            assert_eq!(quality, 1.0);
        } else {
            panic!("No match found for Apache 2.x HTTP response signature");
        }
    }
}

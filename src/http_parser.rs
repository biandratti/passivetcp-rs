use crate::http;

pub fn parse_http_request(payload: &[u8]) -> Option<ObservableHttpRequest> {
    if let Ok(payload_str) = std::str::from_utf8(payload) {
        let http_methods = [
            "GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "TRACE", "CONNECT",
        ];
        if !http_methods
            .iter()
            .any(|method| payload_str.starts_with(method))
        {
            return None;
        }

        let headers = payload_str.lines();
        //println!("headers: {:?}", headers);

        let mut user_agent: Option<String> = None;
        let mut lang: Option<String> = None;
        let mut raw_headers = vec![];

        let mut version = http::Version::Any;
        let mut horder = vec![];
        let mut expsw = String::new();

        for line in headers {
            /* if line.is_empty() {
                break;
            }*/

            raw_headers.push(line.to_string());

            if line.to_lowercase().starts_with("user-agent:") {
                user_agent = Some(line.split_once(":").unwrap().1.trim().to_string());
                if let Some(ua) = &user_agent {
                    expsw = ua.clone();
                }
            }

            if line.to_lowercase().starts_with("accept-language:") {
                lang = Some(line.split_once(":").unwrap().1.trim().to_string());
            }

            if line.starts_with("HTTP/") {
                if let Some(version_str) = line.split(" ").nth(2) {
                    version = match version_str {
                        "HTTP/1.0" => http::Version::V10,
                        "HTTP/1.1" => http::Version::V11,
                        _ => http::Version::Any,
                    };
                }
            }

            if let Some(header_name) = line.split_once(":").map(|(key, _)| key.trim()) {
                println!("header_name: {}", header_name);
                horder.push(header_name.to_string());
            }
        }

        let signature = http::Signature {
            version,
            horder: horder
                .iter()
                .map(|header| http::Header::new(header))
                .collect(),

            habsent: vec![], //TODO: WIP: add specific headers here.
            expsw,
        };

        return Some(ObservableHttpRequest {
            lang,
            user_agent,
            signature,
        });
    }
    None
}

pub struct ObservableHttpRequest {
    pub lang: Option<String>,
    pub user_agent: Option<String>,
    pub signature: http::Signature,
}

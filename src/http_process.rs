use crate::http;

pub fn process_http_request(payload: &[u8]) -> Option<ObservableHttpRequest> {
    //TODO: WIP
    None
}

pub struct ObservableHttpRequest {
    pub lang: Option<String>,
    pub user_agent: Option<String>,
    pub signature: http::Signature,
}
use std::str::FromStr;

use crate::db::{Database, FingerprintCollection, Label, Type};
use crate::error::PassiveTcpError;
use crate::tcp::WindowSizeType;
use crate::{
    http::{Header as HttpHeader, Signature as HttpSignature, Version as HttpVersion},
    tcp::{IpVersion, PayloadSize, Quirk, Signature as TcpSignature, TcpOption, Ttl, WindowSize},
};
use nom::branch::alt;
use nom::bytes::complete::{take_until, take_while};
use nom::character::complete::{alpha1, char, digit1};
use nom::combinator::{map, map_res, opt};
use nom::multi::{separated_list0, separated_list1};
use nom::sequence::{pair, separated_pair, terminated};
use nom::*;
use nom::{
    bytes::complete::tag,
    character::complete::{alphanumeric1, space0},
    combinator::rest,
    sequence::preceded,
    IResult,
};
use tracing::{trace, warn};

impl FromStr for Database {
    type Err = PassiveTcpError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut classes = vec![];
        let mut mtu_entries = vec![];
        let mut ua_os_entries = vec![];

        let mut temp_tcp_request_entries: Vec<(Label, Vec<TcpSignature>)> = vec![];
        let mut temp_tcp_response_entries: Vec<(Label, Vec<TcpSignature>)> = vec![];
        let mut temp_http_request_entries: Vec<(Label, Vec<HttpSignature>)> = vec![];
        let mut temp_http_response_entries: Vec<(Label, Vec<HttpSignature>)> = vec![];

        let mut cur_mod = None;

        for line in s.lines() {
            let line = line.trim();

            if line.is_empty() || line.starts_with(';') {
                continue;
            }

            if line.starts_with("classes") {
                classes.append(
                    &mut parse_classes(line)
                        .map_err(|err| {
                            PassiveTcpError::Parse(format!(
                                "fail to parse `classes`: {}, {}",
                                line, err
                            ))
                        })?
                        .1,
                );
            } else if line.starts_with("ua_os") {
                ua_os_entries.append(
                    &mut parse_ua_os(line)
                        .map_err(|err| {
                            PassiveTcpError::Parse(format!(
                                "fail to parse `ua_os`: {}, {}",
                                line, err
                            ))
                        })?
                        .1,
                );
            } else if line.starts_with('[') && line.ends_with(']') {
                cur_mod = Some(
                    parse_module(line)
                        .map_err(|err| {
                            PassiveTcpError::Parse(format!(
                                "fail to parse `module`: {}, {}",
                                line, err
                            ))
                        })?
                        .1,
                );
            } else if let Some((module, direction)) = cur_mod.as_ref() {
                let (_, (name, value)) = parse_named_value(line).map_err(|err| {
                    PassiveTcpError::Parse(format!("fail to parse named value: {}, {}", line, err))
                })?;

                match name {
                    "label" if module == "mtu" => {
                        mtu_entries.push((value.to_string(), vec![]));
                    }
                    "sig" if module == "mtu" => {
                        if let Some((_label, values)) = mtu_entries.last_mut() {
                            let sig = value.parse::<u16>().map_err(|err| {
                                PassiveTcpError::Parse(format!(
                                    "fail to parse `mtu` value: {}, {}",
                                    value, err
                                ))
                            })?;
                            values.push(sig);
                        } else {
                            return Err(PassiveTcpError::Parse(format!(
                                "`mtu` value without `label`: {}",
                                value
                            )));
                        }
                    }
                    "label" => {
                        let (_, label) = parse_label(value).map_err(|err| {
                            PassiveTcpError::Parse(format!(
                                "fail to parse `label`: {}, {}",
                                value, err
                            ))
                        })?;

                        match (module.as_str(), direction.as_ref().map(|s| s.as_ref())) {
                            ("tcp", Some("request")) => {
                                temp_tcp_request_entries.push((label, vec![]))
                            }
                            ("tcp", Some("response")) => {
                                temp_tcp_response_entries.push((label, vec![]))
                            }
                            ("http", Some("request")) => {
                                temp_http_request_entries.push((label, vec![]))
                            }
                            ("http", Some("response")) => {
                                temp_http_response_entries.push((label, vec![]))
                            }
                            _ => {
                                warn!("skip `label` in unknown module `{}`: {}", module, value);
                            }
                        }
                    }
                    "sig" => match (module.as_str(), direction.as_ref().map(|s| s.as_ref())) {
                        ("tcp", Some("request")) => {
                            if let Some((label, values)) = temp_tcp_request_entries.last_mut() {
                                let sig = value.parse()?;
                                trace!("sig for `{}` tcp request: {}", label, sig);
                                values.push(sig);
                            } else {
                                return Err(PassiveTcpError::Parse(format!(
                                    "tcp signature without `label`: {}",
                                    value
                                )));
                            }
                        }
                        ("tcp", Some("response")) => {
                            if let Some((label, values)) = temp_tcp_response_entries.last_mut() {
                                let sig = value.parse()?;
                                trace!("sig for `{}` tcp response: {}", label, sig);
                                values.push(sig);
                            } else {
                                return Err(PassiveTcpError::Parse(format!(
                                    "tcp signature without `label`: {}",
                                    value
                                )));
                            }
                        }
                        ("http", Some("request")) => {
                            if let Some((label, values)) = temp_http_request_entries.last_mut() {
                                let sig = value.parse()?;
                                trace!("sig for `{}` http request: {}", label, sig);
                                values.push(sig);
                            } else {
                                return Err(PassiveTcpError::Parse(format!(
                                    "http signature without `label`: {}",
                                    value
                                )));
                            }
                        }
                        ("http", Some("response")) => {
                            if let Some((label, values)) = temp_http_response_entries.last_mut() {
                                let sig = value.parse()?;
                                trace!("sig for `{}` http response: {}", label, sig);
                                values.push(sig);
                            } else {
                                return Err(PassiveTcpError::Parse(format!(
                                    "http signature without `label`: {}",
                                    value
                                )));
                            }
                        }
                        _ => {
                            warn!("skip `sig` in unknown module `{}`: {}", module, value);
                        }
                    },
                    "sys" if module != "mtu" => {}
                    _ => {
                        warn!("skip unknown named value: {} = {}", name, value);
                    }
                }
            } else {
                return Err(PassiveTcpError::Parse(format!(
                    "unexpected line outside the module: {}",
                    line
                )));
            }
        }

        Ok(Database {
            classes,
            mtu: mtu_entries,
            ua_os: ua_os_entries,
            tcp_request: FingerprintCollection::new(temp_tcp_request_entries),
            tcp_response: FingerprintCollection::new(temp_tcp_response_entries),
            http_request: FingerprintCollection::new(temp_http_request_entries),
            http_response: FingerprintCollection::new(temp_http_response_entries),
        })
    }
}

macro_rules! impl_from_str {
    ($ty:ty, $parse:ident) => {
        impl FromStr for $ty {
            type Err = PassiveTcpError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                let (remaining, res) = $parse(s).map_err(|err| {
                    PassiveTcpError::Parse(format!(
                        "parse {} failed: {}, {}",
                        stringify!($ty),
                        s,
                        err
                    ))
                })?;

                if !remaining.is_empty() {
                    Err(PassiveTcpError::Parse(format!(
                        "parse {} failed, remaining: {}",
                        stringify!($ty),
                        remaining
                    )))
                } else {
                    Ok(res)
                }
            }
        }
    };
}

impl_from_str!(Label, parse_label);
impl_from_str!(Type, parse_type);
impl_from_str!(TcpSignature, parse_tcp_signature);
impl_from_str!(IpVersion, parse_ip_version);
impl_from_str!(Ttl, parse_ttl);
impl_from_str!(WindowSize, parse_window_size);
impl_from_str!(TcpOption, parse_tcp_option);
impl_from_str!(Quirk, parse_quirk);
impl_from_str!(PayloadSize, parse_payload_size);
impl_from_str!(HttpSignature, parse_http_signature);
impl_from_str!(HttpHeader, parse_http_header);

fn parse_named_value(input: &str) -> IResult<&str, (&str, &str)> {
    let (input, (name, _, _, _, value)) =
        (alphanumeric1, space0, tag("="), space0, rest).parse(input)?;
    Ok((input, (name, value)))
}

fn parse_classes(input: &str) -> IResult<&str, Vec<String>> {
    let (input, (_, _, _, _, classes)) = (
        tag("classes"),
        space0,
        tag("="),
        space0,
        separated_list0(tag(","), alphanumeric1),
    )
        .parse(input)?;

    let class_vec = classes.into_iter().map(|s| s.to_string()).collect();
    Ok((input, class_vec))
}

fn parse_module(input: &str) -> IResult<&str, (String, Option<String>)> {
    let (input, (_, module, direction, _)) =
        (tag("["), alpha1, opt(preceded(tag(":"), alpha1)), tag("]")).parse(input)?;
    let module_str = module.to_string();
    let direction_str = direction.map(|s| s.to_string());

    Ok((input, (module_str, direction_str)))
}

fn parse_ua_os(input: &str) -> IResult<&str, Vec<(String, Option<String>)>> {
    let (input, (_, _, _, _, values)) = (
        tag("ua_os"),
        space0,
        tag("="),
        space0,
        separated_list0(tag(","), parse_key_value),
    )
        .parse(input)?;

    let result = values
        .into_iter()
        .map(|(name, value)| (name.to_string(), value.map(|s| s.to_string())))
        .collect();

    Ok((input, result))
}

fn parse_key_value(input: &str) -> IResult<&str, (&str, Option<&str>)> {
    let (input, (name, _, value)) = (
        alphanumeric1,
        space0,
        opt(preceded((space0, tag("="), space0), alphanumeric1)),
    )
        .parse(input)?;

    Ok((input, (name, value)))
}

fn parse_label(input: &str) -> IResult<&str, Label> {
    let (input, (ty, _, class, _, name, flavor)) = (
        parse_type,
        tag(":"),
        alt((
            map(tag("!"), |_| None),
            map(take_until(":"), |s: &str| Some(s.to_string())),
        )),
        tag(":"),
        take_until(":"),
        opt(preceded(tag(":"), rest)),
    )
        .parse(input)?;

    Ok((
        input,
        Label {
            ty,
            class,
            name: name.to_string(),
            flavor: flavor.filter(|f| !f.is_empty()).map(String::from),
        },
    ))
}

fn parse_type(input: &str) -> IResult<&str, Type> {
    alt((
        tag("s").map(|_| Type::Specified),
        tag("g").map(|_| Type::Generic),
    ))
    .parse(input)
}

fn parse_tcp_signature(input: &str) -> IResult<&str, TcpSignature> {
    let (
        input,
        (version, _, ittl, _, olen, _, mss, _, wsize, _, wscale, _, olayout, _, quirks, _, pclass),
    ) = (
        parse_ip_version,
        tag(":"),
        parse_ttl,
        tag(":"),
        map_res(digit1, |s: &str| s.parse::<u8>()), // olen
        tag(":"),
        alt((
            tag("*").map(|_| None),
            map_res(digit1, |s: &str| s.parse::<u16>().map(Some)),
        )), // mss
        tag(":"),
        parse_window_size,
        tag(","),
        alt((
            tag("*").map(|_| None),
            map_res(digit1, |s: &str| s.parse::<u8>().map(Some)),
        )), // wscale
        tag(":"),
        separated_list1(tag(","), parse_tcp_option),
        tag(":"),
        separated_list0(tag(","), parse_quirk),
        tag(":"),
        parse_payload_size,
    )
        .parse(input)?;

    Ok((
        input,
        TcpSignature {
            version,
            ittl,
            olen,
            mss,
            wsize,
            wscale,
            olayout,
            quirks,
            pclass,
            timestamp: None,
            ip_total_length: None,
            tcp_header_len_words: None,
            ip_id: None,
        },
    ))
}

fn parse_ip_version(input: &str) -> IResult<&str, IpVersion> {
    alt((
        map(tag("4"), |_| IpVersion::V4),
        map(tag("6"), |_| IpVersion::V6),
        map(tag("*"), |_| IpVersion::Any),
    ))
    .parse(input)
}

fn parse_ttl(input: &str) -> IResult<&str, Ttl> {
    alt((
        map_res(terminated(digit1, tag("-")), |s: &str| {
            s.parse::<u8>().map(Ttl::Bad)
        }),
        map_res(terminated(digit1, tag("+?")), |s: &str| {
            s.parse::<u8>().map(Ttl::Guess)
        }),
        map_res(
            separated_pair(digit1, tag("+"), digit1),
            |(ttl_str, distance_str): (&str, &str)| match (
                ttl_str.parse::<u8>(),
                distance_str.parse::<u8>(),
            ) {
                (Ok(ttl), Ok(distance)) => Ok(Ttl::Distance(ttl, distance)),
                (Err(_), _) => Err("Failed to parse ttl"),
                (_, Err(_)) => Err("Failed to parse distance"),
            },
        ),
        map_res(digit1, |s: &str| s.parse::<u8>().map(Ttl::Value)),
    ))
    .parse(input)
}

fn parse_window_size(input: &str) -> IResult<&str, WindowSize> {
    alt((
        map(tag("*"), |_| WindowSize {
            raw: None,
            ty: WindowSizeType::Any,
        }),
        map_res(preceded(tag("mss*"), digit1), |s: &str| {
            s.parse::<u8>().map(|value| WindowSize {
                raw: None,
                ty: WindowSizeType::Mss(value),
            })
        }),
        map_res(preceded(tag("mtu*"), digit1), |s: &str| {
            s.parse::<u8>().map(|value| WindowSize {
                raw: None,
                ty: WindowSizeType::Mtu(value),
            })
        }),
        map_res(preceded(tag("%"), digit1), |s: &str| {
            s.parse::<u16>().map(|value| WindowSize {
                raw: None,
                ty: WindowSizeType::Mod(value),
            })
        }),
        map_res(digit1, |s: &str| {
            s.parse::<u16>().map(|value| WindowSize {
                raw: None,
                ty: WindowSizeType::Value(value),
            })
        }),
    ))
    .parse(input)
}

fn parse_tcp_option(input: &str) -> IResult<&str, TcpOption> {
    alt((
        map_res(preceded(tag("eol+"), digit1), |s: &str| {
            s.parse::<u8>().map(TcpOption::Eol)
        }),
        tag("nop").map(|_| TcpOption::Nop),
        tag("mss").map(|_| TcpOption::Mss),
        tag("ws").map(|_| TcpOption::Ws),
        tag("sok").map(|_| TcpOption::Sok),
        tag("sack").map(|_| TcpOption::Sack),
        tag("ts").map(|_| TcpOption::TS),
        preceded(
            tag("?"),
            map(digit1, |s: &str| s.parse::<u8>().unwrap_or(0)),
        )
        .map(TcpOption::Unknown),
    ))
    .parse(input)
}

fn parse_quirk(input: &str) -> IResult<&str, Quirk> {
    alt((
        map(tag("df"), |_| Quirk::Df),
        map(tag("id+"), |_| Quirk::NonZeroID),
        map(tag("id-"), |_| Quirk::ZeroID),
        map(tag("ecn"), |_| Quirk::Ecn),
        map(tag("0+"), |_| Quirk::MustBeZero),
        map(tag("flow"), |_| Quirk::FlowID),
        map(tag("seq-"), |_| Quirk::SeqNumZero),
        map(tag("ack+"), |_| Quirk::AckNumNonZero),
        map(tag("ack-"), |_| Quirk::AckNumZero),
        map(tag("uptr+"), |_| Quirk::NonZeroURG),
        map(tag("urgf+"), |_| Quirk::Urg),
        map(tag("pushf+"), |_| Quirk::Push),
        map(tag("ts1-"), |_| Quirk::OwnTimestampZero),
        map(tag("ts2+"), |_| Quirk::PeerTimestampNonZero),
        map(tag("opt+"), |_| Quirk::TrailinigNonZero),
        map(tag("exws"), |_| Quirk::ExcessiveWindowScaling),
        map(tag("bad"), |_| Quirk::OptBad),
    ))
    .parse(input)
}

fn parse_payload_size(input: &str) -> IResult<&str, PayloadSize> {
    alt((
        map(tag("0"), |_| PayloadSize::Zero),
        map(tag("+"), |_| PayloadSize::NonZero),
        map(tag("*"), |_| PayloadSize::Any),
    ))
    .parse(input)
}

fn parse_http_signature(input: &str) -> IResult<&str, HttpSignature> {
    let (input, (version, _, horder, _, habsent, _, expsw)) = (
        parse_http_version,
        tag(":"),
        separated_list1(tag(","), parse_http_header),
        tag(":"),
        opt(separated_list0(tag(","), parse_http_header)),
        tag(":"),
        rest,
    )
        .parse(input)?;

    let habsent = habsent
        .unwrap_or_default()
        .into_iter()
        .filter(|h| !h.name.is_empty())
        .collect();

    Ok((
        input,
        HttpSignature {
            version,
            horder,
            habsent,
            expsw: expsw.to_string(),
        },
    ))
}

fn parse_http_version(input: &str) -> IResult<&str, HttpVersion> {
    alt((
        map(tag("0"), |_| HttpVersion::V10),
        map(tag("1"), |_| HttpVersion::V11),
        map(tag("*"), |_| HttpVersion::Any),
    ))
    .parse(input)
}

fn parse_header_key_value(input: &str) -> IResult<&str, (&str, Option<&str>)> {
    pair(
        take_while(|c: char| (c.is_ascii_alphanumeric() || c == '-') && c != ':' && c != '='),
        opt(preceded(tag("=["), terminated(take_until("]"), char(']')))),
    )
    .parse(input)
}

fn parse_http_header(input: &str) -> IResult<&str, HttpHeader> {
    let (input, optional) = opt(char('?')).parse(input)?;
    let (input, (name, value)) = parse_header_key_value(input)?;

    Ok((
        input,
        HttpHeader {
            optional: optional.is_some(),
            name: name.to_string(),
            value: value.map(|s| s.to_string()),
        },
    ))
}

#[cfg(test)]
mod tests {
    use lazy_static::lazy_static;

    use super::*;
    use crate::http::header;
    use crate::tcp::{Quirk::*, TcpOption::*};

    lazy_static! {
        static ref LABELS: Vec<(&'static str, Label)> = vec![
            (
                "s:!:Uncle John's Networked ls Utility:2.3.0.1",
                Label {
                    ty: Type::Specified,
                    class: None,
                    name: "Uncle John's Networked ls Utility".to_owned(),
                    flavor: Some("2.3.0.1".to_owned()),
                },
            ),
            (
                "s:unix:Linux:3.11 and newer",
                Label {
                    ty: Type::Specified,
                    class: Some("unix".to_owned()),
                    name: "Linux".to_owned(),
                    flavor: Some("3.11 and newer".to_owned()),
                },
            ),
            (
                "s:!:Chrome:11.x to 26.x",
                Label {
                    ty: Type::Specified,
                    class: None,
                    name: "Chrome".to_owned(),
                    flavor: Some("11.x to 26.x".to_owned()),
                },
            ),
            (
                "s:!:curl:",
                Label {
                    ty: Type::Specified,
                    class: None,
                    name: "curl".to_owned(),
                    flavor: None,
                },
            )
        ];
        static ref TCP_SIGNATURES: Vec<(&'static str, TcpSignature)> = vec![
            (
                "*:64:0:*:mss*20,10:mss,sok,ts,nop,ws:df,id+:0",
                TcpSignature {
                    version: IpVersion::Any,
                    ittl: Ttl::Value(64),
                    olen: 0,
                    mss: None,
                    wsize: WindowSize {
                        raw: None,
                        ty: WindowSizeType::Mss(20),
                    },
                    wscale: Some(10),
                    olayout: vec![Mss, Sok, TS, Nop, Ws],
                    quirks: vec![Df, NonZeroID],
                    pclass: PayloadSize::Zero,
                    timestamp: None,
                    ip_total_length: None,
                    tcp_header_len_words: None,
                ip_id: None,
                }
            ),
            (
                "*:64:0:*:16384,0:mss::0",
                TcpSignature {
                    version: IpVersion::Any,
                    ittl: Ttl::Value(64),
                    olen: 0,
                    mss: None,
                    wsize: WindowSize {
                        raw: None,
                        ty: WindowSizeType::Value(16384),
                    },
                    wscale: Some(0),
                    olayout: vec![Mss],
                    quirks: vec![],
                    pclass: PayloadSize::Zero,
                    timestamp: None,
                    ip_total_length: None,
                    tcp_header_len_words: None,
                ip_id: None,
                }
            ),
            (
                "4:128:0:1460:mtu*2,0:mss,nop,ws::0",
                TcpSignature {
                    version: IpVersion::V4,
                    ittl: Ttl::Value(128),
                    olen: 0,
                    mss: Some(1460),
                    wsize: WindowSize {
                        raw: None,
                        ty: WindowSizeType::Mtu(2),
                    },
                    wscale: Some(0),
                    olayout: vec![Mss, Nop, Ws],
                    quirks: vec![],
                    pclass: PayloadSize::Zero,
                    timestamp: None,
                    ip_total_length: None,
                    tcp_header_len_words: None,
                ip_id: None,
                }
            ),
            (
                "*:64-:0:265:%512,0:mss,sok,ts:ack+:0",
                TcpSignature {
                    version: IpVersion::Any,
                    ittl: Ttl::Bad(64),
                    olen: 0,
                    mss: Some(265),
                    wsize: WindowSize {
                        raw: None,
                        ty: WindowSizeType::Mod(512),
                    },
                    wscale: Some(0),
                    olayout: vec![Mss, Sok, TS],
                    quirks: vec![AckNumNonZero],
                    pclass: PayloadSize::Zero,
                    timestamp: None,
                    ip_total_length: None,
                 tcp_header_len_words: None,
                ip_id: None,
                }
            ),
            (
                "*:64:0:*:mss*44,1:mss,sok,ts,nop,ws:df,id+:0",
                TcpSignature {
                    version: IpVersion::Any,
                    ittl: Ttl::Value(64),
                    olen: 0,
                    mss: None,
                    wsize: WindowSize {
                        raw: None,
                        ty: WindowSizeType::Mss(44),
                    },
                    wscale: Some(1),
                    olayout: vec![Mss, Sok, TS, Nop, Ws],
                    quirks: vec![Df, NonZeroID],
                    pclass: PayloadSize::Zero,
                    timestamp: None,
                    ip_total_length: None,
                    tcp_header_len_words: None,
                ip_id: None,
                }
            ),
            (
                "*:64:0:*:*,*:mss,sok,ts,nop,ws:df,id+:0",
                TcpSignature {
                    version: IpVersion::Any,
                    ittl: Ttl::Value(64),
                    olen: 0,
                    mss: None,
                    wsize: WindowSize {
                        raw: None,
                        ty: WindowSizeType::Any,
                    },
                    wscale: None,
                    olayout: vec![Mss, Sok, TS, Nop, Ws],
                    quirks: vec![Df, NonZeroID],
                    pclass: PayloadSize::Zero,
                    timestamp: None,
                    ip_total_length: None,
                    tcp_header_len_words: None,
                ip_id: None,
                }

            )
        ];
        static ref TTLS: Vec<(&'static str, Ttl)> = vec![
            (
                "64",
                Ttl::Value(64)
            ),
            (
                "54+10",
                Ttl::Distance(54, 10)
            ),
            (
                "64-",
                Ttl::Bad(64)
            ),
            (
                "54+?",
                Ttl::Guess(54)
            )
        ];
        static ref HTTP_SIGNATURES: Vec<(&'static str, HttpSignature)> = vec![
            (
                "*:Host,User-Agent,Accept=[,*/*;q=],?Accept-Language,Accept-Encoding=[gzip,deflate],Accept-Charset=[utf-8;q=0.7,*;q=0.7],Keep-Alive=[300],Connection=[keep-alive]::Firefox/",
                HttpSignature {
                    version: HttpVersion::Any,
                    horder: vec![
                        header("Host"),
                        header("User-Agent"),
                        header("Accept").with_value(",*/*;q="),
                        header("Accept-Language").optional(),
                        header("Accept-Encoding").with_value("gzip,deflate"),
                        header("Accept-Charset").with_value("utf-8;q=0.7,*;q=0.7"),
                        header("Keep-Alive").with_value("300"),
                        header("Connection").with_value("keep-alive"),
                    ],
                    habsent: vec![],
                    expsw: "Firefox/".to_owned(),
                }
            )
        ];
        static ref HTTP_HEADERS: Vec<(&'static str, HttpHeader)> = vec![
            ("Host", HttpHeader{ optional: false, name: "Host".to_owned(), value: None}),
            ("User-Agent", HttpHeader{ optional: false, name: "User-Agent".to_owned(), value: None}),
            ("Accept=[,*/*;q=]", HttpHeader{ optional: false, name: "Accept".to_owned(), value: Some(",*/*;q=".to_owned())}),
            ("?Accept-Language", HttpHeader{ optional: true, name: "Accept-Language".to_owned(), value: None}),
        ];
    }

    #[test]
    fn test_label() {
        for (s, l) in LABELS.iter() {
            assert_eq!(&s.parse::<Label>().unwrap(), l);
        }
    }

    #[test]
    fn test_tcp_signature() {
        for (s, sig) in TCP_SIGNATURES.iter() {
            assert_eq!(&s.parse::<TcpSignature>().unwrap(), sig);
            assert_eq!(&sig.to_string(), s);
        }
    }

    #[test]
    fn test_ttl() {
        for (s, ttl) in TTLS.iter() {
            assert_eq!(&s.parse::<Ttl>().unwrap(), ttl);
            assert_eq!(&ttl.to_string(), s);
        }
    }

    #[test]
    fn test_http_signature() {
        for (s, sig) in HTTP_SIGNATURES.iter() {
            assert_eq!(&s.parse::<HttpSignature>().unwrap(), sig);
            assert_eq!(&sig.to_string(), s);
        }
    }

    #[test]
    fn test_http_header() {
        for (s, h) in HTTP_HEADERS.iter() {
            assert_eq!(&s.parse::<HttpHeader>().unwrap(), h);
            assert_eq!(&h.to_string(), s);
        }
    }
}

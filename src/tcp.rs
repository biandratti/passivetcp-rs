use crate::db::TcpP0fIndexKey;
use crate::fingerprint_traits::{DatabaseSignature, ObservedFingerprint};
use tracing::debug;

#[derive(Clone, Debug, PartialEq)]
pub struct Signature {
    pub version: IpVersion,
    /// initial TTL used by the OS.
    pub ittl: Ttl,
    /// length of IPv4 options or IPv6 extension headers.
    pub olen: u8,
    /// maximum segment size, if specified in TCP options.
    pub mss: Option<u16>,
    /// window size.
    pub wsize: WindowSize,
    /// window scaling factor, if specified in TCP options.
    pub wscale: Option<u8>,
    /// layout and ordering of TCP options, if any.
    pub olayout: Vec<TcpOption>,
    /// properties and quirks observed in IP or TCP headers.
    pub quirks: Vec<Quirk>,
    /// payload size classification
    pub pclass: PayloadSize,
    /// timestamp values
    pub timestamp: Option<Timestamp>,
    /// Raw IP Total Length.
    pub ip_total_length: Option<u16>,
    /// Raw TCP Data Offset (header length in 32-bit words).
    pub tcp_header_len_words: Option<u8>,
    /// Raw IP ID.  identification field and is primarily used for uniquely identifying the group of fragments of a single IP datagram
    /// It is required only in ip v4.
    pub ip_id: Option<u16>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Timestamp {
    /// timestamp value
    pub tsval: Option<u32>,
    /// timestamp echo reply
    pub tsecr: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpMatchQuality {
    High,
    Medium,
    Low,
}

impl TcpMatchQuality {
    pub fn as_score(self) -> u32 {
        match self {
            TcpMatchQuality::High => 0,
            TcpMatchQuality::Medium => 5,
            TcpMatchQuality::Low => 10,
        }
    }
}

impl Signature {
    fn distance_olen(&self, other: &Self) -> Option<u32> {
        if self.olen == other.olen {
            Some(TcpMatchQuality::High.as_score())
        } else {
            Some(TcpMatchQuality::Low.as_score())
        }
    }

    fn distance_mss(&self, other: &Self) -> Option<u32> {
        if other.mss.is_none() || self.mss == other.mss {
            Some(TcpMatchQuality::High.as_score())
        } else {
            Some(TcpMatchQuality::Low.as_score())
        }
    }

    fn distance_wscale(&self, other: &Self) -> Option<u32> {
        if other.wscale.is_none() || self.wscale == other.wscale {
            Some(TcpMatchQuality::High.as_score())
        } else {
            Some(TcpMatchQuality::Medium.as_score())
        }
    }

    fn distance_olayout(&self, other: &Self) -> Option<u32> {
        if self.olayout == other.olayout {
            Some(TcpMatchQuality::High.as_score())
        } else {
            None
        }
    }

    fn distance_quirks(&self, other: &Self) -> Option<u32> {
        if self.quirks == other.quirks {
            Some(TcpMatchQuality::High.as_score())
        } else {
            None
        }
    }
}

impl ObservedFingerprint for Signature {
    type Key = TcpP0fIndexKey;

    fn generate_index_key(&self) -> Self::Key {
        let olayout_parts: Vec<String> =
            self.olayout.iter().map(|opt| format!("{}", opt)).collect();
        TcpP0fIndexKey {
            ip_version_key: self.version,
            olayout_key: olayout_parts.join(","),
            pclass_key: self.pclass,
        }
    }
}

impl DatabaseSignature<Signature> for Signature {
    fn calculate_distance(&self, observed: &Signature) -> Option<u32> {
        let distance = observed.version.distance_ip_version(&self.version)?
            + observed.ittl.distance_ttl(&self.ittl)?
            + observed.distance_olen(self)?
            + observed.distance_mss(self)?
            + observed
                .wsize
                .distance_window_size(&self.wsize, observed.mss)?
            + observed.distance_wscale(self)?
            + observed.distance_olayout(self)?
            + observed.distance_quirks(self)?
            + observed.pclass.distance_payload_size(&self.pclass)?;
        Some(distance)
    }

    fn generate_index_keys_for_db_entry(&self) -> Vec<TcpP0fIndexKey> {
        let mut keys = Vec::new();
        let olayout_key_str = self
            .olayout
            .iter()
            .map(|opt| format!("{}", opt))
            .collect::<Vec<String>>()
            .join(",");

        let versions_for_keys = if self.version == IpVersion::Any {
            vec![IpVersion::V4, IpVersion::V6]
        } else {
            vec![self.version]
        };

        let pclasses_for_keys = if self.pclass == PayloadSize::Any {
            vec![PayloadSize::Zero, PayloadSize::NonZero]
        } else {
            vec![self.pclass]
        };

        for v_key_part in &versions_for_keys {
            for pc_key_part in &pclasses_for_keys {
                keys.push(TcpP0fIndexKey {
                    ip_version_key: *v_key_part,
                    olayout_key: olayout_key_str.clone(),
                    pclass_key: *pc_key_part,
                });
            }
        }
        keys
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IpVersion {
    V4,
    V6,
    Any,
}
impl IpVersion {
    pub fn distance_ip_version(&self, other: &IpVersion) -> Option<u32> {
        if other == &IpVersion::Any {
            Some(TcpMatchQuality::High.as_score())
        } else {
            match (self, other) {
                (IpVersion::V4, IpVersion::V4) | (IpVersion::V6, IpVersion::V6) => {
                    Some(TcpMatchQuality::High.as_score())
                }
                _ => None,
            }
        }
    }
}

/// Time To Live (TTL) representation used for OS fingerprinting and network distance calculation
#[derive(Clone, Debug, PartialEq)]
pub enum Ttl {
    /// Raw TTL value when we don't have enough context to determine initial TTL
    /// Contains the observed TTL value from the IP header
    Value(u8),

    /// TTL with calculated network distance
    /// First u8 is the observed TTL value
    /// Second u8 is the estimated number of hops (distance = initial_ttl - observed_ttl)
    Distance(u8, u8),

    /// TTL value that's been guessed based on common OS initial values
    /// Contains the estimated initial TTL (e.g., 64 for Linux, 128 for Windows)
    Guess(u8),

    /// Invalid or problematic TTL value
    /// Contains the raw TTL value that was deemed invalid (e.g., 0)
    Bad(u8),
}

impl Ttl {
    pub fn distance_ttl(&self, other: &Ttl) -> Option<u32> {
        match (self, other) {
            (Ttl::Value(a), Ttl::Value(b)) => {
                if a == b {
                    Some(TcpMatchQuality::High.as_score())
                } else {
                    Some(TcpMatchQuality::Low.as_score())
                }
            }
            (Ttl::Distance(a1, a2), Ttl::Distance(b1, b2)) => {
                if a1 == b1 && a2 == b2 {
                    Some(TcpMatchQuality::High.as_score())
                } else {
                    Some(TcpMatchQuality::Low.as_score())
                }
            }
            (Ttl::Distance(a1, _), Ttl::Value(b1)) => {
                if a1 == b1 {
                    Some(TcpMatchQuality::High.as_score())
                } else {
                    Some(TcpMatchQuality::Low.as_score())
                }
            }
            (Ttl::Guess(a), Ttl::Guess(b)) => {
                if a == b {
                    Some(TcpMatchQuality::High.as_score())
                } else {
                    Some(TcpMatchQuality::Low.as_score())
                }
            }
            (Ttl::Bad(a), Ttl::Bad(b)) => {
                if a == b {
                    Some(TcpMatchQuality::High.as_score())
                } else {
                    Some(TcpMatchQuality::Low.as_score())
                }
            }
            (Ttl::Guess(a), Ttl::Value(b)) => {
                if a == b {
                    Some(TcpMatchQuality::High.as_score())
                } else {
                    Some(TcpMatchQuality::Low.as_score())
                }
            }
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct WindowSize {
    pub raw: Option<u16>,
    pub ty: WindowSizeType,
}

/// TCP Window Size representation used for fingerprinting different TCP stacks
#[derive(Clone, Debug, PartialEq)]
pub enum WindowSizeType {
    /// Window size is a multiple of MSS (Maximum Segment Size)
    /// The u8 value represents the multiplier (e.g., Mss(4) means window = MSS * 4)
    Mss(u8),

    /// Window size is a multiple of MTU (Maximum Transmission Unit)
    /// The u8 value represents the multiplier (e.g., Mtu(4) means window = MTU * 4)
    Mtu(u8),

    /// Raw window size value when it doesn't match any pattern
    /// Contains the actual window size value from the TCP header
    Value(u16),

    /// Window size follows a modulo pattern
    /// The u16 value represents the modulo base (e.g., Mod(1024) means window % 1024 == 0)
    Mod(u16),

    /// Represents any window size (wildcard matcher)
    Any,
}

impl WindowSize {
    pub fn distance_window_size(&self, other: &WindowSize, mss: Option<u16>) -> Option<u32> {
        match (&self.ty, &other.ty) {
            (WindowSizeType::Mss(a), WindowSizeType::Mss(b)) => {
                if a == b {
                    Some(TcpMatchQuality::High.as_score())
                } else {
                    Some(TcpMatchQuality::Low.as_score())
                }
            }
            (WindowSizeType::Mtu(a), WindowSizeType::Mtu(b)) => {
                if a == b {
                    Some(TcpMatchQuality::High.as_score())
                } else {
                    Some(TcpMatchQuality::Low.as_score())
                }
            }
            (WindowSizeType::Value(a), WindowSizeType::Mss(b)) => {
                if let Some(mss_value) = mss {
                    let ratio_other = a / mss_value;
                    if *b as u16 == ratio_other {
                        debug!(
                            "window size difference: observed_value {}, db_mss_multiplier {} == ratio_other {}",
                            a, b, ratio_other
                        );
                        Some(TcpMatchQuality::High.as_score())
                    } else {
                        Some(TcpMatchQuality::Low.as_score())
                    }
                } else {
                    Some(TcpMatchQuality::Low.as_score())
                }
            }
            (WindowSizeType::Mod(a), WindowSizeType::Mod(b)) => {
                if a == b {
                    Some(TcpMatchQuality::High.as_score())
                } else {
                    Some(TcpMatchQuality::Low.as_score())
                }
            }
            (_, WindowSizeType::Any) | (WindowSizeType::Any, _) => {
                Some(TcpMatchQuality::High.as_score())
            }
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum TcpOption {
    /// eol+n  - explicit end of options, followed by n bytes of padding
    Eol(u8),
    /// nop    - no-op option
    Nop,
    /// mss    - maximum segment size
    Mss,
    /// ws     - window scaling
    Ws,
    /// sok    - selective ACK permitted
    Sok,
    /// sack   - selective ACK (should not be seen)
    Sack,
    /// ts     - timestamp
    TS,
    /// ?n     - unknown option ID n
    Unknown(u8),
}

#[derive(Clone, Debug, PartialEq)]
pub enum Quirk {
    /// df     - "don't fragment" set (probably PMTUD); ignored for IPv6
    Df,
    /// id+    - DF set but IPID non-zero; ignored for IPv6
    NonZeroID,
    /// id-    - DF not set but IPID is zero; ignored for IPv6
    ZeroID,
    /// ecn    - explicit congestion notification support
    Ecn,
    /// 0+     - "must be zero" field not zero; ignored for IPv6
    MustBeZero,
    /// flow   - non-zero IPv6 flow ID; ignored for IPv4
    FlowID,
    /// seq-   - sequence number is zero
    SeqNumZero,
    /// ack+   - ACK number is non-zero, but ACK flag not set
    AckNumNonZero,
    /// ack-   - ACK number is zero, but ACK flag set
    AckNumZero,
    /// uptr+  - URG pointer is non-zero, but URG flag not set
    NonZeroURG,
    /// urgf+  - URG flag used
    Urg,
    /// pushf+ - PUSH flag used
    Push,
    /// ts1-   - own timestamp specified as zero
    OwnTimestampZero,
    /// ts2+   - non-zero peer timestamp on initial SYN
    PeerTimestampNonZero,
    /// opt+   - trailing non-zero data in options segment
    TrailinigNonZero,
    /// exws   - excessive window scaling factor (> 14)
    ExcessiveWindowScaling,
    /// bad    - malformed TCP options
    OptBad,
}

/// Classification of TCP payload sizes used in fingerprinting
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PayloadSize {
    /// Packet has no payload (empty)
    /// Common in SYN packets and some control messages
    Zero,

    /// Packet contains data in the payload
    /// Typical for data transfer packets
    NonZero,

    /// Matches any payload size
    /// Used as a wildcard in signature matching
    Any,
}

impl PayloadSize {
    pub fn distance_payload_size(&self, other: &PayloadSize) -> Option<u32> {
        if other == &PayloadSize::Any || self == other {
            Some(TcpMatchQuality::High.as_score())
        } else {
            None
        }
    }
}

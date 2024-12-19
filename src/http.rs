#[derive(Clone, Debug, PartialEq)]
pub struct Signature {
    /// HTTP version
    pub version: Version,
    /// ordered list of headers that should appear in matching traffic.
    pub horder: Vec<Header>,
    /// list of headers that must *not* appear in matching traffic.
    pub habsent: Vec<Header>,
    /// expected substring in 'User-Agent' or 'Server'.
    pub expsw: String,
}

impl Signature {
    pub fn matches(&self, db_signature: &Self) -> bool {
        self.version.matches_version(&db_signature.version)
            && self.horder == db_signature.horder
            && self.habsent == db_signature.habsent
            && self.expsw == db_signature.expsw
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum Version {
    /// HTTP/1.0
    V10,
    /// HTTP/1.1
    V11,
    /// HTTP/1.0 or HTTP/1.1
    Any,
}

impl Version {
    pub fn matches_version(&self, other: &Version) -> bool {
        matches!(
            (self, other),
            (Version::V10, Version::V10) | (Version::V11, Version::V11) | (_, Version::Any)
        )
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Header {
    pub optional: bool,
    pub name: String,
    pub value: Option<String>,
}

#[cfg(test)]
pub fn header<S: AsRef<str>>(name: S) -> Header {
    Header::new(name)
}

//TODO: WIP
//#[cfg(test)]
impl Header {
    pub fn new<S: AsRef<str>>(name: S) -> Self {
        Header {
            optional: false,
            name: name.as_ref().to_owned(),
            value: None,
        }
    }

    pub fn with_value<S: AsRef<str>>(mut self, value: S) -> Self {
        self.value = Some(value.as_ref().to_owned());
        self
    }

    pub fn optional(mut self) -> Self {
        self.optional = true;
        self
    }
}

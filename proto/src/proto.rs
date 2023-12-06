use lber::common::TagClass;
use lber::structure::{StructureTag, PL};
use lber::structures::ASNTag;
use lber::structures::{
    Boolean, Enumerated, ExplicitTag, Integer, Null, OctetString, Sequence, Set, Tag,
};
use lber::universal::Types;
use lber::write as lber_write;

use lber::parse::Parser;

use bytes::BytesMut;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::fmt;
use uuid::Uuid;

use crate::error::LdapProtoError;
use std::convert::{From, TryFrom};
use std::hash::Hash;
use std::iter::{once, once_with};

use base64::{engine::general_purpose, Engine as _};

pub const OID_WHOAMI: &str = "1.3.6.1.4.1.4203.1.11.3";
pub const OID_PASSWORD_MODIFY: &str = "1.3.6.1.4.1.4203.1.11.1";

macro_rules! bytes_to_string {
    ($bytes:expr) => {
        if let Ok(s) = String::from_utf8($bytes.clone()) {
            s
        } else {
            let mut s = format!("b64[{}]", general_purpose::URL_SAFE.encode(&$bytes));
            if s.len() > 100 {
                s.truncate(96);
                s.push_str("...]");
            }
            s
        }
    };
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub struct LdapMsg {
    pub msgid: i32,
    pub op: LdapOp,
    pub ctrl: Vec<LdapControl>,
}

#[derive(Debug, Clone, PartialEq, Hash, Eq, PartialOrd, Ord)]
#[repr(i64)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum SyncRequestMode {
    RefreshOnly = 1,
    RefreshAndPersist = 3,
}

#[derive(Debug, Clone, PartialEq, Hash, Eq, PartialOrd, Ord)]
#[repr(i64)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum SyncStateValue {
    Present = 0,
    Add = 1,
    Modify = 2,
    Delete = 3,
}

#[derive(Clone, PartialEq, Hash, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum LdapControl {
    SyncRequest {
        // Shouldn't this imply true?
        criticality: bool,
        mode: SyncRequestMode,
        cookie: Option<Vec<u8>>,
        reload_hint: bool,
    },
    SyncState {
        state: SyncStateValue,
        entry_uuid: Uuid,
        cookie: Option<Vec<u8>>,
    },
    SyncDone {
        cookie: Option<Vec<u8>>,
        refresh_deletes: bool,
    },
    AdDirsync {
        flags: i64,
        // Msdn and wireshark disagree on the name of this type.
        max_bytes: i64,
        cookie: Option<Vec<u8>>,
    },
    // https://www.ietf.org/rfc/rfc2696.txt
    SimplePagedResults {
        size: i64,
        cookie: Vec<u8>,
    },
    ManageDsaIT {
        criticality: bool,
    },
}

impl fmt::Debug for LdapControl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LdapControl::SyncRequest {
                criticality,
                mode,
                cookie,
                reload_hint,
            } => {
                let d_cookie = cookie.as_ref().map(|s| bytes_to_string!(s));
                f.debug_struct("LdapControl::SyncRequest")
                    .field("criticality", &criticality)
                    .field("mode", &mode)
                    .field("cookie", &d_cookie)
                    .field("reload_hint", &reload_hint)
                    .finish()
            }
            LdapControl::SyncState {
                state,
                entry_uuid,
                cookie,
            } => {
                let d_cookie = cookie.as_ref().map(|s| bytes_to_string!(s));
                f.debug_struct("LdapControl::SyncState")
                    .field("state", &state)
                    .field("entry_uuid", &entry_uuid)
                    .field("cookie", &d_cookie)
                    .finish()
            }
            LdapControl::SyncDone {
                cookie,
                refresh_deletes,
            } => {
                let d_cookie = cookie.as_ref().map(|s| bytes_to_string!(s));
                f.debug_struct("LdapControl::SyncDone")
                    .field("refresh_deletes", &refresh_deletes)
                    .field("cookie", &d_cookie)
                    .finish()
            }
            LdapControl::AdDirsync {
                flags,
                max_bytes,
                cookie,
            } => {
                let d_cookie = cookie.as_ref().map(|s| bytes_to_string!(s));
                f.debug_struct("LdapControl::AdDirsync")
                    .field("flags", &flags)
                    .field("max_bytes", &max_bytes)
                    .field("cookie", &d_cookie)
                    .finish()
            }
            LdapControl::SimplePagedResults { size, cookie } => {
                let d_cookie = bytes_to_string!(cookie);
                f.debug_struct("LdapControl::SimplePagedResults")
                    .field("size", &size)
                    .field("cookie", &d_cookie)
                    .finish()
            }
            LdapControl::ManageDsaIT { criticality } => f
                .debug_struct("LdapControl::ManageDsaIT")
                .field("criticality", &criticality)
                .finish(),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
#[repr(i64)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum LdapResultCode {
    Success = 0,
    OperationsError = 1,
    ProtocolError = 2,
    TimeLimitExceeded = 3,
    SizeLimitExceeded = 4,
    CompareFalse = 5,
    CompareTrue = 6,
    AuthMethodNotSupported = 7,
    StrongerAuthRequired = 8,
    // 9 reserved?
    Referral = 10,
    AdminLimitExceeded = 11,
    UnavailableCriticalExtension = 12,
    ConfidentialityRequired = 13,
    SaslBindInProgress = 14,
    // 15 ?
    NoSuchAttribute = 16,
    UndefinedAttributeType = 17,
    InappropriateMatching = 18,
    ConstraintViolation = 19,
    AttributeOrValueExists = 20,
    InvalidAttributeSyntax = 21,
    //22 31
    NoSuchObject = 32,
    AliasProblem = 33,
    InvalidDNSyntax = 34,
    // 35
    AliasDereferencingProblem = 36,
    // 37 - 47
    InappropriateAuthentication = 48,
    InvalidCredentials = 49,
    InsufficentAccessRights = 50,
    Busy = 51,
    Unavailable = 52,
    UnwillingToPerform = 53,
    LoopDetect = 54,
    // 55 - 63
    NamingViolation = 64,
    ObjectClassViolation = 65,
    NotAllowedOnNonLeaf = 66,
    NotALlowedOnRDN = 67,
    EntryAlreadyExists = 68,
    ObjectClassModsProhibited = 69,
    // 70
    AffectsMultipleDSAs = 71,
    // 72 - 79
    Other = 80,
    EsyncRefreshRequired = 4096,
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub struct LdapResult {
    pub code: LdapResultCode,
    pub matcheddn: String,
    pub message: String,
    pub referral: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum LdapOp {
    BindRequest(LdapBindRequest),
    BindResponse(LdapBindResponse),
    UnbindRequest,
    // https://tools.ietf.org/html/rfc4511#section-4.5
    SearchRequest(LdapSearchRequest),
    SearchResultEntry(LdapSearchResultEntry),
    SearchResultDone(LdapResult),
    SearchResultReference(LdapSearchResultReference),
    // https://datatracker.ietf.org/doc/html/rfc4511#section-4.6
    ModifyRequest(LdapModifyRequest),
    ModifyResponse(LdapResult),
    // https://tools.ietf.org/html/rfc4511#section-4.7
    AddRequest(LdapAddRequest),
    AddResponse(LdapResult),
    // https://tools.ietf.org/html/rfc4511#section-4.8
    DelRequest(String),
    DelResponse(LdapResult),
    // https://datatracker.ietf.org/doc/html/rfc4511#section-4.9
    ModifyDNRequest(LdapModifyDNRequest),
    ModifyDNResponse(LdapResult),
    // https://www.rfc-editor.org/rfc/rfc4511#section-4.10
    CompareRequest(LdapCompareRequest),
    CompareResult(LdapResult),
    // https://tools.ietf.org/html/rfc4511#section-4.11
    AbandonRequest(i32),
    // https://tools.ietf.org/html/rfc4511#section-4.12
    ExtendedRequest(LdapExtendedRequest),
    ExtendedResponse(LdapExtendedResponse),
    // https://www.rfc-editor.org/rfc/rfc4511#section-4.13
    IntermediateResponse(LdapIntermediateResponse),
}

#[derive(Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum LdapBindCred {
    Simple(String),
    SASL(SaslCredentials),
}

#[derive(Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[cfg_attr(feature = "serde", serde(rename = "snake_case"))]
pub struct SaslCredentials {
    pub mechanism: String,
    pub credentials: Vec<u8>,
}

impl From<SaslCredentials> for StructureTag {
    fn from(value: SaslCredentials) -> Self {
        StructureTag {
            id: 3,                    // SASL credentials are a SEQUENCE
            class: TagClass::Context, // SEQUENCE is a universal type
            payload: PL::C(vec![
                StructureTag {
                    class: TagClass::Universal,
                    id: Types::OctetString as u64, // or Types::PrintableString as u64
                    payload: PL::P(value.mechanism.into_bytes()),
                },
                StructureTag {
                    class: TagClass::Universal,
                    id: Types::OctetString as u64,
                    payload: PL::P(value.credentials),
                },
            ]),
        }
    }
}

impl fmt::Debug for SaslCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SaslCredentials")
            .field("mechanism", &self.mechanism)
            .finish()
    }
}

// Implement by hand to avoid printing the password.
impl fmt::Debug for LdapBindCred {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LdapBindCred::Simple(_) => f.debug_struct("LdapBindCred::Simple").finish(),
            LdapBindCred::SASL(_) => f.debug_struct("LdapBindCred::SASL").finish(),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub struct LdapBindRequest {
    pub dn: String,
    pub cred: LdapBindCred,
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub struct LdapBindResponse {
    pub res: LdapResult,
    pub saslcreds: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Hash, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[repr(i64)]
pub enum LdapSearchScope {
    Base = 0,
    OneLevel = 1,
    Subtree = 2,
    // https://datatracker.ietf.org/doc/html/draft-sermersheim-ldap-subordinate-scope-02#section-2
    Children = 3,
}

#[derive(Debug, Clone, PartialEq, Hash, Eq, PartialOrd, Ord)]
#[repr(i64)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum LdapDerefAliases {
    Never = 0,
    InSearching = 1,
    FindingBaseObj = 2,
    Always = 3,
}

#[derive(Debug, Clone, PartialEq, Default, Hash, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub struct LdapSubstringFilter {
    pub initial: Option<String>,
    pub any: Vec<String>,
    pub final_: Option<String>, //escape final keyword
}

impl From<&str> for LdapSubstringFilter {
    fn from(value: &str) -> Self {
        let mut filter = LdapSubstringFilter {
            initial: None,
            any: Vec::new(),
            final_: None,
        };

        let mut split_iter = value.split('*');
        if let Some(start) = split_iter.next() {
            if !start.is_empty() {
                filter.initial = Some(start.to_string());
            }
        }

        if let Some(end) = split_iter.next_back() {
            if !end.is_empty() {
                filter.final_ = Some(end.to_string());
            }
        }

        split_iter.for_each(|v| filter.any.push(v.to_string()));

        filter
    }
}

impl From<String> for LdapSubstringFilter {
    fn from(value: String) -> Self {
        Self::from(value.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Default, Hash, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub struct LdapMatchingRuleAssertion {
    pub matching_rule: Option<String>,
    pub type_: Option<String>,
    pub match_value: String,
    pub dn_attributes: bool, // DEFAULT FALSE
}

impl LdapMatchingRuleAssertion {
    pub fn from_strings(left: String, right: String) -> Self {
        let match_value = right.to_string();
        let mut split = left.split(':').collect::<VecDeque<_>>();
        let dn_attribute = split.contains(&"dn");
        split.retain(|s| *s != "dn");
        let first = split.pop_front().unwrap();
        dbg!(first);
        if first.is_empty() {
            // :caseExactMatch:=foo
            return Self {
                matching_rule: split.pop_front().map(|s| s.to_string()),
                type_: None,
                match_value,
                dn_attributes: dn_attribute,
            };
        }

        // foo:caseExactMatch:=bar
        Self {
            matching_rule: split.pop_back().map(|s| s.to_string()),
            type_: Some(first.to_string()),
            match_value,
            dn_attributes: dn_attribute,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Hash, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum LdapFilter {
    And(Vec<LdapFilter>),
    Or(Vec<LdapFilter>),
    Not(Box<LdapFilter>),
    Equality(String, String),
    Substring(String, LdapSubstringFilter),
    GreaterOrEqual(String, String),
    LessOrEqual(String, String),
    Present(String),
    Approx(String, String),
    Extensible(LdapMatchingRuleAssertion),
}

#[derive(Debug, Clone, PartialEq, PartialOrd, Ord, Hash, Eq)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub struct LdapSearchRequest {
    pub base: String,
    pub scope: LdapSearchScope,
    pub aliases: LdapDerefAliases,
    pub sizelimit: i32,
    pub timelimit: i32,
    pub typesonly: bool,
    pub filter: LdapFilter,
    pub attrs: Vec<String>,
}

// https://tools.ietf.org/html/rfc4511#section-4.1.7
#[derive(Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub struct LdapPartialAttribute {
    pub atype: String,
    pub vals: Vec<Vec<u8>>,
}

impl LdapPartialAttribute {
    pub fn size(&self) -> usize {
        std::mem::size_of::<Self>()
            + self.atype.capacity()
            + (self.vals.capacity() * std::mem::size_of::<Vec<()>>())
            + self
                .vals
                .iter()
                .map(|val| val.capacity() * std::mem::size_of::<Vec<()>>())
                .sum::<usize>()
    }
}

// Implement by hand to avoid printing the password.
impl fmt::Debug for LdapPartialAttribute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut f = f.debug_struct("LdapPartialAttribute");
        f.field("atype", &self.atype);

        let atype_lower = self.atype.to_lowercase();
        if atype_lower == "userpassword"
            || atype_lower == "ipanthash"
            || atype_lower == "oathtotptoken"
            || atype_lower == "oathhotptoken"
        {
            f.field("vals", &["********"]);
        } else {
            let d_vals: Vec<_> = self.vals.iter().map(|val| bytes_to_string!(val)).collect();
            f.field("vals", &d_vals);
        }
        f.finish()
    }
}

// A PartialAttribute allows zero values, while
// Attribute requires at least one value.
pub type LdapAttribute = LdapPartialAttribute;

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub struct LdapSearchResultEntry {
    pub dn: String,
    pub attributes: Vec<LdapPartialAttribute>,
}

impl LdapSearchResultEntry {
    pub fn size(&self) -> usize {
        std::mem::size_of::<Self>()
            + self.dn.capacity()
            + self
                .attributes
                .iter()
                .map(|attr| attr.size())
                .sum::<usize>()
    }
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub struct LdapAddRequest {
    pub dn: String,
    pub attributes: Vec<LdapAttribute>,
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub struct LdapModifyRequest {
    pub dn: String,
    pub changes: Vec<LdapModify>,
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub struct LdapModify {
    pub operation: LdapModifyType,
    pub modification: LdapPartialAttribute,
}

#[derive(Debug, Clone, PartialEq)]
#[repr(i64)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum LdapModifyType {
    Add = 0,
    Delete = 1,
    Replace = 2,
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub struct LdapModifyDNRequest {
    pub dn: String,
    pub newrdn: String,
    pub deleteoldrdn: bool,
    pub new_superior: Option<String>,
}

#[derive(Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub struct LdapCompareRequest {
    pub dn: String,
    pub atype: String,
    pub val: Vec<u8>,
}

impl fmt::Debug for LdapCompareRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let d_val = bytes_to_string!(self.val);
        f.debug_struct("LdapCompareRequest")
            .field("dn", &self.dn)
            .field("atype", &self.atype)
            .field("val", &d_val)
            .finish()
    }
}

#[derive(Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub struct LdapExtendedRequest {
    // 0
    pub name: String,
    // 1
    pub value: Option<Vec<u8>>,
}

// Implement by hand to avoid printing the password.
impl fmt::Debug for LdapExtendedRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut f = f.debug_struct("LdapExtendedRequest");
        f.field("name", &self.name);
        if self.name == OID_PASSWORD_MODIFY {
            f.field("value", &self.value.as_ref().map(|_| "vec![...]"));
        } else {
            let d_value = self.value.as_ref().map(|s| bytes_to_string!(s));
            f.field("value", &d_value);
        }
        f.finish()
    }
}

#[derive(Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub struct LdapExtendedResponse {
    pub res: LdapResult,
    // 10
    pub name: Option<String>,
    // 11
    pub value: Option<Vec<u8>>,
}

impl fmt::Debug for LdapExtendedResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LdapExtendedResponse")
            .field("result", &self.res)
            .field("name", &self.name)
            // Password modify responses may contain a generated password
            // but they don't provide their OID in the name field. As a
            // result we have to assume this value could always be sensitive.
            .field("value", &"vec![...]")
            .finish()
    }
}

#[derive(Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum LdapIntermediateResponse {
    SyncInfoNewCookie {
        cookie: Vec<u8>,
    },
    SyncInfoRefreshDelete {
        cookie: Option<Vec<u8>>,
        done: bool,
    },
    SyncInfoRefreshPresent {
        cookie: Option<Vec<u8>>,
        done: bool,
    },
    SyncInfoIdSet {
        cookie: Option<Vec<u8>>,
        refresh_deletes: bool,
        syncuuids: Vec<Uuid>,
    },
    Raw {
        name: Option<String>,
        value: Option<Vec<u8>>,
    },
}

impl fmt::Debug for LdapIntermediateResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self {
            LdapIntermediateResponse::SyncInfoNewCookie { cookie } => {
                let d_cookie = bytes_to_string!(cookie);
                f.debug_struct("LdapIntermediateResponse::SyncInfoNewCookie")
                    .field("cookie", &d_cookie)
                    .finish()
            }
            LdapIntermediateResponse::SyncInfoRefreshDelete { cookie, done } => {
                let d_cookie = cookie.as_ref().map(|s| bytes_to_string!(s));
                f.debug_struct("LdapIntermediateResponse::SyncInfoRefreshDelete")
                    .field("cookie", &d_cookie)
                    .field("done", &done)
                    .finish()
            }
            LdapIntermediateResponse::SyncInfoRefreshPresent { cookie, done } => {
                let d_cookie = cookie.as_ref().map(|s| bytes_to_string!(s));
                f.debug_struct("LdapIntermediateResponse::SyncInfoRefreshPresent")
                    .field("cookie", &d_cookie)
                    .field("done", &done)
                    .finish()
            }
            LdapIntermediateResponse::SyncInfoIdSet {
                cookie,
                refresh_deletes,
                syncuuids,
            } => {
                let d_cookie = cookie.as_ref().map(|s| bytes_to_string!(s));
                f.debug_struct("LdapIntermediateResponse::SyncInfoIdSet")
                    .field("cookie", &d_cookie)
                    .field("refresh_deletes", &refresh_deletes)
                    .field("syncuuids", &syncuuids)
                    .finish()
            }
            LdapIntermediateResponse::Raw { name, value } => {
                let d_value = value.as_ref().map(|s| bytes_to_string!(s));
                f.debug_struct("LdapIntermediateResponse::Raw")
                    .field("name", &name)
                    .field("value", &d_value)
                    .finish()
            }
        }
    }
}

#[derive(Clone, PartialEq)]
pub struct LdapWhoamiRequest {}

impl From<LdapWhoamiRequest> for LdapExtendedRequest {
    fn from(_value: LdapWhoamiRequest) -> LdapExtendedRequest {
        LdapExtendedRequest {
            name: OID_WHOAMI.to_string(),
            value: None,
        }
    }
}

#[derive(Clone, PartialEq)]
pub struct LdapWhoamiResponse {
    pub dn: Option<String>,
}

impl TryFrom<&LdapExtendedResponse> for LdapWhoamiResponse {
    type Error = LdapProtoError;

    fn try_from(value: &LdapExtendedResponse) -> Result<Self, Self::Error> {
        if value.name.is_some() {
            return Err(LdapProtoError::WhoamiResponseName);
        }

        let dn = value
            .value
            .as_ref()
            .and_then(|bv| String::from_utf8(bv.to_vec()).ok());

        Ok(LdapWhoamiResponse { dn })
    }
}

#[derive(Clone, PartialEq)]
pub struct LdapPasswordModifyRequest {
    pub user_identity: Option<String>,
    pub old_password: Option<String>,
    pub new_password: Option<String>,
}

// Implement by hand to avoid printing the password.
impl fmt::Debug for LdapPasswordModifyRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut f = f.debug_struct("LdapPasswordModifyRequest");
        f.field("user_identity", &self.user_identity);
        f.field(
            "old_password",
            &self.old_password.as_ref().map(|_| "********"),
        );
        f.field(
            "new_password",
            &self.old_password.as_ref().map(|_| "********"),
        );
        f.finish()
    }
}

#[derive(Clone, PartialEq)]
pub struct LdapPasswordModifyResponse {
    pub res: LdapResult,
    pub gen_password: Option<String>,
}

impl fmt::Debug for LdapPasswordModifyResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LdapPasswordModifyResponse")
            .field("result", &self.res)
            .field("gen_password", &self.gen_password.is_some())
            .finish()
    }
}

impl From<LdapPasswordModifyRequest> for LdapExtendedRequest {
    fn from(value: LdapPasswordModifyRequest) -> LdapExtendedRequest {
        let inner: Vec<_> = vec![
            value.user_identity.map(|s| {
                Tag::OctetString(OctetString {
                    class: TagClass::Context,
                    id: 0,
                    inner: Vec::from(s),
                })
            }),
            value.old_password.map(|s| {
                Tag::OctetString(OctetString {
                    class: TagClass::Context,
                    id: 1,
                    inner: Vec::from(s),
                })
            }),
            value.new_password.map(|s| {
                Tag::OctetString(OctetString {
                    class: TagClass::Context,
                    id: 2,
                    inner: Vec::from(s),
                })
            }),
        ];

        let tag = Tag::Sequence(Sequence {
            inner: inner.into_iter().flatten().collect(),
            ..Default::default()
        });

        let mut bytes = BytesMut::new();

        lber_write::encode_into(&mut bytes, tag.into_structure())
            .expect("Failed to encode inner structure, this is a bug!");

        LdapExtendedRequest {
            name: OID_PASSWORD_MODIFY.to_string(),
            value: Some(bytes.to_vec()),
        }
    }
}

impl TryFrom<&LdapExtendedRequest> for LdapPasswordModifyRequest {
    type Error = LdapProtoError;

    fn try_from(value: &LdapExtendedRequest) -> Result<Self, Self::Error> {
        if value.name != OID_PASSWORD_MODIFY {
            return Err(LdapProtoError::PasswordModifyRequestOid);
        }

        let buf = if let Some(b) = &value.value {
            b
        } else {
            return Err(LdapProtoError::PasswordModifyRequestEmpty);
        };

        let mut parser = Parser::new();
        let (_rem, msg) = parser
            .parse(buf)
            .map_err(|_| LdapProtoError::PasswordModifyRequestBer)?;

        let seq = msg
            .match_id(Types::Sequence as u64)
            .and_then(|t| t.expect_constructed())
            .ok_or(LdapProtoError::PasswordModifyRequestBer)?;

        let mut lpmr = LdapPasswordModifyRequest {
            user_identity: None,
            old_password: None,
            new_password: None,
        };

        for t in seq.into_iter() {
            let id = t.id;
            let s = t
                .expect_primitive()
                .and_then(|bv| String::from_utf8(bv).ok())
                .ok_or(LdapProtoError::PasswordModifyRequestBer)?;

            match id {
                0 => lpmr.user_identity = Some(s),
                1 => lpmr.old_password = Some(s),
                2 => lpmr.new_password = Some(s),
                _ => return Err(LdapProtoError::PasswordModifyRequestValueId),
            }
        }

        Ok(lpmr)
    }
}

impl From<LdapPasswordModifyResponse> for LdapExtendedResponse {
    fn from(value: LdapPasswordModifyResponse) -> LdapExtendedResponse {
        let inner: Vec<_> = vec![value.gen_password.map(|s| {
            Tag::OctetString(OctetString {
                class: TagClass::Context,
                id: 0,
                inner: Vec::from(s),
            })
        })];

        let tag = Tag::Sequence(Sequence {
            inner: inner.into_iter().flatten().collect(),
            ..Default::default()
        });

        let mut bytes = BytesMut::new();

        lber_write::encode_into(&mut bytes, tag.into_structure())
            .expect("Failed to encode inner structure, this is a bug!");

        LdapExtendedResponse {
            res: value.res,
            // responseName is absent.
            name: None,
            value: Some(bytes.to_vec()),
        }
    }
}

impl TryFrom<&LdapExtendedResponse> for LdapPasswordModifyResponse {
    type Error = LdapProtoError;

    fn try_from(value: &LdapExtendedResponse) -> Result<Self, Self::Error> {
        if value.name.is_some() {
            return Err(LdapProtoError::PasswordModifyResponseName);
        }

        let buf = if let Some(b) = &value.value {
            b
        } else {
            return Err(LdapProtoError::PasswordModifyResponseEmpty);
        };

        let mut parser = Parser::new();
        let (_rem, msg) = parser
            .parse(buf)
            .map_err(|_| LdapProtoError::PasswordModifyResponseBer)?;

        let mut seq = msg
            .match_id(Types::Sequence as u64)
            .and_then(|t| t.expect_constructed())
            .ok_or(LdapProtoError::PasswordModifyResponseBer)?;

        let gen_password = seq
            .pop()
            .and_then(|t| t.match_id(0))
            .and_then(|t| t.expect_primitive())
            .and_then(|bv| String::from_utf8(bv).ok());

        Ok(LdapPasswordModifyResponse {
            res: value.res.clone(),
            gen_password,
        })
    }
}

impl From<LdapBindCred> for Tag {
    fn from(value: LdapBindCred) -> Tag {
        match value {
            LdapBindCred::Simple(pw) => Tag::OctetString(OctetString {
                id: 0,
                class: TagClass::Context,
                inner: Vec::from(pw),
            }),
            LdapBindCred::SASL(token) => Tag::StructureTag(token.into()),
        }
    }
}

impl LdapMsg {
    pub fn new(msgid: i32, op: LdapOp) -> Self {
        LdapMsg {
            msgid,
            op,
            ctrl: Vec::new(),
        }
    }

    pub fn new_with_ctrls(msgid: i32, op: LdapOp, ctrl: Vec<LdapControl>) -> Self {
        LdapMsg { msgid, op, ctrl }
    }

    pub fn try_from_openldap_mem_dump(bytes: &[u8]) -> Result<Self, LdapProtoError> {
        let mut parser = lber::parse::Parser::new();
        let (r1_bytes, msgid_tag) = parser
            .parse(bytes)
            .map_err(|_| LdapProtoError::OlMemDumpBer)?;

        let (r2_bytes, op_tag) = parser
            .parse(r1_bytes)
            .map_err(|_| LdapProtoError::OlMemDumpBer)?;

        let ctrl_tag = if r2_bytes.is_empty() {
            None
        } else {
            parser
                .parse(r2_bytes)
                .map(|(_rem, tag)| Some(tag))
                .map_err(|_| LdapProtoError::OlMemDumpBer)?
        };

        // The first item should be the messageId
        let msgid = msgid_tag
            .match_class(TagClass::Universal)
            .and_then(|t| t.match_id(Types::Integer as u64))
            // Get the raw bytes
            .and_then(|t| t.expect_primitive())
            .and_then(ber_integer_to_i64)
            // Trunc to i32.
            .map(|i| i as i32)
            .ok_or(LdapProtoError::OlMemDumpBer)?;

        let op = LdapOp::try_from(op_tag)?;

        let ctrl = ctrl_tag
            .and_then(|t| t.match_class(TagClass::Context))
            .and_then(|t| t.match_id(0))
            // So it's probably controls, decode them?
            .map(|_t| Vec::new())
            .unwrap_or_else(Vec::new);

        Ok(LdapMsg { msgid, op, ctrl })
    }
}

impl TryFrom<StructureTag> for LdapMsg {
    type Error = LdapProtoError;

    /// <https://tools.ietf.org/html/rfc4511#section-4.1.1>
    fn try_from(value: StructureTag) -> Result<Self, Self::Error> {
        /*
         * LDAPMessage ::= SEQUENCE {
         *      messageID       MessageID,
         *      protocolOp      CHOICE {
         *           bindRequest           BindRequest,
         *           bindResponse          BindResponse,
         *           unbindRequest         UnbindRequest,
         *           searchRequest         SearchRequest,
         *           searchResEntry        SearchResultEntry,
         *           searchResDone         SearchResultDone,
         *           searchResRef          SearchResultReference,
         *           modifyRequest         ModifyRequest,
         *           modifyResponse        ModifyResponse,
         *           addRequest            AddRequest,
         *           addResponse           AddResponse,
         *           delRequest            DelRequest,
         *           delResponse           DelResponse,
         *           modDNRequest          ModifyDNRequest,
         *           modDNResponse         ModifyDNResponse,
         *           compareRequest        CompareRequest,
         *           compareResponse       CompareResponse,
         *           abandonRequest        AbandonRequest,
         *           extendedReq           ExtendedRequest,
         *           extendedResp          ExtendedResponse,
         *           ...,
         *           intermediateResponse  IntermediateResponse },
         *      controls       [0] Controls OPTIONAL }
         *
         * MessageID ::= INTEGER (0 ..  maxInt)
         *
         * maxInt INTEGER ::= 2147483647 -- (2^^31 - 1) --
         */
        let mut seq = value
            .match_id(Types::Sequence as u64)
            .and_then(|t| t.expect_constructed())
            .ok_or_else(|| {
                error!("Message is not constructed");
                LdapProtoError::LdapMsgBer
            })?;

        // seq is now a vec of the inner elements.
        let (msgid_tag, op_tag, ctrl_tag) = match seq.len() {
            2 => {
                // We destructure in reverse order due to how vec in rust
                // works.
                let c = None;
                let o = seq.pop();
                let m = seq.pop();
                (m, o, c)
            }
            3 => {
                let c = seq.pop();
                let o = seq.pop();
                let m = seq.pop();
                (m, o, c)
            }
            _ => {
                error!("Invalid ldapmsg sequence length");
                return Err(LdapProtoError::LdapMsgSeqLen);
            }
        };

        trace!(?msgid_tag, ?op_tag, ?ctrl_tag);

        // The first item should be the messageId
        let msgid = msgid_tag
            .and_then(|t| t.match_class(TagClass::Universal))
            .and_then(|t| t.match_id(Types::Integer as u64))
            // Get the raw bytes
            .and_then(|t| t.expect_primitive())
            .and_then(ber_integer_to_i64)
            // Trunc to i32.
            .map(|i| i as i32)
            .ok_or_else(|| {
                error!("Invalid msgid");
                LdapProtoError::LdapMsgId
            })?;

        let op = op_tag.ok_or_else(|| {
            error!("No ldap op present");
            LdapProtoError::LdapMsgOp
        })?;
        let op = LdapOp::try_from(op)?;

        let ctrl_vec = ctrl_tag
            .and_then(|t| t.match_class(TagClass::Context))
            .and_then(|t| t.match_id(0))
            // So it's probably controls, decode them?
            .and_then(|t| t.expect_constructed())
            .unwrap_or_default();

        let ctrl = ctrl_vec
            .into_iter()
            .map(TryInto::<LdapControl>::try_into)
            .collect::<Result<Vec<_>, _>>()?;

        let msg = LdapMsg { msgid, op, ctrl };

        trace!(ldapmsg = ?msg);

        Ok(msg)
    }
}

impl From<LdapMsg> for StructureTag {
    fn from(value: LdapMsg) -> StructureTag {
        let LdapMsg { msgid, op, ctrl } = value;
        let seq: Vec<_> = once_with(|| {
            Some(Tag::Integer(Integer {
                inner: msgid as i64,
                ..Default::default()
            }))
        })
        .chain(once_with(|| Some(op.into())))
        .chain(once_with(|| {
            if ctrl.is_empty() {
                None
            } else {
                let inner = ctrl.into_iter().map(|c| c.into()).collect();
                Some(Tag::Sequence(Sequence {
                    class: TagClass::Context,
                    id: 0,
                    inner,
                    // ..Default::default()
                }))
            }
        }))
        .chain(once(None))
        .flatten()
        .collect();
        Tag::Sequence(Sequence {
            inner: seq,
            ..Default::default()
        })
        .into_structure()
    }
}

impl TryFrom<StructureTag> for LdapOp {
    type Error = LdapProtoError;

    fn try_from(value: StructureTag) -> Result<Self, Self::Error> {
        let StructureTag { class, id, payload } = value;
        if class != TagClass::Application {
            error!("ldap op is not tagged as application");
            return Err(LdapProtoError::LdapOpTag);
        }
        match (id, payload) {
            // https://tools.ietf.org/html/rfc4511#section-4.2
            // BindRequest
            (0, PL::C(inner)) => LdapBindRequest::try_from(inner).map(LdapOp::BindRequest),
            // BindResponse
            (1, PL::C(inner)) => LdapBindResponse::try_from(inner).map(LdapOp::BindResponse),
            // UnbindRequest
            (2, _) => Ok(LdapOp::UnbindRequest),
            (3, PL::C(inner)) => LdapSearchRequest::try_from(inner).map(LdapOp::SearchRequest),
            (4, PL::C(inner)) => {
                LdapSearchResultEntry::try_from(inner).map(LdapOp::SearchResultEntry)
            }
            (5, PL::C(inner)) => {
                LdapResult::try_from_tag(inner).map(|(lr, _)| LdapOp::SearchResultDone(lr))
            }
            (6, PL::C(inner)) => LdapModifyRequest::try_from(inner).map(LdapOp::ModifyRequest),
            (7, PL::C(inner)) => {
                LdapResult::try_from_tag(inner).map(|(lr, _)| LdapOp::ModifyResponse(lr))
            }
            (8, PL::C(inner)) => LdapAddRequest::try_from(inner).map(LdapOp::AddRequest),
            (9, PL::C(inner)) => {
                LdapResult::try_from_tag(inner).map(|(lr, _)| LdapOp::AddResponse(lr))
            }
            (10, PL::P(inner)) => String::from_utf8(inner)
                .ok()
                .ok_or(LdapProtoError::DelRequestBer)
                .map(LdapOp::DelRequest),
            (11, PL::C(inner)) => {
                LdapResult::try_from_tag(inner).map(|(lr, _)| LdapOp::DelResponse(lr))
            }
            (12, PL::C(inner)) => LdapModifyDNRequest::try_from(inner).map(LdapOp::ModifyDNRequest),
            (13, PL::C(inner)) => {
                LdapResult::try_from_tag(inner).map(|(lr, _)| LdapOp::ModifyDNResponse(lr))
            }
            // https://datatracker.ietf.org/doc/html/rfc4511#section-4.1.9
            (14, PL::C(inner)) => LdapBindResponse::try_from(inner).map(LdapOp::BindResponse),
            (15, PL::C(inner)) => {
                LdapResult::try_from_tag(inner).map(|(lr, _)| LdapOp::CompareResult(lr))
            }
            (16, PL::P(inner)) => ber_integer_to_i64(inner)
                .ok_or(LdapProtoError::AbandonRequestBer)
                .map(|s| LdapOp::AbandonRequest(s as i32)),
            (19, PL::C(inner)) => {
                LdapSearchResultReference::try_from(inner).map(LdapOp::SearchResultReference)
            }
            (23, PL::C(inner)) => LdapExtendedRequest::try_from(inner).map(LdapOp::ExtendedRequest),
            (24, PL::C(inner)) => {
                LdapExtendedResponse::try_from(inner).map(LdapOp::ExtendedResponse)
            }
            (25, PL::C(inner)) => {
                LdapIntermediateResponse::try_from(inner).map(LdapOp::IntermediateResponse)
            }
            (id, _) => {
                println!("unknown op -> {:?}", id);
                Err(LdapProtoError::LdapOpUnknown)
            }
        }
    }
}

impl From<LdapOp> for Tag {
    fn from(value: LdapOp) -> Tag {
        match value {
            LdapOp::BindRequest(lbr) => Tag::Sequence(Sequence {
                class: TagClass::Application,
                id: 0,
                inner: lbr.into(),
            }),
            LdapOp::BindResponse(lbr) => Tag::Sequence(Sequence {
                class: TagClass::Application,
                id: 1,
                inner: lbr.into(),
            }),
            LdapOp::UnbindRequest => Tag::Null(Null {
                class: TagClass::Application,
                id: 2,
                inner: (),
            }),
            LdapOp::SearchRequest(sr) => Tag::Sequence(Sequence {
                class: TagClass::Application,
                id: 3,
                inner: sr.into(),
            }),
            LdapOp::SearchResultEntry(sre) => Tag::Sequence(Sequence {
                class: TagClass::Application,
                id: 4,
                inner: sre.into(),
            }),
            LdapOp::SearchResultDone(lr) => Tag::Sequence(Sequence {
                class: TagClass::Application,
                id: 5,
                inner: lr.into(),
            }),
            LdapOp::SearchResultReference(urls) => Tag::Sequence(Sequence {
                class: TagClass::Application,
                id: 19,
                inner: urls.into(),
            }),
            LdapOp::ModifyRequest(mr) => Tag::Sequence(Sequence {
                class: TagClass::Application,
                id: 6,
                inner: mr.into(),
            }),
            LdapOp::ModifyResponse(lr) => Tag::Sequence(Sequence {
                class: TagClass::Application,
                id: 7,
                inner: lr.into(),
            }),
            LdapOp::AddRequest(lar) => Tag::Sequence(Sequence {
                class: TagClass::Application,
                id: 8,
                inner: lar.into(),
            }),
            LdapOp::AddResponse(lr) => Tag::Sequence(Sequence {
                class: TagClass::Application,
                id: 9,
                inner: lr.into(),
            }),
            LdapOp::DelRequest(s) => Tag::OctetString(OctetString {
                class: TagClass::Application,
                id: 10,
                inner: Vec::from(s),
            }),
            LdapOp::DelResponse(lr) => Tag::Sequence(Sequence {
                class: TagClass::Application,
                id: 11,
                inner: lr.into(),
            }),
            LdapOp::ModifyDNRequest(mdr) => Tag::Sequence(Sequence {
                class: TagClass::Application,
                id: 12,
                inner: mdr.into(),
            }),
            LdapOp::ModifyDNResponse(lr) => Tag::Sequence(Sequence {
                class: TagClass::Application,
                id: 13,
                inner: lr.into(),
            }),
            LdapOp::CompareRequest(cr) => Tag::Sequence(Sequence {
                class: TagClass::Application,
                id: 14,
                inner: cr.into(),
            }),
            LdapOp::CompareResult(lr) => Tag::Sequence(Sequence {
                class: TagClass::Application,
                id: 15,
                inner: lr.into(),
            }),
            LdapOp::AbandonRequest(id) => Tag::Integer(Integer {
                class: TagClass::Application,
                id: 16,
                inner: id as i64,
            }),
            LdapOp::ExtendedRequest(ler) => Tag::Sequence(Sequence {
                class: TagClass::Application,
                id: 23,
                inner: ler.into(),
            }),
            LdapOp::ExtendedResponse(ler) => Tag::Sequence(Sequence {
                class: TagClass::Application,
                id: 24,
                inner: ler.into(),
            }),
            LdapOp::IntermediateResponse(lir) => Tag::Sequence(Sequence {
                class: TagClass::Application,
                id: 25,
                inner: lir.into(),
            }),
        }
    }
}

impl TryFrom<StructureTag> for LdapControl {
    type Error = LdapProtoError;

    fn try_from(value: StructureTag) -> Result<Self, Self::Error> {
        let mut seq = value
            .match_id(Types::Sequence as u64)
            .and_then(|t| t.expect_constructed())
            .ok_or(LdapProtoError::ControlBer)?;

        // We destructure in reverse order due to how vec in rust
        // works.
        let (oid_tag, criticality_tag, value_tag) = match seq.len() {
            1 => {
                let v = None;
                let c = None;
                let o = seq.pop();
                (o, c, v)
            }
            2 => {
                let v = seq.pop();
                let c = None;
                let o = seq.pop();
                (o, c, v)
            }
            3 => {
                let v = seq.pop();
                let c = seq.pop();
                let o = seq.pop();
                (o, c, v)
            }
            _ => return Err(LdapProtoError::ControlSeqLen),
        };

        // trace!(?oid_tag, ?criticality_tag, ?value_tag);

        // We need to know what the oid is first.
        let oid = oid_tag
            .and_then(|t| t.match_class(TagClass::Universal))
            .and_then(|t| t.match_id(Types::OctetString as u64))
            .and_then(|t| t.expect_primitive())
            .and_then(|bv| String::from_utf8(bv).ok())
            .ok_or(LdapProtoError::ControlBer)?;

        match oid.as_str() {
            "1.3.6.1.4.1.4203.1.9.1.1" => {
                // parse as sync req
                let criticality = criticality_tag
                    .and_then(|t| t.match_class(TagClass::Universal))
                    .and_then(|t| t.match_id(Types::Boolean as u64))
                    .and_then(|t| t.expect_primitive())
                    .and_then(ber_bool_to_bool)
                    .unwrap_or(false);

                let value_ber = value_tag
                    .and_then(|t| t.match_class(TagClass::Universal))
                    .and_then(|t| t.match_id(Types::OctetString as u64))
                    .and_then(|t| t.expect_primitive())
                    .ok_or(LdapProtoError::ControlBer)?;

                let mut parser = Parser::new();
                let (_rem, value) = parser
                    .parse(&value_ber)
                    .map_err(|_| LdapProtoError::ControlBer)?;

                let mut value = value
                    .expect_constructed()
                    .ok_or(LdapProtoError::ControlBer)?;

                value.reverse();

                let mode = value
                    .pop()
                    .and_then(|t| t.match_class(TagClass::Universal))
                    .and_then(|t| t.match_id(Types::Enumerated as u64))
                    .and_then(|t| t.expect_primitive())
                    .and_then(ber_integer_to_i64)
                    .and_then(|v| match v {
                        1 => Some(SyncRequestMode::RefreshOnly),
                        3 => Some(SyncRequestMode::RefreshAndPersist),
                        _ => None,
                    })
                    .ok_or(LdapProtoError::ControlSyncMode)?;

                let cookie = value
                    .pop()
                    .and_then(|t| t.match_class(TagClass::Universal))
                    .and_then(|t| t.match_id(Types::OctetString as u64))
                    .and_then(|t| t.expect_primitive());

                let reload_hint = value
                    .pop()
                    .and_then(|t| t.match_class(TagClass::Universal))
                    .and_then(|t| t.match_id(Types::Boolean as u64))
                    .and_then(|t| t.expect_primitive())
                    .and_then(ber_bool_to_bool)
                    .unwrap_or(false);

                Ok(LdapControl::SyncRequest {
                    criticality,
                    mode,
                    cookie,
                    reload_hint,
                })
            }
            "1.3.6.1.4.1.4203.1.9.1.2" => {
                // parse as sync state control

                //criticality is ignored.

                let value_ber = value_tag
                    .and_then(|t| t.match_class(TagClass::Universal))
                    .and_then(|t| t.match_id(Types::OctetString as u64))
                    .and_then(|t| t.expect_primitive())
                    .ok_or(LdapProtoError::ControlBer)?;

                let mut parser = Parser::new();
                let (_rem, value) = parser
                    .parse(&value_ber)
                    .map_err(|_| LdapProtoError::ControlBer)?;

                let mut value = value
                    .expect_constructed()
                    .ok_or(LdapProtoError::ControlBer)?;

                value.reverse();

                let state = value
                    .pop()
                    .and_then(|t| t.match_class(TagClass::Universal))
                    .and_then(|t| t.match_id(Types::Enumerated as u64))
                    .and_then(|t| t.expect_primitive())
                    .and_then(ber_integer_to_i64)
                    .and_then(|v| match v {
                        0 => Some(SyncStateValue::Present),
                        1 => Some(SyncStateValue::Add),
                        2 => Some(SyncStateValue::Modify),
                        3 => Some(SyncStateValue::Delete),
                        _ => None,
                    })
                    .ok_or(LdapProtoError::ControlSyncState)?;

                let entry_uuid = value
                    .pop()
                    .and_then(|t| t.match_class(TagClass::Universal))
                    .and_then(|t| t.match_id(Types::OctetString as u64))
                    .and_then(|t| t.expect_primitive())
                    .ok_or(LdapProtoError::ControlBer)
                    .and_then(|v| {
                        Uuid::from_slice(&v).map_err(|_| LdapProtoError::ControlSyncUuid)
                    })?;

                let cookie = value
                    .pop()
                    .and_then(|t| t.match_class(TagClass::Universal))
                    .and_then(|t| t.match_id(Types::OctetString as u64))
                    .and_then(|t| t.expect_primitive());

                Ok(LdapControl::SyncState {
                    state,
                    entry_uuid,
                    cookie,
                })
            }
            "1.3.6.1.4.1.4203.1.9.1.3" => {
                // parse as sync done control
                // criticality is ignored.

                let value_ber = value_tag
                    .and_then(|t| t.match_class(TagClass::Universal))
                    .and_then(|t| t.match_id(Types::OctetString as u64))
                    .and_then(|t| t.expect_primitive())
                    .ok_or(LdapProtoError::ControlBer)?;

                let mut parser = Parser::new();
                let (_rem, value) = parser
                    .parse(&value_ber)
                    .map_err(|_| LdapProtoError::ControlBer)?;

                let mut value = value
                    .expect_constructed()
                    .ok_or(LdapProtoError::ControlBer)?;

                value.reverse();

                let cookie = value
                    .pop()
                    .and_then(|t| t.match_class(TagClass::Universal))
                    .and_then(|t| t.match_id(Types::OctetString as u64))
                    .and_then(|t| t.expect_primitive());

                let refresh_deletes = value
                    .pop()
                    .and_then(|t| t.match_class(TagClass::Universal))
                    .and_then(|t| t.match_id(Types::Boolean as u64))
                    .and_then(|t| t.expect_primitive())
                    .and_then(ber_bool_to_bool)
                    .unwrap_or(false);

                Ok(LdapControl::SyncDone {
                    cookie,
                    refresh_deletes,
                })
            }
            "1.2.840.113556.1.4.841" => {
                let value_ber = value_tag
                    .and_then(|t| t.match_class(TagClass::Universal))
                    .and_then(|t| t.match_id(Types::OctetString as u64))
                    .and_then(|t| t.expect_primitive())
                    .ok_or(LdapProtoError::ControlBer)?;

                let mut parser = Parser::new();
                let (_rem, value) = parser
                    .parse(&value_ber)
                    .map_err(|_| LdapProtoError::ControlBer)?;

                let mut value = value
                    .expect_constructed()
                    .ok_or(LdapProtoError::ControlBer)?;

                value.reverse();

                let flags = value
                    .pop()
                    .and_then(|t| t.match_class(TagClass::Universal))
                    .and_then(|t| t.match_id(Types::Integer as u64))
                    .and_then(|t| t.expect_primitive())
                    .and_then(ber_integer_to_i64)
                    .ok_or(LdapProtoError::ControlAdDirsyncInteger)?;

                let max_bytes = value
                    .pop()
                    .and_then(|t| t.match_class(TagClass::Universal))
                    .and_then(|t| t.match_id(Types::Integer as u64))
                    .and_then(|t| t.expect_primitive())
                    .and_then(ber_integer_to_i64)
                    .ok_or(LdapProtoError::ControlAdDirsyncInteger)?;

                let cookie = value
                    .pop()
                    .and_then(|t| t.match_class(TagClass::Universal))
                    .and_then(|t| t.match_id(Types::OctetString as u64))
                    .and_then(|t| t.expect_primitive());

                Ok(LdapControl::AdDirsync {
                    flags,
                    max_bytes,
                    cookie,
                })
            }
            "1.2.840.113556.1.4.319" => {
                let value_ber = value_tag
                    .and_then(|t| t.match_class(TagClass::Universal))
                    .and_then(|t| t.match_id(Types::OctetString as u64))
                    .and_then(|t| t.expect_primitive())
                    .ok_or(LdapProtoError::ControlBer)?;

                let mut parser = Parser::new();
                let (_rem, value) = parser
                    .parse(&value_ber)
                    .map_err(|_| LdapProtoError::ControlBer)?;

                let mut value = value
                    .expect_constructed()
                    .ok_or(LdapProtoError::ControlBer)?;

                value.reverse();

                let size = value
                    .pop()
                    .and_then(|t| t.match_class(TagClass::Universal))
                    .and_then(|t| t.match_id(Types::Integer as u64))
                    .and_then(|t| t.expect_primitive())
                    .and_then(ber_integer_to_i64)
                    .ok_or(LdapProtoError::ControlPagedInteger)?;

                let cookie = value
                    .pop()
                    .and_then(|t| t.match_class(TagClass::Universal))
                    .and_then(|t| t.match_id(Types::OctetString as u64))
                    .and_then(|t| t.expect_primitive())
                    .ok_or(LdapProtoError::ControlPagedCookie)?;

                Ok(LdapControl::SimplePagedResults { size, cookie })
            }
            "2.16.840.1.113730.3.4.2" => {
                // ManageDsaIT per https://www.rfc-editor.org/rfc/rfc3296

                let criticality = criticality_tag
                    .and_then(|t| t.match_class(TagClass::Universal))
                    .and_then(|t| t.match_id(Types::Boolean as u64))
                    .and_then(|t| t.expect_primitive())
                    .and_then(ber_bool_to_bool)
                    .unwrap_or(false);

                // Has no content.

                Ok(LdapControl::ManageDsaIT { criticality })
            }
            oid => {
                warn!(%oid, "Unsupported control oid");
                Err(LdapProtoError::ControlUnknown)
            }
        }
    }
}

impl From<LdapControl> for Tag {
    fn from(value: LdapControl) -> Tag {
        let (oid, crit, inner_tag) = match value {
            LdapControl::SyncRequest {
                criticality,
                mode,
                cookie,
                reload_hint,
            } => {
                let inner: Vec<_> = vec![
                    Some(Tag::Enumerated(Enumerated {
                        inner: mode as i64,
                        ..Default::default()
                    })),
                    cookie.map(|c| {
                        Tag::OctetString(OctetString {
                            inner: c,
                            ..Default::default()
                        })
                    }),
                    if reload_hint {
                        Some(Tag::Boolean(Boolean {
                            inner: true,
                            ..Default::default()
                        }))
                    } else {
                        None
                    },
                ];

                (
                    "1.3.6.1.4.1.4203.1.9.1.1",
                    criticality,
                    Some(Tag::Sequence(Sequence {
                        inner: inner.into_iter().flatten().collect(),
                        ..Default::default()
                    })),
                )
            }
            LdapControl::SyncState {
                state,
                entry_uuid,
                cookie,
            } => {
                let inner: Vec<_> = vec![
                    Some(Tag::Enumerated(Enumerated {
                        inner: state as i64,
                        ..Default::default()
                    })),
                    Some(Tag::OctetString(OctetString {
                        inner: entry_uuid.as_bytes().to_vec(),
                        ..Default::default()
                    })),
                    cookie.map(|c| {
                        Tag::OctetString(OctetString {
                            inner: c,
                            ..Default::default()
                        })
                    }),
                ];

                (
                    "1.3.6.1.4.1.4203.1.9.1.2",
                    false,
                    Some(Tag::Sequence(Sequence {
                        inner: inner.into_iter().flatten().collect(),
                        ..Default::default()
                    })),
                )
            }
            LdapControl::SyncDone {
                cookie,
                refresh_deletes,
            } => {
                let inner: Vec<_> = vec![
                    cookie.map(|c| {
                        Tag::OctetString(OctetString {
                            inner: c,
                            ..Default::default()
                        })
                    }),
                    if refresh_deletes {
                        Some(Tag::Boolean(Boolean {
                            inner: true,
                            ..Default::default()
                        }))
                    } else {
                        None
                    },
                ];

                (
                    "1.3.6.1.4.1.4203.1.9.1.3",
                    false,
                    Some(Tag::Sequence(Sequence {
                        inner: inner.into_iter().flatten().collect(),
                        ..Default::default()
                    })),
                )
            }
            LdapControl::AdDirsync {
                flags,
                max_bytes,
                cookie,
            } => {
                let criticality = true;
                let inner: Vec<_> = vec![
                    Tag::Integer(Integer {
                        inner: flags,
                        ..Default::default()
                    }),
                    Tag::Integer(Integer {
                        inner: max_bytes,
                        ..Default::default()
                    }),
                    Tag::OctetString(OctetString {
                        inner: cookie.unwrap_or_default(),
                        ..Default::default()
                    }),
                ];

                (
                    "1.2.840.113556.1.4.841",
                    criticality,
                    Some(Tag::Sequence(Sequence {
                        inner,
                        ..Default::default()
                    })),
                )
            }
            LdapControl::SimplePagedResults { size, cookie } => {
                let inner: Vec<_> = vec![
                    Tag::Integer(Integer {
                        inner: size,
                        ..Default::default()
                    }),
                    Tag::OctetString(OctetString {
                        inner: cookie,
                        ..Default::default()
                    }),
                ];

                (
                    "1.2.840.113556.1.4.319",
                    false,
                    Some(Tag::Sequence(Sequence {
                        inner,
                        ..Default::default()
                    })),
                )
            }
            LdapControl::ManageDsaIT { criticality } => {
                ("2.16.840.1.113730.3.4.2", criticality, None)
            }
        };

        let mut inner = Vec::with_capacity(3);

        inner.push(Tag::OctetString(OctetString {
            inner: Vec::from(oid),
            ..Default::default()
        }));
        if crit {
            inner.push(Tag::Boolean(Boolean {
                inner: true,
                ..Default::default()
            }));
        }

        if let Some(inner_tag) = inner_tag {
            let mut bytes = BytesMut::new();
            lber_write::encode_into(&mut bytes, inner_tag.into_structure())
                .expect("Failed to encode inner structure, this is a bug!");
            inner.push(Tag::OctetString(OctetString {
                inner: bytes.to_vec(),
                ..Default::default()
            }));
        }

        Tag::Sequence(Sequence {
            inner,
            ..Default::default()
        })
    }
}

impl TryFrom<StructureTag> for LdapBindCred {
    type Error = LdapProtoError;

    fn try_from(value: StructureTag) -> Result<Self, Self::Error> {
        if value.class != TagClass::Context {
            return Err(LdapProtoError::BindCredBer);
        }

        match value.id {
            0 => value
                .expect_primitive()
                .and_then(|bv| String::from_utf8(bv).ok())
                .map(LdapBindCred::Simple)
                .ok_or(LdapProtoError::BindCredBer),
            _ => Err(LdapProtoError::BindCredId),
        }
    }
}

impl TryFrom<Vec<StructureTag>> for LdapBindRequest {
    type Error = LdapProtoError;

    fn try_from(mut value: Vec<StructureTag>) -> Result<Self, Self::Error> {
        // https://tools.ietf.org/html/rfc4511#section-4.2
        // BindRequest
        value.reverse();

        // Check the version is 3
        let v = value
            .pop()
            .and_then(|t| t.match_class(TagClass::Universal))
            .and_then(|t| t.match_id(Types::Integer as u64))
            .and_then(|t| t.expect_primitive())
            .and_then(ber_integer_to_i64)
            .ok_or(LdapProtoError::BindRequestVersion)?;
        if v != 3 {
            return Err(LdapProtoError::BindRequestVersion);
        };

        // Get the DN
        let dn = value
            .pop()
            .and_then(|t| t.match_class(TagClass::Universal))
            .and_then(|t| t.match_id(Types::OctetString as u64))
            .and_then(|t| t.expect_primitive())
            .and_then(|bv| String::from_utf8(bv).ok())
            .ok_or(LdapProtoError::BindRequestBer)?;

        // Andddd get the credential
        let cred = value
            .pop()
            .and_then(|v| LdapBindCred::try_from(v).ok())
            .ok_or(LdapProtoError::BindRequestBer)?;

        Ok(LdapBindRequest { dn, cred })
    }
}

impl From<LdapBindRequest> for Vec<Tag> {
    fn from(value: LdapBindRequest) -> Vec<Tag> {
        vec![
            Tag::Integer(Integer {
                inner: 3,
                ..Default::default()
            }),
            Tag::OctetString(OctetString {
                inner: Vec::from(value.dn),
                ..Default::default()
            }),
            value.cred.into(),
        ]
    }
}

impl LdapResult {
    fn into_tag_iter(self) -> impl Iterator<Item = Option<Tag>> {
        let LdapResult {
            code,
            matcheddn,
            message,
            referral,
        } = self;

        once_with(|| {
            Some(Tag::Enumerated(Enumerated {
                inner: code as i64,
                ..Default::default()
            }))
        })
        .chain(once_with(|| {
            Some(Tag::OctetString(OctetString {
                inner: Vec::from(matcheddn),
                ..Default::default()
            }))
        }))
        .chain(once_with(|| {
            Some(Tag::OctetString(OctetString {
                inner: Vec::from(message),
                ..Default::default()
            }))
        }))
        .chain(once_with(move || {
            if !referral.is_empty() {
                let inner = referral
                    .iter()
                    .map(|s| {
                        Tag::OctetString(OctetString {
                            inner: Vec::from(s.clone()),
                            ..Default::default()
                        })
                    })
                    .collect();
                // Remember to mark this as id 3, class::Context  (I think)
                Some(Tag::Sequence(Sequence {
                    class: TagClass::Context,
                    id: 3,
                    inner,
                }))
            } else {
                None
            }
        }))
    }
}

impl From<LdapResult> for Vec<Tag> {
    fn from(value: LdapResult) -> Vec<Tag> {
        // get all the values from the LdapResult
        value.into_tag_iter().flatten().collect()
    }
}

impl LdapResult {
    fn try_from_tag(
        mut value: Vec<StructureTag>,
    ) -> Result<(Self, Vec<StructureTag>), LdapProtoError> {
        // First, reverse all the elements so we are in the correct order.
        value.reverse();

        let code = value
            .pop()
            .and_then(|t| t.match_class(TagClass::Universal))
            .and_then(|t| t.match_id(Types::Enumerated as u64))
            .and_then(|t| t.expect_primitive())
            .and_then(ber_integer_to_i64)
            .ok_or(LdapProtoError::ResultBer)
            .and_then(LdapResultCode::try_from)?;

        let matcheddn = value
            .pop()
            .and_then(|t| t.match_class(TagClass::Universal))
            .and_then(|t| t.match_id(Types::OctetString as u64))
            .and_then(|t| t.expect_primitive())
            .and_then(|bv| String::from_utf8(bv).ok())
            .ok_or(LdapProtoError::ResultBer)?;

        let message = value
            .pop()
            .and_then(|t| t.match_class(TagClass::Universal))
            .and_then(|t| t.match_id(Types::OctetString as u64))
            .and_then(|t| t.expect_primitive())
            .and_then(|bv| String::from_utf8(bv).ok())
            .ok_or(LdapProtoError::ResultBer)?;

        let (_referrals, other): (Vec<_>, Vec<_>) = value.into_iter().partition(|v| v.id == 3);

        // assert referrals only is one
        let referral = Vec::new();

        Ok((
            LdapResult {
                code,
                matcheddn,
                message,
                referral,
            },
            other,
        ))
    }
}

impl LdapBindResponse {
    pub fn new_success(msg: &str) -> Self {
        LdapBindResponse {
            res: LdapResult {
                code: LdapResultCode::Success,
                matcheddn: "".to_string(),
                message: msg.to_string(),
                referral: Vec::new(),
            },
            saslcreds: None,
        }
    }

    pub fn new_invalidcredentials(dn: &str, msg: &str) -> Self {
        LdapBindResponse {
            res: LdapResult {
                code: LdapResultCode::InvalidCredentials,
                matcheddn: dn.to_string(),
                message: msg.to_string(),
                referral: Vec::new(),
            },
            saslcreds: None,
        }
    }
}

impl TryFrom<Vec<StructureTag>> for LdapBindResponse {
    type Error = LdapProtoError;

    fn try_from(value: Vec<StructureTag>) -> Result<Self, Self::Error> {
        trace!(?value);
        // This MUST be the first thing we do!
        let (res, tags) = LdapResult::try_from_tag(value)?;

        // Now with the remaining tags, as per rfc4511#section-4.2.2, we extract the optional sasl creds. Class Context, id 7. OctetString.
        let saslcreds = tags
            .get(0)
            .map(|tag| {
                debug!(?tag);
                let vec = tag
                    .clone()
                    .match_class(TagClass::Context)
                    .and_then(|t| t.match_id(7))
                    .and_then(|t| t.expect_primitive());

                vec.ok_or(LdapProtoError::BindCredBer)
            })
            .transpose()?;

        Ok(LdapBindResponse { res, saslcreds })
    }
}

impl From<LdapBindResponse> for Vec<Tag> {
    fn from(value: LdapBindResponse) -> Vec<Tag> {
        // get all the values from the LdapResult
        let LdapBindResponse { res, saslcreds } = value;
        res.into_tag_iter()
            .chain(once_with(|| {
                saslcreds.map(|sc| {
                    Tag::OctetString(OctetString {
                        inner: sc,
                        ..Default::default()
                    })
                })
            }))
            .flatten()
            .collect()
    }
}

impl TryFrom<StructureTag> for LdapFilter {
    type Error = LdapProtoError;

    fn try_from(value: StructureTag) -> Result<Self, Self::Error> {
        if value.class != TagClass::Context {
            error!("Invalid tagclass");
            return Err(LdapProtoError::FilterTag);
        };

        match value.id {
            0 => {
                let inner = value.expect_constructed().ok_or_else(|| {
                    trace!("invalid and filter");
                    LdapProtoError::FilterBer
                })?;
                let vf: Result<Vec<_>, _> = inner.into_iter().map(LdapFilter::try_from).collect();
                Ok(LdapFilter::And(vf?))
            }
            1 => {
                let inner = value.expect_constructed().ok_or_else(|| {
                    trace!("invalid or filter");
                    LdapProtoError::FilterBer
                })?;
                let vf: Result<Vec<_>, _> = inner.into_iter().map(LdapFilter::try_from).collect();
                Ok(LdapFilter::Or(vf?))
            }
            2 => {
                let inner = value
                    .expect_constructed()
                    .and_then(|mut i| i.pop())
                    .ok_or_else(|| {
                        trace!("invalid not filter");
                        LdapProtoError::FilterBer
                    })?;
                let inner_filt = LdapFilter::try_from(inner)?;
                Ok(LdapFilter::Not(Box::new(inner_filt)))
            }
            3 => {
                let mut inner = value.expect_constructed().ok_or_else(|| {
                    trace!("invalid eq filter");
                    LdapProtoError::FilterBer
                })?;
                inner.reverse();

                let a = inner
                    .pop()
                    .and_then(|t| t.match_class(TagClass::Universal))
                    .and_then(|t| t.match_id(Types::OctetString as u64))
                    .and_then(|t| t.expect_primitive())
                    .and_then(|bv| {
                        String::from_utf8(bv)
                            .map_err(|e| {
                                trace!(?e);
                            })
                            .ok()
                    })
                    .ok_or_else(|| {
                        trace!("invalid attribute in eq filter");
                        LdapProtoError::FilterBer
                    })?;

                let v = inner
                    .pop()
                    .and_then(|t| t.match_class(TagClass::Universal))
                    .and_then(|t| {
                        if cfg!(feature = "strict") {
                            t.match_id(Types::OctetString as u64)
                        } else {
                            Some(t)
                        }
                    })
                    .and_then(|t| t.expect_primitive())
                    .and_then(|bv| {
                        String::from_utf8(bv)
                            .map_err(|e| {
                                trace!(?e);
                            })
                            .ok()
                    })
                    .ok_or_else(|| {
                        trace!("invalid value in eq filter");
                        LdapProtoError::FilterBer
                    })?;

                Ok(LdapFilter::Equality(a, v))
            }
            4 => {
                let mut inner = value.expect_constructed().ok_or_else(|| {
                    trace!("invalid sub filter");
                    LdapProtoError::FilterBer
                })?;
                inner.reverse();

                let ty = inner
                    .pop()
                    .and_then(|t| t.match_class(TagClass::Universal))
                    .and_then(|t| t.match_id(Types::OctetString as u64))
                    .and_then(|t| t.expect_primitive())
                    .and_then(|bv| String::from_utf8(bv).ok())
                    .ok_or(LdapProtoError::FilterBer)?;

                let f = inner
                    .pop()
                    .and_then(|t| t.match_class(TagClass::Universal))
                    .and_then(|t| t.match_id(Types::Sequence as u64))
                    .and_then(|t| t.expect_constructed())
                    .and_then(|bv| {
                        let mut filter = LdapSubstringFilter::default();
                        for (
                            i,
                            StructureTag {
                                class: _,
                                id,
                                payload,
                            },
                        ) in bv.iter().enumerate()
                        {
                            match (id, payload) {
                                (0, PL::P(s)) => {
                                    if i == 0 {
                                        // If 'initial' is present, it SHALL
                                        // be the first element of 'substrings'.
                                        filter.initial = Some(String::from_utf8(s.clone()).ok()?);
                                    } else {
                                        return None;
                                    }
                                }
                                (1, PL::P(s)) => {
                                    filter.any.push(String::from_utf8(s.clone()).ok()?);
                                }
                                (2, PL::P(s)) => {
                                    if i == bv.len() - 1 {
                                        // If 'final' is present, it
                                        // SHALL be the last element of 'substrings'.
                                        filter.final_ = Some(String::from_utf8(s.clone()).ok()?);
                                    } else {
                                        return None;
                                    }
                                }
                                _ => return None,
                            }
                        }
                        Some(filter)
                    })
                    .ok_or(LdapProtoError::FilterBer)?;

                Ok(LdapFilter::Substring(ty, f))
            }
            5 => {
                let mut inner = value.expect_constructed().ok_or_else(|| {
                    trace!("invalid ge filter");
                    LdapProtoError::FilterBer
                })?;
                inner.reverse();

                let a = inner
                    .pop()
                    .and_then(|t| t.match_class(TagClass::Universal))
                    .and_then(|t| t.match_id(Types::OctetString as u64))
                    .and_then(|t| t.expect_primitive())
                    .and_then(|bv| {
                        String::from_utf8(bv)
                            .map_err(|e| {
                                trace!(?e);
                            })
                            .ok()
                    })
                    .ok_or_else(|| {
                        trace!("invalid attribute in ge filter");
                        LdapProtoError::FilterBer
                    })?;

                let v = inner
                    .pop()
                    .and_then(|t| t.match_class(TagClass::Universal))
                    .and_then(|t| {
                        if cfg!(feature = "strict") {
                            t.match_id(Types::OctetString as u64)
                        } else {
                            Some(t)
                        }
                    })
                    .and_then(|t| t.expect_primitive())
                    .and_then(|bv| {
                        String::from_utf8(bv)
                            .map_err(|e| {
                                trace!(?e);
                            })
                            .ok()
                    })
                    .ok_or_else(|| {
                        trace!("invalid value in ge filter");
                        LdapProtoError::FilterBer
                    })?;

                Ok(LdapFilter::GreaterOrEqual(a, v))
            }
            6 => {
                let mut inner = value.expect_constructed().ok_or_else(|| {
                    trace!("invalid le filter");
                    LdapProtoError::FilterBer
                })?;
                inner.reverse();

                let a = inner
                    .pop()
                    .and_then(|t| t.match_class(TagClass::Universal))
                    .and_then(|t| t.match_id(Types::OctetString as u64))
                    .and_then(|t| t.expect_primitive())
                    .and_then(|bv| {
                        String::from_utf8(bv)
                            .map_err(|e| {
                                trace!(?e);
                            })
                            .ok()
                    })
                    .ok_or_else(|| {
                        trace!("invalid attribute in le filter");
                        LdapProtoError::FilterBer
                    })?;

                let v = inner
                    .pop()
                    .and_then(|t| t.match_class(TagClass::Universal))
                    .and_then(|t| {
                        if cfg!(feature = "strict") {
                            t.match_id(Types::OctetString as u64)
                        } else {
                            Some(t)
                        }
                    })
                    .and_then(|t| t.expect_primitive())
                    .and_then(|bv| {
                        String::from_utf8(bv)
                            .map_err(|e| {
                                trace!(?e);
                            })
                            .ok()
                    })
                    .ok_or_else(|| {
                        trace!("invalid value in le filter");
                        LdapProtoError::FilterBer
                    })?;

                Ok(LdapFilter::LessOrEqual(a, v))
            }
            7 => {
                let a = value
                    .expect_primitive()
                    .and_then(|bv| String::from_utf8(bv).ok())
                    .ok_or_else(|| {
                        trace!("invalid pres filter");
                        LdapProtoError::FilterBer
                    })?;
                Ok(LdapFilter::Present(a))
            }
            8 => {
                let mut inner = value.expect_constructed().ok_or_else(|| {
                    trace!("invalid approx filter");
                    LdapProtoError::FilterBer
                })?;
                inner.reverse();

                let a = inner
                    .pop()
                    .and_then(|t| t.match_class(TagClass::Universal))
                    .and_then(|t| t.match_id(Types::OctetString as u64))
                    .and_then(|t| t.expect_primitive())
                    .and_then(|bv| {
                        String::from_utf8(bv)
                            .map_err(|e| {
                                trace!(?e);
                            })
                            .ok()
                    })
                    .ok_or_else(|| {
                        trace!("invalid attribute in approx filter");
                        LdapProtoError::FilterBer
                    })?;

                let v = inner
                    .pop()
                    .and_then(|t| t.match_class(TagClass::Universal))
                    .and_then(|t| {
                        if cfg!(feature = "strict") {
                            t.match_id(Types::OctetString as u64)
                        } else {
                            Some(t)
                        }
                    })
                    .and_then(|t| t.expect_primitive())
                    .and_then(|bv| {
                        String::from_utf8(bv)
                            .map_err(|e| {
                                trace!(?e);
                            })
                            .ok()
                    })
                    .ok_or_else(|| {
                        trace!("invalid value in approx filter");
                        LdapProtoError::FilterBer
                    })?;

                Ok(LdapFilter::Approx(a, v))
            }
            9 => {
                let inner = value.expect_constructed().ok_or_else(|| {
                    trace!("invalid extensible filter");
                    LdapProtoError::FilterBer
                })?;

                let mut filter = LdapMatchingRuleAssertion::default();

                for StructureTag { class, id, payload } in inner.into_iter().take(4) {
                    match (class, id, payload) {
                        (TagClass::Context, 1, PL::P(s)) => {
                            filter.matching_rule = Some(String::from_utf8(s).map_err(|e| {
                                trace!(?e);
                                LdapProtoError::FilterBer
                            })?)
                        }
                        (TagClass::Context, 2, PL::P(s)) => {
                            filter.type_ = Some(String::from_utf8(s).map_err(|e| {
                                trace!(?e);
                                LdapProtoError::FilterBer
                            })?)
                        }
                        (TagClass::Context, 3, PL::P(s)) => {
                            filter.match_value = String::from_utf8(s).map_err(|e| {
                                trace!(?e);
                                LdapProtoError::FilterBer
                            })?
                        }
                        (TagClass::Context, 4, PL::P(s)) => {
                            filter.dn_attributes = ber_bool_to_bool(s).unwrap_or(false);
                        }
                        _ => {
                            trace!("invalid extensible filter");
                            return Err(LdapProtoError::FilterBer);
                        }
                    }
                }

                Ok(LdapFilter::Extensible(filter))
            }
            _ => {
                trace!("invalid value tag");
                Err(LdapProtoError::FilterBer)
            }
        }
    }
}

impl From<LdapFilter> for Tag {
    fn from(value: LdapFilter) -> Tag {
        match value {
            LdapFilter::And(vf) => Tag::Set(Set {
                id: 0,
                class: TagClass::Context,
                inner: vf.into_iter().map(|v| v.into()).collect(),
            }),
            LdapFilter::Or(vf) => Tag::Set(Set {
                id: 1,
                class: TagClass::Context,
                inner: vf.into_iter().map(|v| v.into()).collect(),
            }),
            LdapFilter::Not(f) => Tag::ExplicitTag(ExplicitTag {
                id: 2,
                class: TagClass::Context,
                inner: Box::new((*f).into()),
            }),
            LdapFilter::Equality(a, v) => Tag::Sequence(Sequence {
                id: 3,
                class: TagClass::Context,
                inner: vec![
                    Tag::OctetString(OctetString {
                        inner: Vec::from(a),
                        ..Default::default()
                    }),
                    Tag::OctetString(OctetString {
                        inner: Vec::from(v),
                        ..Default::default()
                    }),
                ],
            }),
            LdapFilter::Substring(t, f) => Tag::Sequence(Sequence {
                id: 4,
                class: TagClass::Context,
                inner: vec![
                    Tag::OctetString(OctetString {
                        inner: Vec::from(t),
                        ..Default::default()
                    }),
                    Tag::Sequence(Sequence {
                        inner: {
                            let mut res = vec![];
                            if f.initial.is_some() {
                                res.push(Tag::OctetString(OctetString {
                                    id: 0,
                                    inner: f.initial.unwrap().as_bytes().to_vec(),
                                    class: TagClass::Context,
                                }))
                            }

                            f.any.iter().for_each(|v| {
                                res.push(Tag::OctetString(OctetString {
                                    id: 1,
                                    inner: v.as_bytes().to_vec(),
                                    class: TagClass::Context,
                                }))
                            });

                            if f.final_.is_some() {
                                res.push(Tag::OctetString(OctetString {
                                    id: 2,
                                    inner: f.final_.unwrap().as_bytes().to_vec(),
                                    class: TagClass::Context,
                                }))
                            }

                            res
                        },
                        ..Default::default()
                    }),
                ],
            }),
            LdapFilter::GreaterOrEqual(a, v) => Tag::Sequence(Sequence {
                id: 5,
                class: TagClass::Context,
                inner: vec![
                    Tag::OctetString(OctetString {
                        inner: Vec::from(a),
                        ..Default::default()
                    }),
                    Tag::OctetString(OctetString {
                        inner: Vec::from(v),
                        ..Default::default()
                    }),
                ],
            }),
            LdapFilter::LessOrEqual(a, v) => Tag::Sequence(Sequence {
                id: 6,
                class: TagClass::Context,
                inner: vec![
                    Tag::OctetString(OctetString {
                        inner: Vec::from(a),
                        ..Default::default()
                    }),
                    Tag::OctetString(OctetString {
                        inner: Vec::from(v),
                        ..Default::default()
                    }),
                ],
            }),
            LdapFilter::Present(a) => Tag::OctetString(OctetString {
                id: 7,
                class: TagClass::Context,
                inner: Vec::from(a),
            }),
            LdapFilter::Approx(a, v) => Tag::Sequence(Sequence {
                id: 8,
                class: TagClass::Context,
                inner: vec![
                    Tag::OctetString(OctetString {
                        inner: Vec::from(a),
                        ..Default::default()
                    }),
                    Tag::OctetString(OctetString {
                        inner: Vec::from(v),
                        ..Default::default()
                    }),
                ],
            }),
            LdapFilter::Extensible(f) => Tag::Sequence(Sequence {
                id: 9,
                class: TagClass::Context,
                inner: {
                    let mut res = vec![];
                    let LdapMatchingRuleAssertion {
                        matching_rule,
                        type_,
                        match_value,
                        dn_attributes,
                    } = f;

                    match matching_rule {
                        Some(v) => res.push(Tag::OctetString(OctetString {
                            inner: Vec::from(v),
                            id: 1,
                            class: TagClass::Context,
                        })),
                        None => {}
                    }

                    match type_ {
                        Some(v) => res.push(Tag::OctetString(OctetString {
                            inner: Vec::from(v),
                            id: 2,
                            class: TagClass::Context,
                        })),
                        None => {}
                    }

                    res.push(Tag::OctetString(OctetString {
                        inner: Vec::from(match_value),
                        id: 3,
                        class: TagClass::Context,
                    }));

                    res.push(Tag::Boolean(Boolean {
                        inner: dn_attributes,
                        id: 4,
                        class: TagClass::Context,
                    }));

                    res
                },
            }),
        }
    }
}

impl TryFrom<Vec<StructureTag>> for LdapSearchRequest {
    type Error = LdapProtoError;

    fn try_from(mut value: Vec<StructureTag>) -> Result<Self, Self::Error> {
        value.reverse();

        let base = value
            .pop()
            .and_then(|t| t.match_class(TagClass::Universal))
            .and_then(|t| t.match_id(Types::OctetString as u64))
            .and_then(|t| t.expect_primitive())
            .and_then(|bv| String::from_utf8(bv).ok())
            .ok_or_else(|| {
                trace!("invalid basedn");
                LdapProtoError::SearchBer
            })?;
        let scope = value
            .pop()
            .and_then(|t| t.match_class(TagClass::Universal))
            .and_then(|t|
                // Some non-complient clients will not tag this as enum.
                if cfg!(feature = "strict") {
                    t.match_id(Types::Enumerated as u64)
                } else {
                    Some(t)
                }
            )
            .and_then(|t| t.expect_primitive())
            .and_then(ber_integer_to_i64)
            .ok_or_else(|| {
                trace!("invalid scope");
                LdapProtoError::SearchBer
            })
            .and_then(LdapSearchScope::try_from)?;
        let aliases = value
            .pop()
            .and_then(|t| t.match_class(TagClass::Universal))
            .and_then(|t| t.match_id(Types::Enumerated as u64))
            .and_then(|t| t.expect_primitive())
            .and_then(ber_integer_to_i64)
            .ok_or_else(|| {
                trace!("invalid aliases");

                LdapProtoError::SearchBer
            })
            .and_then(LdapDerefAliases::try_from)?;
        let sizelimit = value
            .pop()
            .and_then(|t| t.match_class(TagClass::Universal))
            .and_then(|t| t.match_id(Types::Integer as u64))
            .and_then(|t| t.expect_primitive())
            .and_then(ber_integer_to_i64)
            .map(|v| v as i32)
            .ok_or_else(|| {
                trace!("invalid sizelimit");
                LdapProtoError::SearchBer
            })?;
        let timelimit = value
            .pop()
            .and_then(|t| t.match_class(TagClass::Universal))
            .and_then(|t| t.match_id(Types::Integer as u64))
            .and_then(|t| t.expect_primitive())
            .and_then(ber_integer_to_i64)
            .map(|v| v as i32)
            .ok_or_else(|| {
                trace!("invalid timelimit");
                LdapProtoError::SearchBer
            })?;
        let typesonly = value
            .pop()
            .and_then(|t| t.match_class(TagClass::Universal))
            .and_then(|t| t.match_id(Types::Boolean as u64))
            .and_then(|t| t.expect_primitive())
            .and_then(ber_bool_to_bool)
            .ok_or_else(|| {
                trace!("invalid typesonly");
                LdapProtoError::SearchBer
            })?;
        let filter = value
            .pop()
            .and_then(|t| LdapFilter::try_from(t).ok())
            .ok_or_else(|| {
                trace!("invalid filter");
                LdapProtoError::SearchBer
            })?;
        let attrs = value
            .pop()
            .map(|attrs| {
                trace!(?attrs);
                attrs
            })
            .and_then(|t| t.match_class(TagClass::Universal))
            .and_then(|t| {
                if cfg!(feature = "strict") {
                    t.match_id(Types::Sequence as u64)
                } else {
                    Some(t)
                }
            })
            .and_then(|t| {
                if cfg!(feature = "strict") {
                    t.expect_constructed()
                } else {
                    Some(Vec::new())
                }
            })
            .and_then(|vs| {
                let r: Option<Vec<_>> = vs
                    .into_iter()
                    .map(|bv| {
                        bv.match_class(TagClass::Universal)
                            .and_then(|t| t.match_id(Types::OctetString as u64))
                            .and_then(|t| t.expect_primitive())
                            .and_then(|bv| String::from_utf8(bv).ok())
                    })
                    .collect();
                r
            })
            .ok_or_else(|| {
                trace!("invalid attributes");

                LdapProtoError::SearchBer
            })?;

        Ok(LdapSearchRequest {
            base,
            scope,
            aliases,
            sizelimit,
            timelimit,
            typesonly,
            filter,
            attrs,
        })
    }
}

impl From<LdapSearchRequest> for Vec<Tag> {
    fn from(value: LdapSearchRequest) -> Vec<Tag> {
        let LdapSearchRequest {
            base,
            scope,
            aliases,
            sizelimit,
            timelimit,
            typesonly,
            filter,
            attrs,
        } = value;

        vec![
            Tag::OctetString(OctetString {
                inner: Vec::from(base),
                ..Default::default()
            }),
            Tag::Enumerated(Enumerated {
                inner: scope as i64,
                ..Default::default()
            }),
            Tag::Enumerated(Enumerated {
                inner: aliases as i64,
                ..Default::default()
            }),
            Tag::Integer(Integer {
                inner: sizelimit as i64,
                ..Default::default()
            }),
            Tag::Integer(Integer {
                inner: timelimit as i64,
                ..Default::default()
            }),
            Tag::Boolean(Boolean {
                inner: typesonly,
                ..Default::default()
            }),
            filter.into(),
            Tag::Sequence(Sequence {
                inner: attrs
                    .into_iter()
                    .map(|v| {
                        Tag::OctetString(OctetString {
                            inner: Vec::from(v),
                            ..Default::default()
                        })
                    })
                    .collect(),
                ..Default::default()
            }),
        ]
    }
}

impl TryFrom<StructureTag> for LdapModify {
    type Error = LdapProtoError;

    fn try_from(value: StructureTag) -> Result<Self, Self::Error> {
        // get the inner from the sequence
        let mut inner = value
            .match_class(TagClass::Universal)
            .and_then(|t| t.match_id(Types::Sequence as u64))
            .and_then(|t| t.expect_constructed())
            .ok_or(LdapProtoError::ModifyBer)?;

        inner.reverse();

        let operation = inner
            .pop()
            .and_then(|t| t.match_class(TagClass::Universal))
            .and_then(|t| t.match_id(Types::Enumerated as u64))
            .and_then(|t| t.expect_primitive())
            .and_then(ber_integer_to_i64)
            .ok_or(LdapProtoError::ModifyBer)
            .and_then(LdapModifyType::try_from)?;

        let modification = inner
            .pop()
            .and_then(|t| LdapPartialAttribute::try_from(t).ok())
            .ok_or(LdapProtoError::ModifyBer)?;

        Ok(Self {
            operation,
            modification,
        })
    }
}

impl TryFrom<StructureTag> for LdapPartialAttribute {
    type Error = LdapProtoError;

    fn try_from(value: StructureTag) -> Result<Self, Self::Error> {
        // get the inner from the sequence
        let mut inner = value
            .match_class(TagClass::Universal)
            .and_then(|t| t.match_id(Types::Sequence as u64))
            .and_then(|t| t.expect_constructed())
            .ok_or(LdapProtoError::PartialAttributeBer)?;

        inner.reverse();

        let atype = inner
            .pop()
            .and_then(|t| t.match_class(TagClass::Universal))
            .and_then(|t| t.match_id(Types::OctetString as u64))
            .and_then(|t| t.expect_primitive())
            .and_then(|bv| String::from_utf8(bv).ok())
            .ok_or(LdapProtoError::PartialAttributeBer)?;

        let vals = inner
            .pop()
            .and_then(|t| t.match_class(TagClass::Universal))
            .and_then(|t| t.match_id(Types::Set as u64))
            .and_then(|t| t.expect_constructed())
            .and_then(|bset| {
                let r: Option<Vec<_>> = bset
                    .into_iter()
                    .map(|bv| {
                        bv.match_class(TagClass::Universal)
                            .and_then(|t| t.match_id(Types::OctetString as u64))
                            .and_then(|t| t.expect_primitive())
                    })
                    .collect();
                r
            })
            .ok_or(LdapProtoError::PartialAttributeBer)?;

        Ok(LdapPartialAttribute { atype, vals })
    }
}

impl TryFrom<Vec<StructureTag>> for LdapSearchResultEntry {
    type Error = LdapProtoError;

    fn try_from(mut value: Vec<StructureTag>) -> Result<Self, Self::Error> {
        value.reverse();

        let dn = value
            .pop()
            .and_then(|t| t.match_class(TagClass::Universal))
            .and_then(|t| t.match_id(Types::OctetString as u64))
            .and_then(|t| t.expect_primitive())
            .and_then(|bv| String::from_utf8(bv).ok())
            .ok_or(LdapProtoError::SearchResultEntryBer)?;

        let attributes = value
            .pop()
            .and_then(|t| t.match_class(TagClass::Universal))
            .and_then(|t| t.match_id(Types::Sequence as u64))
            .and_then(|t| t.expect_constructed())
            .and_then(|bset| {
                let r: Result<Vec<_>, _> = bset
                    .into_iter()
                    .map(LdapPartialAttribute::try_from)
                    .collect();
                r.ok()
            })
            .ok_or(LdapProtoError::SearchResultEntryBer)?;

        Ok(LdapSearchResultEntry { dn, attributes })
    }
}

impl From<LdapPartialAttribute> for Tag {
    fn from(value: LdapPartialAttribute) -> Tag {
        let LdapPartialAttribute { atype, vals } = value;
        Tag::Sequence(Sequence {
            inner: vec![
                Tag::OctetString(OctetString {
                    inner: Vec::from(atype),
                    ..Default::default()
                }),
                Tag::Set(Set {
                    inner: vals
                        .into_iter()
                        .map(|v| {
                            Tag::OctetString(OctetString {
                                inner: v,
                                ..Default::default()
                            })
                        })
                        .collect(),
                    ..Default::default()
                }),
            ],
            ..Default::default()
        })
    }
}

impl From<LdapSearchResultEntry> for Vec<Tag> {
    fn from(value: LdapSearchResultEntry) -> Vec<Tag> {
        let LdapSearchResultEntry { dn, attributes } = value;
        vec![
            Tag::OctetString(OctetString {
                inner: Vec::from(dn),
                ..Default::default()
            }),
            Tag::Sequence(Sequence {
                inner: attributes.into_iter().map(|v| v.into()).collect(),
                ..Default::default()
            }),
        ]
    }
}

impl TryFrom<Vec<StructureTag>> for LdapExtendedRequest {
    type Error = LdapProtoError;

    fn try_from(mut value: Vec<StructureTag>) -> Result<Self, Self::Error> {
        // Put the values in order.
        value.reverse();
        // Read the values in
        let name = value
            .pop()
            .and_then(|t| t.match_class(TagClass::Context))
            .and_then(|t| t.match_id(0))
            .and_then(|t| t.expect_primitive())
            .and_then(|bv| String::from_utf8(bv).ok())
            .ok_or(LdapProtoError::ExtendedRequestBer)?;

        let value = value
            .pop()
            .and_then(|t| t.match_class(TagClass::Context))
            .and_then(|t| t.match_id(1))
            .and_then(|t| t.expect_primitive());

        Ok(LdapExtendedRequest { name, value })
    }
}

impl From<LdapExtendedRequest> for Vec<Tag> {
    fn from(value: LdapExtendedRequest) -> Vec<Tag> {
        let LdapExtendedRequest { name, value } = value;

        once_with(|| {
            Tag::OctetString(OctetString {
                id: 0,
                class: TagClass::Context,
                inner: Vec::from(name),
            })
        })
        .chain(
            once_with(|| {
                value.map(|v| {
                    Tag::OctetString(OctetString {
                        id: 1,
                        class: TagClass::Context,
                        inner: v,
                    })
                })
            })
            .flatten(),
        )
        .collect()
    }
}

impl TryFrom<Vec<StructureTag>> for LdapExtendedResponse {
    type Error = LdapProtoError;

    fn try_from(value: Vec<StructureTag>) -> Result<Self, Self::Error> {
        // This MUST be the first thing we do!
        let (res, remtag) = LdapResult::try_from_tag(value)?;
        // Now from the remaining tags, get the items.
        let mut name = None;
        let mut value = None;
        remtag.into_iter().for_each(|v| {
            match (v.id, v.class) {
                (10, TagClass::Context) => {
                    name = v
                        .expect_primitive()
                        .and_then(|bv| String::from_utf8(bv).ok())
                }
                (11, TagClass::Context) => value = v.expect_primitive(),
                _ => {
                    // Do nothing
                }
            }
        });

        Ok(LdapExtendedResponse { res, name, value })
    }
}

impl From<LdapExtendedResponse> for Vec<Tag> {
    fn from(value: LdapExtendedResponse) -> Vec<Tag> {
        let LdapExtendedResponse { res, name, value } = value;
        res.into_tag_iter()
            .chain(once_with(|| {
                name.map(|v| {
                    Tag::OctetString(OctetString {
                        id: 10,
                        class: TagClass::Context,
                        inner: Vec::from(v),
                    })
                })
            }))
            .chain(once_with(|| {
                value.map(|v| {
                    Tag::OctetString(OctetString {
                        id: 11,
                        class: TagClass::Context,
                        inner: v,
                    })
                })
            }))
            .flatten()
            .collect()
    }
}

impl LdapExtendedResponse {
    pub fn new_success(name: Option<&str>, value: Option<&str>) -> Self {
        LdapExtendedResponse {
            res: LdapResult {
                code: LdapResultCode::Success,
                matcheddn: "".to_string(),
                message: "".to_string(),
                referral: Vec::new(),
            },
            name: name.map(|v| v.to_string()),
            value: value.map(Vec::from),
        }
    }

    pub fn new_operationserror(msg: &str) -> Self {
        LdapExtendedResponse {
            res: LdapResult {
                code: LdapResultCode::OperationsError,
                matcheddn: "".to_string(),
                message: msg.to_string(),
                referral: Vec::new(),
            },
            name: None,
            value: None,
        }
    }
}

impl TryFrom<Vec<StructureTag>> for LdapIntermediateResponse {
    type Error = LdapProtoError;

    fn try_from(tags: Vec<StructureTag>) -> Result<Self, Self::Error> {
        let mut name = None;
        let mut value = None;
        tags.into_iter().for_each(|v| {
            match (v.id, v.class) {
                (0, TagClass::Context) => {
                    name = v
                        .expect_primitive()
                        .and_then(|bv| String::from_utf8(bv).ok())
                }
                (1, TagClass::Context) => value = v.expect_primitive(),
                _ => {
                    // Do nothing
                }
            }
        });

        // Ok! Now can we match this?

        match (name.as_deref(), value.as_ref()) {
            (Some("1.3.6.1.4.1.4203.1.9.1.4"), Some(buf)) => {
                // It's a sync info done. Start to process the value.
                let mut parser = Parser::new();
                let (_rem, msg) = parser
                    .parse(buf)
                    .map_err(|_| LdapProtoError::IntermediateResponseBer)?;

                if msg.class != TagClass::Context {
                    error!("Invalid tagclass");
                    return Err(LdapProtoError::IntermediateResponseTag);
                };

                let id = msg.id;
                let mut inner = msg.expect_constructed().ok_or_else(|| {
                    trace!("invalid or filter");
                    LdapProtoError::IntermediateResponseBer
                })?;

                match id {
                    0 => {
                        let cookie =
                            inner
                                .pop()
                                .and_then(|t| t.expect_primitive())
                                .ok_or_else(|| {
                                    trace!("invalid cookie");
                                    LdapProtoError::IntermediateResponseBer
                                })?;
                        Ok(LdapIntermediateResponse::SyncInfoNewCookie { cookie })
                    }
                    1 => {
                        // Whom ever wrote this rfc has a lot to answer for ...
                        let mut done = true;
                        let mut cookie = None;

                        for t in inner
                            .into_iter()
                            .filter_map(|t| t.match_class(TagClass::Universal))
                        {
                            if t.id == Types::Boolean as u64 {
                                done = t
                                    .expect_primitive()
                                    .and_then(ber_bool_to_bool)
                                    .ok_or(LdapProtoError::IntermediateResponseBer)?;
                            } else if t.id == Types::OctetString as u64 {
                                cookie = t.expect_primitive();
                            } else {
                                // skipped
                            }
                        }

                        Ok(LdapIntermediateResponse::SyncInfoRefreshDelete { cookie, done })
                    }
                    2 => {
                        let done = inner
                            .pop()
                            .and_then(|t| t.match_class(TagClass::Universal))
                            .and_then(|t| t.match_id(Types::Boolean as u64))
                            .and_then(|t| t.expect_primitive())
                            .and_then(ber_bool_to_bool)
                            .unwrap_or(true);

                        let cookie = inner.pop().and_then(|t| t.expect_primitive());

                        Ok(LdapIntermediateResponse::SyncInfoRefreshPresent { cookie, done })
                    }
                    3 => {
                        let syncuuids = inner
                            .pop()
                            .and_then(|t| t.match_class(TagClass::Universal))
                            .and_then(|t| t.match_id(Types::Set as u64))
                            .and_then(|t| t.expect_constructed())
                            .ok_or(LdapProtoError::IntermediateResponseBer)
                            .and_then(|bset| {
                                let r: Result<Vec<_>, _> = bset
                                    .into_iter()
                                    .map(|bv| {
                                        bv.match_class(TagClass::Universal)
                                            .and_then(|t| t.match_id(Types::OctetString as u64))
                                            .and_then(|t| t.expect_primitive())
                                            .ok_or(LdapProtoError::IntermediateResponseBer)
                                            .and_then(|v| {
                                                Uuid::from_slice(&v).map_err(|_| {
                                                    error!("Invalid syncUUID");
                                                    LdapProtoError::IntermediateResponseSyncUuid
                                                })
                                            })
                                    })
                                    .collect();
                                r
                            })?;

                        let refresh_deletes = inner
                            .pop()
                            .and_then(|t| t.match_class(TagClass::Universal))
                            .and_then(|t| t.match_id(Types::Boolean as u64))
                            .and_then(|t| t.expect_primitive())
                            .and_then(ber_bool_to_bool)
                            .unwrap_or(false);

                        let cookie = inner.pop().and_then(|t| t.expect_primitive());

                        Ok(LdapIntermediateResponse::SyncInfoIdSet {
                            cookie,
                            refresh_deletes,
                            syncuuids,
                        })
                    }
                    _ => {
                        trace!("invalid value id");
                        Err(LdapProtoError::IntermediateResponseId)
                    }
                }
            }
            _ => Ok(LdapIntermediateResponse::Raw { name, value }),
        }
    }
}

impl From<LdapIntermediateResponse> for Vec<Tag> {
    fn from(value: LdapIntermediateResponse) -> Vec<Tag> {
        let (name, value) = match value {
            LdapIntermediateResponse::SyncInfoNewCookie { cookie } => {
                let inner = vec![Tag::OctetString(OctetString {
                    inner: cookie,
                    ..Default::default()
                })];

                let inner_tag = Tag::Sequence(Sequence {
                    class: TagClass::Context,
                    id: 0,
                    inner,
                });

                let mut bytes = BytesMut::new();
                lber_write::encode_into(&mut bytes, inner_tag.into_structure())
                    .expect("Failed to encode inner structure, this is a bug!");
                (
                    Some("1.3.6.1.4.1.4203.1.9.1.4".to_string()),
                    Some(bytes.to_vec()),
                )
            }
            LdapIntermediateResponse::SyncInfoRefreshDelete { cookie, done } => {
                let inner = once_with(|| {
                    cookie.map(|c| {
                        Tag::OctetString(OctetString {
                            inner: c,
                            ..Default::default()
                        })
                    })
                })
                .chain(once_with(|| {
                    if !done {
                        Some(Tag::Boolean(Boolean {
                            inner: false,
                            ..Default::default()
                        }))
                    } else {
                        None
                    }
                }))
                .flatten()
                .collect();

                let inner_tag = Tag::Sequence(Sequence {
                    class: TagClass::Context,
                    id: 1,
                    inner,
                });

                let mut bytes = BytesMut::new();
                lber_write::encode_into(&mut bytes, inner_tag.into_structure())
                    .expect("Failed to encode inner structure, this is a bug!");
                (
                    Some("1.3.6.1.4.1.4203.1.9.1.4".to_string()),
                    Some(bytes.to_vec()),
                )
            }
            LdapIntermediateResponse::SyncInfoRefreshPresent { cookie, done } => {
                let inner = once_with(|| {
                    cookie.map(|c| {
                        Tag::OctetString(OctetString {
                            inner: c,
                            ..Default::default()
                        })
                    })
                })
                .chain(once_with(|| {
                    if !done {
                        Some(Tag::Boolean(Boolean {
                            inner: false,
                            ..Default::default()
                        }))
                    } else {
                        None
                    }
                }))
                .flatten()
                .collect();

                let inner_tag = Tag::Sequence(Sequence {
                    class: TagClass::Context,
                    id: 2,
                    inner,
                });

                let mut bytes = BytesMut::new();
                lber_write::encode_into(&mut bytes, inner_tag.into_structure())
                    .expect("Failed to encode inner structure, this is a bug!");
                (
                    Some("1.3.6.1.4.1.4203.1.9.1.4".to_string()),
                    Some(bytes.to_vec()),
                )
            }
            LdapIntermediateResponse::SyncInfoIdSet {
                cookie,
                refresh_deletes,
                syncuuids,
            } => {
                let inner = once_with(|| {
                    cookie.map(|c| {
                        Tag::OctetString(OctetString {
                            inner: c,
                            ..Default::default()
                        })
                    })
                })
                .chain(once_with(|| {
                    if refresh_deletes {
                        Some(Tag::Boolean(Boolean {
                            inner: true,
                            ..Default::default()
                        }))
                    } else {
                        None
                    }
                }))
                .chain(once_with(|| {
                    Some(Tag::Set(Set {
                        inner: syncuuids
                            .into_iter()
                            .map(|entry_uuid| {
                                Tag::OctetString(OctetString {
                                    inner: entry_uuid.as_bytes().to_vec(),
                                    ..Default::default()
                                })
                            })
                            .collect(),
                        ..Default::default()
                    }))
                }))
                .flatten()
                .collect();

                let inner_tag = Tag::Sequence(Sequence {
                    class: TagClass::Context,
                    id: 3,
                    inner,
                });

                let mut bytes = BytesMut::new();
                lber_write::encode_into(&mut bytes, inner_tag.into_structure())
                    .expect("Failed to encode inner structure, this is a bug!");
                (
                    Some("1.3.6.1.4.1.4203.1.9.1.4".to_string()),
                    Some(bytes.to_vec()),
                )
            }
            LdapIntermediateResponse::Raw { name, value } => (name, value),
        };

        once_with(|| {
            name.map(|v| {
                Tag::OctetString(OctetString {
                    id: 0,
                    class: TagClass::Context,
                    inner: Vec::from(v),
                })
            })
        })
        .chain(once_with(|| {
            value.map(|v| {
                Tag::OctetString(OctetString {
                    id: 1,
                    class: TagClass::Context,
                    inner: v,
                })
            })
        }))
        .flatten()
        .collect()
    }
}

impl TryFrom<i64> for LdapModifyType {
    type Error = LdapProtoError;

    fn try_from(value: i64) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(LdapModifyType::Add),
            1 => Ok(LdapModifyType::Delete),
            2 => Ok(LdapModifyType::Replace),
            _ => Err(LdapProtoError::ModifyTypeValue),
        }
    }
}

impl TryFrom<i64> for LdapSearchScope {
    type Error = LdapProtoError;

    fn try_from(value: i64) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(LdapSearchScope::Base),
            1 => Ok(LdapSearchScope::OneLevel),
            2 => Ok(LdapSearchScope::Subtree),
            3 => Ok(LdapSearchScope::Children),
            _ => Err(LdapProtoError::SearchScopeValue),
        }
    }
}

impl TryFrom<i64> for LdapDerefAliases {
    type Error = LdapProtoError;

    fn try_from(value: i64) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(LdapDerefAliases::Never),
            1 => Ok(LdapDerefAliases::InSearching),
            2 => Ok(LdapDerefAliases::FindingBaseObj),
            3 => Ok(LdapDerefAliases::Always),
            _ => Err(LdapProtoError::DerefAliasesValue),
        }
    }
}

impl TryFrom<Vec<StructureTag>> for LdapModifyRequest {
    type Error = LdapProtoError;

    fn try_from(mut value: Vec<StructureTag>) -> Result<Self, Self::Error> {
        value.reverse();

        let dn = value
            .pop()
            .and_then(|t| t.match_class(TagClass::Universal))
            .and_then(|t| t.match_id(Types::OctetString as u64))
            .and_then(|t| t.expect_primitive())
            .and_then(|bv| String::from_utf8(bv).ok())
            .ok_or(LdapProtoError::ModifyRequestBer)?;

        let changes = value
            .pop()
            .and_then(|t| t.match_class(TagClass::Universal))
            .and_then(|t| t.match_id(Types::Sequence as u64))
            .and_then(|t| t.expect_constructed())
            .ok_or(LdapProtoError::ModifyRequestBer)
            .and_then(|bset| {
                bset.into_iter()
                    .map(LdapModify::try_from)
                    .collect::<Result<Vec<_>, _>>()
            })?;

        Ok(Self { dn, changes })
    }
}

impl TryFrom<Vec<StructureTag>> for LdapAddRequest {
    type Error = LdapProtoError;

    fn try_from(mut value: Vec<StructureTag>) -> Result<Self, Self::Error> {
        value.reverse();

        let dn = value
            .pop()
            .and_then(|t| t.match_class(TagClass::Universal))
            .and_then(|t| t.match_id(Types::OctetString as u64))
            .and_then(|t| t.expect_primitive())
            .and_then(|bv| String::from_utf8(bv).ok())
            .ok_or(LdapProtoError::AddRequestBer)?;

        let attributes = value
            .pop()
            .and_then(|t| t.match_class(TagClass::Universal))
            .and_then(|t| t.match_id(Types::Sequence as u64))
            .and_then(|t| t.expect_constructed())
            .ok_or(LdapProtoError::AddRequestBer)
            .and_then(|bset| {
                bset.into_iter()
                    .map(LdapAttribute::try_from)
                    .collect::<Result<Vec<_>, _>>()
            })?;

        Ok(LdapAddRequest { dn, attributes })
    }
}

impl TryFrom<Vec<StructureTag>> for LdapModifyDNRequest {
    type Error = LdapProtoError;

    fn try_from(mut value: Vec<StructureTag>) -> Result<Self, Self::Error> {
        value.reverse();

        let dn = value
            .pop()
            .and_then(|t| t.match_class(TagClass::Universal))
            .and_then(|t| t.match_id(Types::OctetString as u64))
            .and_then(|t| t.expect_primitive())
            .and_then(|bv| String::from_utf8(bv).ok())
            .ok_or(LdapProtoError::ModifyDNRequestBer)?;

        let newrdn = value
            .pop()
            .and_then(|t| t.match_class(TagClass::Universal))
            .and_then(|t| t.match_id(Types::OctetString as u64))
            .and_then(|t| t.expect_primitive())
            .and_then(|bv| String::from_utf8(bv).ok())
            .ok_or(LdapProtoError::ModifyDNRequestBer)?;

        let deleteoldrdn = value
            .pop()
            .and_then(|t| t.match_class(TagClass::Universal))
            .and_then(|t| t.match_id(Types::Boolean as u64))
            .and_then(|t| t.expect_primitive())
            .and_then(ber_bool_to_bool)
            .ok_or(LdapProtoError::ModifyDNRequestBer)?;

        let new_superior = value
            .pop()
            .and_then(|t| t.match_class(TagClass::Context))
            .and_then(|t| t.match_id(0))
            .and_then(|t| t.expect_primitive())
            .and_then(|bv| String::from_utf8(bv).ok());

        Ok(Self {
            dn,
            newrdn,
            deleteoldrdn,
            new_superior,
        })
    }
}

impl TryFrom<Vec<StructureTag>> for LdapCompareRequest {
    type Error = LdapProtoError;

    fn try_from(mut value: Vec<StructureTag>) -> Result<Self, Self::Error> {
        value.reverse();

        let dn = value
            .pop()
            .and_then(|t| t.match_class(TagClass::Universal))
            .and_then(|t| t.match_id(Types::OctetString as u64))
            .and_then(|t| t.expect_primitive())
            .and_then(|bv| String::from_utf8(bv).ok())
            .ok_or(LdapProtoError::CompareRequestBer)?;

        let mut ava = value
            .pop()
            .and_then(|t| t.match_class(TagClass::Universal))
            .and_then(|t| t.match_id(Types::Sequence as u64))
            .and_then(|t| t.expect_constructed())
            .ok_or(LdapProtoError::CompareRequestBer)?;

        let val = ava
            .pop()
            .and_then(|t| t.match_class(TagClass::Universal))
            .and_then(|t| t.match_id(Types::OctetString as u64))
            .and_then(|t| t.expect_primitive())
            .ok_or(LdapProtoError::CompareRequestBer)?;

        let atype = ava
            .pop()
            .and_then(|t| t.match_class(TagClass::Universal))
            .and_then(|t| t.match_id(Types::OctetString as u64))
            .and_then(|t| t.expect_primitive())
            .and_then(|bv| String::from_utf8(bv).ok())
            .ok_or(LdapProtoError::CompareRequestBer)?;

        Ok(Self { dn, atype, val })
    }
}

impl From<LdapCompareRequest> for Vec<Tag> {
    fn from(value: LdapCompareRequest) -> Vec<Tag> {
        let LdapCompareRequest { dn, atype, val } = value;
        vec![
            Tag::OctetString(OctetString {
                inner: Vec::from(dn),
                ..Default::default()
            }),
            Tag::Sequence(Sequence {
                inner: vec![
                    Tag::OctetString(OctetString {
                        inner: Vec::from(atype),
                        ..Default::default()
                    }),
                    Tag::OctetString(OctetString {
                        inner: val,
                        ..Default::default()
                    }),
                ],
                ..Default::default()
            }),
        ]
    }
}

impl From<LdapModify> for Tag {
    fn from(value: LdapModify) -> Tag {
        let LdapModify {
            operation,
            modification,
        } = value;
        let inner = vec![
            Tag::Enumerated(Enumerated {
                inner: operation as i64,
                ..Default::default()
            }),
            modification.into(),
        ];

        Tag::Sequence(Sequence {
            inner,
            ..Default::default()
        })
    }
}

impl From<LdapModifyRequest> for Vec<Tag> {
    fn from(value: LdapModifyRequest) -> Vec<Tag> {
        let LdapModifyRequest { dn, changes } = value;
        vec![
            Tag::OctetString(OctetString {
                inner: Vec::from(dn),
                ..Default::default()
            }),
            Tag::Sequence(Sequence {
                inner: changes.into_iter().map(|v| v.into()).collect(),
                ..Default::default()
            }),
        ]
    }
}

impl From<LdapAddRequest> for Vec<Tag> {
    fn from(value: LdapAddRequest) -> Vec<Tag> {
        let LdapAddRequest { dn, attributes } = value;
        vec![
            Tag::OctetString(OctetString {
                inner: Vec::from(dn),
                ..Default::default()
            }),
            Tag::Sequence(Sequence {
                inner: attributes.into_iter().map(|v| v.into()).collect(),
                ..Default::default()
            }),
        ]
    }
}

impl From<LdapSearchResultReference> for Vec<Tag> {
    fn from(value: LdapSearchResultReference) -> Self {
        let LdapSearchResultReference { uris } = value;

        // Create a vector to hold the sequence of URI tags
        let uri_tags: Vec<Tag> = uris
            .into_iter()
            .map(|uri| {
                Tag::OctetString(OctetString {
                    inner: Vec::from(uri),
                    ..Default::default()
                })
            })
            .collect();

        uri_tags
    }
}

impl From<LdapModifyDNRequest> for Vec<Tag> {
    fn from(value: LdapModifyDNRequest) -> Vec<Tag> {
        let LdapModifyDNRequest {
            dn,
            newrdn,
            deleteoldrdn,
            new_superior,
        } = value;

        let mut v = Vec::with_capacity(4);

        v.push(Tag::OctetString(OctetString {
            inner: Vec::from(dn),
            ..Default::default()
        }));
        v.push(Tag::OctetString(OctetString {
            inner: Vec::from(newrdn),
            ..Default::default()
        }));
        v.push(Tag::Boolean(Boolean {
            inner: deleteoldrdn,
            ..Default::default()
        }));

        if let Some(ns) = new_superior {
            v.push(Tag::OctetString(OctetString {
                id: 0,
                class: TagClass::Context,
                inner: Vec::from(ns),
            }))
        }
        v
    }
}

impl TryFrom<i64> for LdapResultCode {
    type Error = LdapProtoError;

    fn try_from(value: i64) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(LdapResultCode::Success),
            1 => Ok(LdapResultCode::OperationsError),
            2 => Ok(LdapResultCode::ProtocolError),
            3 => Ok(LdapResultCode::TimeLimitExceeded),
            4 => Ok(LdapResultCode::SizeLimitExceeded),
            5 => Ok(LdapResultCode::CompareFalse),
            6 => Ok(LdapResultCode::CompareTrue),
            7 => Ok(LdapResultCode::AuthMethodNotSupported),
            8 => Ok(LdapResultCode::StrongerAuthRequired),
            10 => Ok(LdapResultCode::Referral),
            11 => Ok(LdapResultCode::AdminLimitExceeded),
            12 => Ok(LdapResultCode::UnavailableCriticalExtension),
            13 => Ok(LdapResultCode::ConfidentialityRequired),
            14 => Ok(LdapResultCode::SaslBindInProgress),
            16 => Ok(LdapResultCode::NoSuchAttribute),
            17 => Ok(LdapResultCode::UndefinedAttributeType),
            18 => Ok(LdapResultCode::InappropriateMatching),
            19 => Ok(LdapResultCode::ConstraintViolation),
            20 => Ok(LdapResultCode::AttributeOrValueExists),
            21 => Ok(LdapResultCode::InvalidAttributeSyntax),
            32 => Ok(LdapResultCode::NoSuchObject),
            33 => Ok(LdapResultCode::AliasProblem),
            34 => Ok(LdapResultCode::InvalidDNSyntax),
            36 => Ok(LdapResultCode::AliasDereferencingProblem),
            48 => Ok(LdapResultCode::InappropriateAuthentication),
            49 => Ok(LdapResultCode::InvalidCredentials),
            50 => Ok(LdapResultCode::InsufficentAccessRights),
            51 => Ok(LdapResultCode::Busy),
            52 => Ok(LdapResultCode::Unavailable),
            53 => Ok(LdapResultCode::UnwillingToPerform),
            54 => Ok(LdapResultCode::LoopDetect),
            64 => Ok(LdapResultCode::NamingViolation),
            65 => Ok(LdapResultCode::ObjectClassViolation),
            66 => Ok(LdapResultCode::NotAllowedOnNonLeaf),
            67 => Ok(LdapResultCode::NotALlowedOnRDN),
            68 => Ok(LdapResultCode::EntryAlreadyExists),
            69 => Ok(LdapResultCode::ObjectClassModsProhibited),
            71 => Ok(LdapResultCode::AffectsMultipleDSAs),
            80 => Ok(LdapResultCode::Other),
            4096 => Ok(LdapResultCode::EsyncRefreshRequired),
            i => {
                error!("Unknown i64 ecode {}", i);
                Err(LdapProtoError::ResultCode)
            }
        }
    }
}

fn ber_bool_to_bool<V: AsRef<[u8]>>(bv: V) -> Option<bool> {
    bv.as_ref().first().map(|v| !matches!(v, 0))
}

fn ber_integer_to_i64<V: AsRef<[u8]>>(v: V) -> Option<i64> {
    let bv = v.as_ref();
    // ints in ber are be and may be truncated.
    let mut raw: [u8; 8] = [0; 8];
    // This is where we need to start inserting bytes.
    let base = if bv.len() > 8 {
        return None;
    } else {
        8 - bv.len()
    };
    raw[base..(bv.len() + base)].clone_from_slice(bv);
    Some(i64::from_be_bytes(raw))
}

#[derive(Debug, PartialEq, PartialOrd, Clone)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub struct LdapSearchResultReference {
    pub uris: Vec<String>,
}

impl TryFrom<Vec<StructureTag>> for LdapSearchResultReference {
    type Error = LdapProtoError;

    fn try_from(value: Vec<StructureTag>) -> Result<Self, Self::Error> {
        let mut uris = Vec::new();

        // Iterate over the StructureTags
        for tag in value {
            if let Some(bytes) = tag.expect_primitive() {
                let uri = String::from_utf8(bytes).map_err(|_| LdapProtoError::LdapMsgBer)?;
                uris.push(uri);
            } else {
                Err(LdapProtoError::LdapMsgBer)?;
            }
        }

        Ok(LdapSearchResultReference { uris })
    }
}

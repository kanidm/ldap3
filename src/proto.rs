use lber::common::TagClass;
use lber::structure::{StructureTag, PL};
use lber::structures::ASNTag;
use lber::structures::{
    Boolean, Enumerated, ExplicitTag, Integer, Null, OctetString, Sequence, Set, Tag,
};
use lber::universal::Types;
use std::convert::{From, TryFrom};
use std::iter::once_with;

#[derive(Debug, Clone, PartialEq)]
pub struct LdapMsg {
    pub msgid: i32,
    pub op: LdapOp,
    pub ctrl: Vec<()>,
}

#[derive(Debug, Clone, PartialEq)]
#[repr(i64)]
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
}

#[derive(Debug, Clone, PartialEq)]
pub struct LdapResult {
    pub code: LdapResultCode,
    pub matcheddn: String,
    pub message: String,
    pub referral: Vec<()>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum LdapOp {
    BindRequest(LdapBindRequest),
    BindResponse(LdapBindResponse),
    UnbindRequest,
    // https://tools.ietf.org/html/rfc4511#section-4.5
    SearchRequest(LdapSearchRequest),
    SearchResultEntry(LdapSearchResultEntry),
    SearchResultDone(LdapResult),
    // https://tools.ietf.org/html/rfc4511#section-4.7
    AddRequest(LdapAddRequest),
    AddResponse(LdapResult),
    // https://tools.ietf.org/html/rfc4511#section-4.8
    DelRequest(String),
    DelResponse(LdapResult),
    // https://tools.ietf.org/html/rfc4511#section-4.11
    AbandonRequest(i32),
    // https://tools.ietf.org/html/rfc4511#section-4.12
    ExtendedRequest(LdapExtendedRequest),
    ExtendedResponse(LdapExtendedResponse),
}

#[derive(Debug, Clone, PartialEq)]
pub enum LdapBindCred {
    Simple(String), // Sasl
}

#[derive(Debug, Clone, PartialEq)]
pub struct LdapBindRequest {
    pub dn: String,
    pub cred: LdapBindCred,
}

#[derive(Debug, Clone, PartialEq)]
pub struct LdapBindResponse {
    pub res: LdapResult,
    pub saslcreds: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
#[repr(i64)]
pub enum LdapSearchScope {
    Base = 0,
    OneLevel = 1,
    Subtree = 2,
}

#[derive(Debug, Clone, PartialEq)]
#[repr(i64)]
pub enum LdapDerefAliases {
    Never = 0,
    InSearching = 1,
    FindingBaseObj = 2,
    Always = 3,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct LdapSubstringFilter {
    pub initial: Option<String>,
    pub any: Vec<String>,
    pub final_: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum LdapFilter {
    And(Vec<LdapFilter>),
    Or(Vec<LdapFilter>),
    Not(Box<LdapFilter>),
    Equality(String, String),
    Substring(String, LdapSubstringFilter),
    //GE
    //LE
    Present(String),
    //Approx
    //Extensible
}

#[derive(Debug, Clone, PartialEq)]
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
#[derive(Debug, Clone, PartialEq)]
pub struct LdapPartialAttribute {
    pub atype: String,
    pub vals: Vec<String>,
}

// A PartialAttribute allows zero values, while
// Attribute requires at least one value.
type LdapAttribute = LdapPartialAttribute;

#[derive(Debug, Clone, PartialEq)]
pub struct LdapSearchResultEntry {
    pub dn: String,
    pub attributes: Vec<LdapPartialAttribute>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct LdapAddRequest {
    pub dn: String,
    pub attributes: Vec<LdapAttribute>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct LdapExtendedRequest {
    // 0
    pub name: String,
    // 1
    pub value: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct LdapExtendedResponse {
    pub res: LdapResult,
    // 10
    pub name: Option<String>,
    // 11
    pub value: Option<Vec<u8>>,
}

impl From<LdapBindCred> for Tag {
    fn from(value: LdapBindCred) -> Tag {
        match value {
            LdapBindCred::Simple(pw) => Tag::OctetString(OctetString {
                id: 0,
                class: TagClass::Context,
                inner: Vec::from(pw),
            }),
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
}

impl TryFrom<StructureTag> for LdapMsg {
    type Error = ();

    /// https://tools.ietf.org/html/rfc4511#section-4.1.1
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
            .ok_or(())?;

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
            _ => return Err(()),
        };

        // The first item should be the messageId
        let msgid = msgid_tag
            .and_then(|t| t.match_class(TagClass::Universal))
            .and_then(|t| t.match_id(Types::Integer as u64))
            // Get the raw bytes
            .and_then(|t| t.expect_primitive())
            .and_then(ber_integer_to_i64)
            // Trunc to i32.
            .map(|i| i as i32)
            .ok_or(())?;

        let op = op_tag.ok_or(())?;
        let op = LdapOp::try_from(op)?;

        let ctrl = ctrl_tag
            .and_then(|t| t.match_class(TagClass::Context))
            .and_then(|t| t.match_id(0))
            // So it's probably controls, decode them?
            .map(|_t| Vec::new())
            .unwrap_or_else(|| Vec::new());

        Ok(LdapMsg { msgid, op, ctrl })
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
            if ctrl.len() > 0 {
                unimplemented!();
            } else {
                None
            }
        }))
        .filter_map(|v| v)
        .collect();
        Tag::Sequence(Sequence {
            inner: seq,
            ..Default::default()
        })
        .into_structure()
    }
}

impl TryFrom<StructureTag> for LdapOp {
    type Error = ();

    fn try_from(value: StructureTag) -> Result<Self, Self::Error> {
        let StructureTag { class, id, payload } = value;
        if class != TagClass::Application {
            return Err(());
        }
        match (id, payload) {
            // https://tools.ietf.org/html/rfc4511#section-4.2
            // BindRequest
            (0, PL::C(inner)) => LdapBindRequest::try_from(inner).map(|v| LdapOp::BindRequest(v)),
            // BindResponse
            (1, PL::C(inner)) => LdapBindResponse::try_from(inner).map(|v| LdapOp::BindResponse(v)),
            // UnbindRequest
            (2, _) => Ok(LdapOp::UnbindRequest),
            (3, PL::C(inner)) => {
                LdapSearchRequest::try_from(inner).map(|v| LdapOp::SearchRequest(v))
            }
            (4, PL::C(inner)) => {
                LdapSearchResultEntry::try_from(inner).map(|v| LdapOp::SearchResultEntry(v))
            }
            (5, PL::C(inner)) => {
                LdapResult::try_from_tag(inner).map(|(lr, _)| LdapOp::SearchResultDone(lr))
            }
            (8, PL::C(inner)) => LdapAddRequest::try_from(inner).map(|v| LdapOp::AddRequest(v)),
            (9, PL::C(inner)) => {
                LdapResult::try_from_tag(inner).map(|(lr, _)| LdapOp::AddResponse(lr))
            }
            (10, PL::P(inner)) => String::from_utf8(inner)
                .ok()
                .ok_or(())
                .map(|s| LdapOp::DelRequest(s)),
            (11, PL::C(inner)) => {
                LdapResult::try_from_tag(inner).map(|(lr, _)| LdapOp::DelResponse(lr))
            }
            (16, PL::P(inner)) => ber_integer_to_i64(inner)
                .ok_or(())
                .map(|s| LdapOp::AbandonRequest(s as i32)),
            (23, PL::C(inner)) => {
                LdapExtendedRequest::try_from(inner).map(|v| LdapOp::ExtendedRequest(v))
            }
            (24, PL::C(inner)) => {
                LdapExtendedResponse::try_from(inner).map(|v| LdapOp::ExtendedResponse(v))
            }
            (id, _) => {
                println!("unknown op -> {:?}", id);
                Err(())
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
        }
    }
}

impl TryFrom<StructureTag> for LdapBindCred {
    type Error = ();

    fn try_from(value: StructureTag) -> Result<Self, Self::Error> {
        if value.class != TagClass::Context {
            return Err(());
        }

        match value.id {
            0 => value
                .expect_primitive()
                .and_then(|bv| String::from_utf8(bv).ok())
                .map(|pw| LdapBindCred::Simple(pw))
                .ok_or(()),
            _ => Err(()),
        }
    }
}

impl TryFrom<Vec<StructureTag>> for LdapBindRequest {
    type Error = ();

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
            .ok_or(())?;
        if v != 3 {
            return Err(());
        };

        // Get the DN
        let dn = value
            .pop()
            .and_then(|t| t.match_class(TagClass::Universal))
            .and_then(|t| t.match_id(Types::OctetString as u64))
            .and_then(|t| t.expect_primitive())
            .and_then(|bv| String::from_utf8(bv).ok())
            .ok_or(())?;

        // Andddd get the credential
        let cred = value
            .pop()
            .and_then(|v| LdapBindCred::try_from(v).ok())
            .ok_or(())?;

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
            if referral.len() > 0 {
                // Remember to mark this as id 3, class::Context  (I think)
                unimplemented!();
            } else {
                None
            }
        }))
    }
}

impl From<LdapResult> for Vec<Tag> {
    fn from(value: LdapResult) -> Vec<Tag> {
        // get all the values from the LdapResult
        value.into_tag_iter().filter_map(|s| s).collect()
    }
}

impl LdapResult {
    fn try_from_tag(mut value: Vec<StructureTag>) -> Result<(Self, Vec<StructureTag>), ()> {
        // First, reverse all the elements so we are in the correct order.
        value.reverse();

        let code = value
            .pop()
            .and_then(|t| t.match_class(TagClass::Universal))
            .and_then(|t| t.match_id(Types::Enumerated as u64))
            .and_then(|t| t.expect_primitive())
            .and_then(ber_integer_to_i64)
            .ok_or(())
            .and_then(|i| LdapResultCode::try_from(i))?;

        let matcheddn = value
            .pop()
            .and_then(|t| t.match_class(TagClass::Universal))
            .and_then(|t| t.match_id(Types::OctetString as u64))
            .and_then(|t| t.expect_primitive())
            .and_then(|bv| String::from_utf8(bv).ok())
            .ok_or(())?;

        let message = value
            .pop()
            .and_then(|t| t.match_class(TagClass::Universal))
            .and_then(|t| t.match_id(Types::OctetString as u64))
            .and_then(|t| t.expect_primitive())
            .and_then(|bv| String::from_utf8(bv).ok())
            .ok_or(())?;

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
    type Error = ();

    fn try_from(value: Vec<StructureTag>) -> Result<Self, Self::Error> {
        // This MUST be the first thing we do!
        let (res, _remtag) = LdapResult::try_from_tag(value)?;

        // Now with the remaining tags, populate anything else we need
        Ok(LdapBindResponse {
            res,
            saslcreds: None,
        })
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
                        inner: Vec::from(sc),
                        ..Default::default()
                    })
                })
            }))
            .filter_map(|s| s)
            .collect()
    }
}

impl TryFrom<StructureTag> for LdapFilter {
    type Error = ();

    fn try_from(value: StructureTag) -> Result<Self, Self::Error> {
        if value.class != TagClass::Context {
            return Err(());
        };

        match value.id {
            0 => {
                let inner = value.expect_constructed().ok_or(())?;
                let vf: Result<Vec<_>, _> =
                    inner.into_iter().map(|v| LdapFilter::try_from(v)).collect();
                Ok(LdapFilter::And(vf?))
            }
            1 => {
                let inner = value.expect_constructed().ok_or(())?;
                let vf: Result<Vec<_>, _> =
                    inner.into_iter().map(|v| LdapFilter::try_from(v)).collect();
                Ok(LdapFilter::Or(vf?))
            }
            2 => {
                let inner = value
                    .expect_constructed()
                    .and_then(|mut i| i.pop())
                    .ok_or(())?;
                let inner_filt = LdapFilter::try_from(inner)?;
                Ok(LdapFilter::Not(Box::new(inner_filt)))
            }
            3 => {
                let mut inner = value.expect_constructed().ok_or(())?;
                inner.reverse();

                let a = inner
                    .pop()
                    .and_then(|t| t.match_class(TagClass::Universal))
                    .and_then(|t| t.match_id(Types::OctetString as u64))
                    .and_then(|t| t.expect_primitive())
                    .and_then(|bv| String::from_utf8(bv).ok())
                    .ok_or(())?;

                let v = inner
                    .pop()
                    .and_then(|t| t.match_class(TagClass::Universal))
                    .and_then(|t| t.match_id(Types::OctetString as u64))
                    .and_then(|t| t.expect_primitive())
                    .and_then(|bv| String::from_utf8(bv).ok())
                    .ok_or(())?;

                Ok(LdapFilter::Equality(a, v))
            }
            4 => {
                let mut inner = value.expect_constructed().ok_or(())?;
                inner.reverse();

                let ty = inner
                    .pop()
                    .and_then(|t| t.match_class(TagClass::Universal))
                    .and_then(|t| t.match_id(Types::OctetString as u64))
                    .and_then(|t| t.expect_primitive())
                    .and_then(|bv| String::from_utf8(bv).ok())
                    .ok_or(())?;

                let f = inner
                    .pop()
                    .and_then(|t| t.match_class(TagClass::Universal))
                    .and_then(|t| t.match_id(Types::Sequence as u64))
                    .and_then(|t| t.expect_constructed())
                    .and_then(|bv| {
                        let mut filter = LdapSubstringFilter::default();
                        for (i, StructureTag { class, id, payload }) in bv.iter().enumerate() {
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
                    .ok_or(())?;

                Ok(LdapFilter::Substring(ty, f))
            }
            7 => {
                let a = value
                    .expect_primitive()
                    .and_then(|bv| String::from_utf8(bv).ok())
                    .ok_or(())?;
                Ok(LdapFilter::Present(a))
            }
            _ => Err(()),
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
                        inner: f
                            .initial
                            .into_iter()
                            .map(|s| {
                                Tag::OctetString(OctetString {
                                    inner: Vec::from(s),
                                    id: 0,
                                    ..Default::default()
                                })
                            })
                            .chain(f.any.into_iter().map(|s| {
                                Tag::OctetString(OctetString {
                                    inner: Vec::from(s),
                                    id: 1,
                                    ..Default::default()
                                })
                            })).chain(f.final_.into_iter().map(|s| {
                                Tag::OctetString(OctetString {
                                    inner: Vec::from(s),
                                    id: 2,
                                    ..Default::default()
                                })
                            }))
                            .collect(),
                        ..Default::default()
                    }),
                ],
            }),
            LdapFilter::Present(a) => Tag::OctetString(OctetString {
                id: 7,
                class: TagClass::Context,
                inner: Vec::from(a),
            }),
        }
    }
}

impl TryFrom<Vec<StructureTag>> for LdapSearchRequest {
    type Error = ();

    fn try_from(mut value: Vec<StructureTag>) -> Result<Self, Self::Error> {
        value.reverse();

        let base = value
            .pop()
            .and_then(|t| t.match_class(TagClass::Universal))
            .and_then(|t| t.match_id(Types::OctetString as u64))
            .and_then(|t| t.expect_primitive())
            .and_then(|bv| String::from_utf8(bv).ok())
            .ok_or(())?;
        let scope = value
            .pop()
            .and_then(|t| t.match_class(TagClass::Universal))
            .and_then(|t| t.match_id(Types::Enumerated as u64))
            .and_then(|t| t.expect_primitive())
            .and_then(ber_integer_to_i64)
            .ok_or(())
            .and_then(|i| LdapSearchScope::try_from(i))?;
        let aliases = value
            .pop()
            .and_then(|t| t.match_class(TagClass::Universal))
            .and_then(|t| t.match_id(Types::Enumerated as u64))
            .and_then(|t| t.expect_primitive())
            .and_then(ber_integer_to_i64)
            .ok_or(())
            .and_then(|i| LdapDerefAliases::try_from(i))?;
        let sizelimit = value
            .pop()
            .and_then(|t| t.match_class(TagClass::Universal))
            .and_then(|t| t.match_id(Types::Integer as u64))
            .and_then(|t| t.expect_primitive())
            .and_then(ber_integer_to_i64)
            .map(|v| v as i32)
            .ok_or(())?;
        let timelimit = value
            .pop()
            .and_then(|t| t.match_class(TagClass::Universal))
            .and_then(|t| t.match_id(Types::Integer as u64))
            .and_then(|t| t.expect_primitive())
            .and_then(ber_integer_to_i64)
            .map(|v| v as i32)
            .ok_or(())?;
        let typesonly = value
            .pop()
            .and_then(|t| t.match_class(TagClass::Universal))
            .and_then(|t| t.match_id(Types::Boolean as u64))
            .and_then(|t| t.expect_primitive())
            .and_then(ber_bool_to_bool)
            .ok_or(())?;
        let filter = value
            .pop()
            .and_then(|t| LdapFilter::try_from(t).ok())
            .ok_or(())?;
        let attrs = value
            .pop()
            .and_then(|t| t.match_class(TagClass::Universal))
            .and_then(|t| t.match_id(Types::Sequence as u64))
            .and_then(|t| t.expect_constructed())
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
            .ok_or(())?;

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

impl TryFrom<StructureTag> for LdapPartialAttribute {
    type Error = ();

    fn try_from(value: StructureTag) -> Result<Self, Self::Error> {
        // get the inner from the sequence
        let mut inner = value
            .match_class(TagClass::Universal)
            .and_then(|t| t.match_id(Types::Sequence as u64))
            .and_then(|t| t.expect_constructed())
            .ok_or(())?;

        inner.reverse();

        let atype = inner
            .pop()
            .and_then(|t| t.match_class(TagClass::Universal))
            .and_then(|t| t.match_id(Types::OctetString as u64))
            .and_then(|t| t.expect_primitive())
            .and_then(|bv| String::from_utf8(bv).ok())
            .ok_or(())?;

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
                            .and_then(|bv| String::from_utf8(bv).ok())
                    })
                    .collect();
                r
            })
            .ok_or(())?;

        Ok(LdapPartialAttribute { atype, vals })
    }
}

impl TryFrom<Vec<StructureTag>> for LdapSearchResultEntry {
    type Error = ();

    fn try_from(mut value: Vec<StructureTag>) -> Result<Self, Self::Error> {
        value.reverse();

        let dn = value
            .pop()
            .and_then(|t| t.match_class(TagClass::Universal))
            .and_then(|t| t.match_id(Types::OctetString as u64))
            .and_then(|t| t.expect_primitive())
            .and_then(|bv| String::from_utf8(bv).ok())
            .ok_or(())?;

        let attributes = value
            .pop()
            .and_then(|t| t.match_class(TagClass::Universal))
            .and_then(|t| t.match_id(Types::Sequence as u64))
            .and_then(|t| t.expect_constructed())
            .and_then(|bset| {
                let r: Result<Vec<_>, _> = bset
                    .into_iter()
                    .map(|bv| LdapPartialAttribute::try_from(bv))
                    .collect();
                r.ok()
            })
            .ok_or(())?;

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
                                inner: Vec::from(v),
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
    type Error = ();

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
            .ok_or(())?;

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
            .filter_map(|s| s),
        )
        .collect()
    }
}

impl TryFrom<Vec<StructureTag>> for LdapExtendedResponse {
    type Error = ();

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
            .filter_map(|s| s)
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
            value: value.map(|v| Vec::from(v)),
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

impl TryFrom<i64> for LdapSearchScope {
    type Error = ();

    fn try_from(value: i64) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(LdapSearchScope::Base),
            1 => Ok(LdapSearchScope::OneLevel),
            2 => Ok(LdapSearchScope::Subtree),
            _ => Err(()),
        }
    }
}

impl TryFrom<i64> for LdapDerefAliases {
    type Error = ();

    fn try_from(value: i64) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(LdapDerefAliases::Never),
            1 => Ok(LdapDerefAliases::InSearching),
            2 => Ok(LdapDerefAliases::FindingBaseObj),
            3 => Ok(LdapDerefAliases::Always),
            _ => Err(()),
        }
    }
}

impl TryFrom<Vec<StructureTag>> for LdapAddRequest {
    type Error = ();

    fn try_from(mut value: Vec<StructureTag>) -> Result<Self, Self::Error> {
        value.reverse();

        let dn = value
            .pop()
            .and_then(|t| t.match_class(TagClass::Universal))
            .and_then(|t| t.match_id(Types::OctetString as u64))
            .and_then(|t| t.expect_primitive())
            .and_then(|bv| String::from_utf8(bv).ok())
            .ok_or(())?;

        let attributes = value
            .pop()
            .and_then(|t| t.match_class(TagClass::Universal))
            .and_then(|t| t.match_id(Types::Sequence as u64))
            .and_then(|t| t.expect_constructed())
            .and_then(|bset| {
                let r: Result<Vec<_>, _> = bset
                    .into_iter()
                    .map(|bv| LdapAttribute::try_from(bv))
                    .collect();
                r.ok()
            })
            .ok_or(())?;

        Ok(LdapAddRequest { dn, attributes })
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

impl TryFrom<i64> for LdapResultCode {
    type Error = ();

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
            _ => Err(()),
        }
    }
}

fn ber_bool_to_bool(bv: Vec<u8>) -> Option<bool> {
    bv.get(0).map(|v| match v {
        0 => false,
        _ => true,
    })
}

fn ber_integer_to_i64(bv: Vec<u8>) -> Option<i64> {
    // ints in ber are be and may be truncated.
    let mut raw: [u8; 8] = [0; 8];
    // This is where we need to start inserting bytes.
    let base = if bv.len() > 8 {
        return None;
    } else {
        8 - bv.len()
    };
    for i in 0..bv.len() {
        raw[base + i] = bv[i];
    }
    Some(i64::from_be_bytes(raw))
}

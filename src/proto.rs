use lber::common::TagClass;
use lber::structure::{StructureTag, PL};
use lber::structures::ASNTag;
use lber::structures::{
    Boolean, Enumerated, ExplicitTag, Integer, Null, OctetString, Sequence, Set, Tag,
};
use lber::universal::Types;
use lber::write as lber_write;

use lber::parse::Parser;
use lber::{Consumer, ConsumerState, Input};

use bytes::BytesMut;

use std::convert::{From, TryFrom};
use std::iter::{once, once_with};

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
    pub referral: Vec<String>,
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
    // https://datatracker.ietf.org/doc/html/rfc4511#section-4.6
    ModifyRequest(LdapModifyRequest),
    ModifyResponse(LdapResult),
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

#[derive(Clone, PartialEq)]
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
#[derive(Clone, PartialEq)]
pub struct LdapPartialAttribute {
    pub atype: String,
    pub vals: Vec<String>,
}

// A PartialAttribute allows zero values, while
// Attribute requires at least one value.
pub type LdapAttribute = LdapPartialAttribute;

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
pub struct LdapModifyRequest {
    pub dn: String,
    pub changes: Vec<LdapModify>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct LdapModify {
    pub operation: LdapModifyType,
    pub modification: LdapPartialAttribute,
}

#[derive(Debug, Clone, PartialEq)]
#[repr(i64)]
pub enum LdapModifyType {
    Add = 0,
    Delete = 1,
    Replace = 2,
}

#[derive(Clone, PartialEq)]
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

#[derive(Clone, PartialEq)]
pub struct LdapPasswordModifyRequest {
    pub user_identity: Option<String>,
    pub old_password: Option<String>,
    pub new_password: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct LdapPasswordModifyResponse {
    pub res: LdapResult,
    pub gen_password: Option<String>,
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

        lber_write::encode_into(&mut bytes, tag.into_structure()).unwrap();

        LdapExtendedRequest {
            name: "1.3.6.1.4.1.4203.1.11.1".to_string(),
            value: Some(bytes.to_vec()),
        }
    }
}

impl TryFrom<&LdapExtendedRequest> for LdapPasswordModifyRequest {
    type Error = ();
    fn try_from(value: &LdapExtendedRequest) -> Result<Self, Self::Error> {
        // 1.3.6.1.4.1.4203.1.11.1
        if value.name != "1.3.6.1.4.1.4203.1.11.1" {
            return Err(());
        }

        let buf = if let Some(b) = &value.value {
            b
        } else {
            return Err(());
        };

        let mut parser = Parser::new();
        let (_size, msg) = match *parser.handle(Input::Element(buf)) {
            ConsumerState::Done(size, ref msg) => (size, msg),
            _ => return Err(()),
        };

        let seq = msg
            .clone()
            .match_id(Types::Sequence as u64)
            .and_then(|t| t.expect_constructed())
            .ok_or(())?;

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
                .ok_or(())?;

            match id {
                0 => lpmr.user_identity = Some(s),
                1 => lpmr.old_password = Some(s),
                2 => lpmr.new_password = Some(s),
                _ => return Err(()),
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

        lber_write::encode_into(&mut bytes, tag.into_structure()).unwrap();

        LdapExtendedResponse {
            res: value.res,
            // responseName is absent.
            name: None,
            value: Some(bytes.to_vec()),
        }
    }
}

impl TryFrom<&LdapExtendedResponse> for LdapPasswordModifyResponse {
    type Error = ();
    fn try_from(value: &LdapExtendedResponse) -> Result<Self, Self::Error> {
        if value.name.is_some() {
            return Err(());
        }

        let buf = if let Some(b) = &value.value {
            b
        } else {
            return Err(());
        };

        let mut parser = Parser::new();
        let (_size, msg) = match *parser.handle(Input::Element(buf)) {
            ConsumerState::Done(size, ref msg) => (size, msg),
            _ => return Err(()),
        };

        let mut seq = msg
            .clone()
            .match_id(Types::Sequence as u64)
            .and_then(|t| t.expect_constructed())
            .ok_or(())?;

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

    pub fn try_from_openldap_mem_dump(bytes: &[u8]) -> Result<Self, ()> {
        let mut parser = lber::parse::Parser::new();
        let (taken, msgid_tag) = match *parser.handle(lber::Input::Element(bytes)) {
            lber::ConsumerState::Done(lber::Move::Consume(size), ref msg) => {
                (size, Some(msg.clone()))
            }
            _ => return Err(()),
        };

        let (_, r_bytes) = bytes.split_at(taken);
        let (taken, op_tag) = match *parser.handle(lber::Input::Element(r_bytes)) {
            lber::ConsumerState::Done(lber::Move::Consume(size), ref msg) => {
                (size, Some(msg.clone()))
            }
            _ => return Err(()),
        };

        let (_, r_bytes) = r_bytes.split_at(taken);
        let (_taken, ctrl_tag) = if r_bytes.is_empty() {
            (0, None)
        } else {
            match *parser.handle(lber::Input::Element(r_bytes)) {
                lber::ConsumerState::Done(lber::Move::Consume(size), ref msg) => {
                    (size, Some(msg.clone()))
                }
                _ => return Err(()),
            }
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
            .unwrap_or_else(Vec::new);

        Ok(LdapMsg { msgid, op, ctrl })
    }
}

impl TryFrom<StructureTag> for LdapMsg {
    type Error = ();

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
            .unwrap_or_else(Vec::new);

        Ok(LdapMsg { msgid, op, ctrl })
    }
}

impl From<LdapMsg> for StructureTag {
    fn from(value: LdapMsg) -> StructureTag {
        let LdapMsg { msgid, op, ctrl: _ } = value;
        let seq: Vec<_> = once_with(|| {
            Some(Tag::Integer(Integer {
                inner: msgid as i64,
                ..Default::default()
            }))
        })
        .chain(once_with(|| Some(op.into())))
        /*
        .chain(once_with(|| {
            if ctrl.is_empty() {
                None
            } else {
                // unimplemented!();
            }
        }))
        */
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
    type Error = ();

    fn try_from(value: StructureTag) -> Result<Self, Self::Error> {
        let StructureTag { class, id, payload } = value;
        if class != TagClass::Application {
            return Err(());
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
                .ok_or(())
                .map(LdapOp::DelRequest),
            (11, PL::C(inner)) => {
                LdapResult::try_from_tag(inner).map(|(lr, _)| LdapOp::DelResponse(lr))
            }
            (16, PL::P(inner)) => ber_integer_to_i64(inner)
                .ok_or(())
                .map(|s| LdapOp::AbandonRequest(s as i32)),
            (23, PL::C(inner)) => LdapExtendedRequest::try_from(inner).map(LdapOp::ExtendedRequest),
            (24, PL::C(inner)) => {
                LdapExtendedResponse::try_from(inner).map(LdapOp::ExtendedResponse)
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
                .map(LdapBindCred::Simple)
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
            .and_then(LdapResultCode::try_from)?;

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
            .flatten()
            .collect()
    }
}

impl TryFrom<StructureTag> for LdapFilter {
    type Error = ();

    fn try_from(value: StructureTag) -> Result<Self, Self::Error> {
        if value.class != TagClass::Context {
            trace!("Invalid tagclass");
            return Err(());
        };

        match value.id {
            0 => {
                let inner = value.expect_constructed().ok_or_else(|| {
                    trace!("invalid and filter");
                })?;
                let vf: Result<Vec<_>, _> = inner.into_iter().map(LdapFilter::try_from).collect();
                Ok(LdapFilter::And(vf?))
            }
            1 => {
                let inner = value.expect_constructed().ok_or_else(|| {
                    trace!("invalid or filter");
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
                    })?;
                let inner_filt = LdapFilter::try_from(inner)?;
                Ok(LdapFilter::Not(Box::new(inner_filt)))
            }
            3 => {
                let mut inner = value.expect_constructed().ok_or_else(|| {
                    trace!("invalid eq filter");
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
                    })?;

                Ok(LdapFilter::Equality(a, v))
            }
            4 => {
                let mut inner = value.expect_constructed().ok_or_else(|| {
                    trace!("invalid sub filter");
                })?;
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
                    .ok_or(())?;

                Ok(LdapFilter::Substring(ty, f))
            }
            7 => {
                let a = value
                    .expect_primitive()
                    .and_then(|bv| String::from_utf8(bv).ok())
                    .ok_or_else(|| {
                        trace!("invalid pres filter");
                    })?;
                Ok(LdapFilter::Present(a))
            }
            _ => {
                trace!("invalid value tag");
                Err(())
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
                            }))
                            .chain(f.final_.into_iter().map(|s| {
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
            .ok_or_else(|| {
                trace!("invalid basedn");
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
                trace!("invalid scope")}
            )
            .and_then(LdapSearchScope::try_from)?;
        let aliases = value
            .pop()
            .and_then(|t| t.match_class(TagClass::Universal))
            .and_then(|t| t.match_id(Types::Enumerated as u64))
            .and_then(|t| t.expect_primitive())
            .and_then(ber_integer_to_i64)
            .ok_or_else(|| trace!("invalid aliases"))
            .and_then(LdapDerefAliases::try_from)?;
        let sizelimit = value
            .pop()
            .and_then(|t| t.match_class(TagClass::Universal))
            .and_then(|t| t.match_id(Types::Integer as u64))
            .and_then(|t| t.expect_primitive())
            .and_then(ber_integer_to_i64)
            .map(|v| v as i32)
            .ok_or_else(|| trace!("invalid sizelimit"))?;
        let timelimit = value
            .pop()
            .and_then(|t| t.match_class(TagClass::Universal))
            .and_then(|t| t.match_id(Types::Integer as u64))
            .and_then(|t| t.expect_primitive())
            .and_then(ber_integer_to_i64)
            .map(|v| v as i32)
            .ok_or_else(|| trace!("invalid timelimit"))?;
        let typesonly = value
            .pop()
            .and_then(|t| t.match_class(TagClass::Universal))
            .and_then(|t| t.match_id(Types::Boolean as u64))
            .and_then(|t| t.expect_primitive())
            .and_then(ber_bool_to_bool)
            .ok_or_else(|| trace!("invalid typesonly"))?;
        let filter = value
            .pop()
            .and_then(|t| LdapFilter::try_from(t).ok())
            .ok_or_else(|| trace!("invalid filter"))?;
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
            .ok_or_else(|| trace!("invalid attributes"))?;

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
    type Error = ();

    fn try_from(value: StructureTag) -> Result<Self, Self::Error> {
        // get the inner from the sequence
        let mut inner = value
            .match_class(TagClass::Universal)
            .and_then(|t| t.match_id(Types::Sequence as u64))
            .and_then(|t| t.expect_constructed())
            .ok_or(())?;

        inner.reverse();

        let operation = inner
            .pop()
            .and_then(|t| t.match_class(TagClass::Universal))
            .and_then(|t| t.match_id(Types::Enumerated as u64))
            .and_then(|t| t.expect_primitive())
            .and_then(ber_integer_to_i64)
            .ok_or(())
            .and_then(LdapModifyType::try_from)?;

        let modification = inner
            .pop()
            .and_then(|t| LdapPartialAttribute::try_from(t).ok())
            .ok_or(())?;

        Ok(Self {
            operation,
            modification,
        })
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
                    .map(LdapPartialAttribute::try_from)
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
            .flatten(),
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

impl TryFrom<i64> for LdapModifyType {
    type Error = ();

    fn try_from(value: i64) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(LdapModifyType::Add),
            1 => Ok(LdapModifyType::Delete),
            2 => Ok(LdapModifyType::Replace),
            _ => Err(()),
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

impl TryFrom<Vec<StructureTag>> for LdapModifyRequest {
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

        let changes = value
            .pop()
            .and_then(|t| t.match_class(TagClass::Universal))
            .and_then(|t| t.match_id(Types::Sequence as u64))
            .and_then(|t| t.expect_constructed())
            .and_then(|bset| {
                let r: Result<Vec<_>, _> = bset.into_iter().map(LdapModify::try_from).collect();
                r.ok()
            })
            .ok_or(())?;

        Ok(Self { dn, changes })
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
                let r: Result<Vec<_>, _> = bset.into_iter().map(LdapAttribute::try_from).collect();
                r.ok()
            })
            .ok_or(())?;

        Ok(LdapAddRequest { dn, attributes })
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

// Implement by hand to avoid printing the password.
impl std::fmt::Debug for LdapBindCred {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, r#"Simple("********")"#)
    }
}

// Implement by hand to avoid printing the password.
impl std::fmt::Debug for LdapPartialAttribute {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut f = f.debug_struct("LdapPartialAttribute");
        f.field("atype", &self.atype);
        if self.atype == "userPassword" && self.vals.len() == 1 {
            f.field("vals", &vec!["********".to_string()]);
        } else {
            f.field("vals", &self.vals);
        }
        f.finish()
    }
}

// Implement by hand to avoid printing the password.
impl std::fmt::Debug for LdapExtendedRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut f = f.debug_struct("LdapExtendedRequest");
        f.field("name", &self.name);
        f.field("value", &self.value.as_ref().map(|_| "vec![...]"));
        f.finish()
    }
}

// Implement by hand to avoid printing the password.
impl std::fmt::Debug for LdapPasswordModifyRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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

fn ber_bool_to_bool(bv: Vec<u8>) -> Option<bool> {
    bv.get(0).map(|v| !matches!(v, 0))
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
    raw[base..(bv.len() + base)].clone_from_slice(&bv[..]);
    Some(i64::from_be_bytes(raw))
}

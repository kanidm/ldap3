use lber::common::TagClass;
use lber::structure::{StructureTag, PL};
use lber::structures::ASNTag;
use lber::structures::{Boolean, Enumerated, Integer, Null, OctetString, Sequence, Set, Tag};
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
pub enum LdapOp {
    SimpleBind(LdapSimpleBind),
}

#[derive(Debug, Clone, PartialEq)]
pub struct LdapSimpleBind {
    pub dn: String,
    pub pw: String,
}

impl LdapOp {
    pub fn is_simplebind(&self) -> bool {
        match self {
            LdapOp::SimpleBind(_) => true,
            _ => false,
        }
    }
}

impl LdapSimpleBind {
    pub fn new_anonymous() -> Self {
        LdapSimpleBind {
            dn: "".to_string(),
            pw: "".to_string(),
        }
    }
}

impl From<LdapSimpleBind> for Tag {
    fn from(value: LdapSimpleBind) -> Tag {
        Tag::Sequence(Sequence {
            id: 0,
            class: TagClass::Application,
            inner: vec![
                Tag::Integer(Integer {
                    inner: 3,
                    ..Default::default()
                }),
                Tag::OctetString(OctetString {
                    inner: Vec::from(value.dn),
                    ..Default::default()
                }),
                Tag::OctetString(OctetString {
                    id: 0,
                    class: TagClass::Context,
                    inner: Vec::from(value.pw),
                }),
            ],
        })
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
            .map(|t| Vec::new())
            .unwrap_or_else(|| Vec::new());

        Ok(LdapMsg { msgid, op, ctrl })
    }
}

impl From<LdapMsg> for StructureTag {
    fn from(value: LdapMsg) -> StructureTag {
        let LdapMsg { msgid, op, ctrl } = value;
        let mut seq: Vec<_> = once_with(|| {
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
        match id {
            // https://tools.ietf.org/html/rfc4511#section-4.2
            // BindRequest
            0 => match payload {
                PL::C(inner) => LdapSimpleBind::try_from(inner).map(|v| LdapOp::SimpleBind(v)),
                _ => Err(()),
            },
            _ => Err(()),
        }
    }
}

impl From<LdapOp> for Tag {
    fn from(value: LdapOp) -> Tag {
        let (id, inner) = match value {
            LdapOp::SimpleBind(lsb) => (0, lsb.into()),
        };
        Tag::Sequence(Sequence {
            class: TagClass::Application,
            id,
            inner,
        })
    }
}

impl TryFrom<Vec<StructureTag>> for LdapSimpleBind {
    type Error = ();

    fn try_from(mut value: Vec<StructureTag>) -> Result<Self, Self::Error> {
        // https://tools.ietf.org/html/rfc4511#section-4.2
        // BindRequest

        // We need 3 elements, the version, the dn, and a choice of the
        // credential (we only support simple)
        let (v, dn, choice) = if value.len() == 3 {
            // Remember it's a vec, so we pop in reverse order.
            let choice = value.pop();
            let dn = value.pop();
            let v = value.pop();
            (v, dn, choice)
        } else {
            return Err(());
        };

        // Check the version is 3
        let v = v
            .and_then(|t| t.match_class(TagClass::Universal))
            .and_then(|t| t.match_id(Types::Integer as u64))
            .and_then(|t| t.expect_primitive())
            .and_then(ber_integer_to_i64)
            .ok_or(())?;
        if v != 3 {
            return Err(());
        };

        // Get the DN
        let dn = dn
            .and_then(|t| t.match_class(TagClass::Universal))
            .and_then(|t| t.match_id(Types::OctetString as u64))
            .and_then(|t| t.expect_primitive())
            .and_then(|bv| String::from_utf8(bv).ok())
            .ok_or(())?;

        // Andddd get the password.
        let pw = choice
            .and_then(|t| t.match_class(TagClass::Context))
            // Only match pw
            .and_then(|t| t.match_id(0))
            .and_then(|t| t.expect_primitive())
            .and_then(|bv| String::from_utf8(bv).ok())
            .ok_or(())?;

        Ok(LdapSimpleBind { dn, pw })
    }
}

impl From<LdapSimpleBind> for Vec<Tag> {
    fn from(value: LdapSimpleBind) -> Vec<Tag> {
        vec![
            Tag::Integer(Integer {
                inner: 3,
                ..Default::default()
            }),
            Tag::OctetString(OctetString {
                inner: Vec::from(value.dn),
                ..Default::default()
            }),
            Tag::OctetString(OctetString {
                id: 0,
                class: TagClass::Context,
                inner: Vec::from(value.pw),
            }),
        ]
    }
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

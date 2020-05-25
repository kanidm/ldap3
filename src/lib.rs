pub mod proto;
pub mod simple;

use bytes::{Buf, BytesMut};
use lber::parse::Parser;
use lber::structure::StructureTag;
use lber::write as lber_write;
use lber::{Consumer, ConsumerState, Input, Move};
use std::convert::TryFrom;
use std::io;
use tokio_util::codec::{Decoder, Encoder};

use crate::proto::LdapMsg;
pub use crate::simple::*;

pub struct LdapCodec;

impl Decoder for LdapCodec {
    type Item = LdapMsg;
    type Error = io::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // How many bytes to consume?
        let mut parser = Parser::new();
        let (size, msg) = match *parser.handle(Input::Element(buf)) {
            ConsumerState::Continue(_) => return Ok(None),
            ConsumerState::Error(_e) => {
                return Err(io::Error::new(io::ErrorKind::Other, "lber parser"))
            }
            ConsumerState::Done(size, ref msg) => (size, msg),
        };
        // Consume that
        let size = match size {
            Move::Await(_) => return Ok(None),
            Move::Seek(_) => return Err(io::Error::new(io::ErrorKind::Other, "lber seek")),
            Move::Consume(s) => s,
        };
        buf.advance(size);
        // Build the LdapMsg from the Tag
        LdapMsg::try_from(msg.clone())
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "ldapmsg invalid"))
            .map(|v| Some(v))
    }
}

impl Encoder for LdapCodec {
    type Item = LdapMsg;
    type Error = io::Error;

    fn encode(&mut self, msg: LdapMsg, buf: &mut BytesMut) -> io::Result<()> {
        let encoded: StructureTag = msg.into();
        lber_write::encode_into(buf, encoded)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::proto::*;
    use crate::LdapCodec;
    use bytes::BytesMut;
    use tokio_util::codec::{Decoder, Encoder};

    macro_rules! do_test {
        ($req:expr) => {{
            let mut buf = BytesMut::new();
            let mut server_codec = LdapCodec;
            assert!(server_codec.encode($req.clone(), &mut buf).is_ok());
            let res = server_codec.decode(&mut buf).expect("failed to decode");
            let msg = res.expect("None found?");
            println!("{:?}", msg);
            assert!($req == msg)
        }};
    }

    #[test]
    fn test_ldapserver_codec_simplebind() {
        do_test!(LdapMsg {
            msgid: 1,
            op: LdapOp::BindRequest(LdapBindRequest {
                dn: "".to_string(),
                cred: LdapBindCred::Simple("".to_string()),
            }),
            ctrl: vec![],
        });
    }

    #[test]
    fn test_ldapserver_codec_unbind() {
        do_test!(LdapMsg {
            msgid: 65536,
            op: LdapOp::UnbindRequest,
            ctrl: vec![],
        });
    }

    #[test]
    fn test_ldapserver_codec_bindresponse() {
        do_test!(LdapMsg {
            msgid: 999999,
            op: LdapOp::BindResponse(LdapBindResponse {
                res: LdapResult {
                    code: LdapResultCode::Success,
                    matcheddn: "cn=Directory Manager".to_string(),
                    message: "It works!".to_string(),
                    referral: vec![],
                },
                saslcreds: None
            }),
            ctrl: vec![],
        });
    }

    #[test]
    fn test_ldapserver_codec_searchrequest() {
        do_test!(LdapMsg {
            msgid: 2_147_483_646,
            op: LdapOp::SearchRequest(LdapSearchRequest {
                base: "dc=example,dc=com".to_string(),
                scope: LdapSearchScope::Base,
                aliases: LdapDerefAliases::Never,
                sizelimit: 0,
                timelimit: 0,
                typesonly: false,
                filter: LdapFilter::Or(vec![
                    LdapFilter::Present("cn".to_string()),
                    LdapFilter::Equality("cn".to_string(), "name".to_string()),
                    LdapFilter::Not(Box::new(LdapFilter::And(vec![LdapFilter::Present(
                        "cursed".to_string()
                    ),]))),
                ]),
                attrs: vec!["cn".to_string(), "objectClass".to_string(),],
            }),
            ctrl: vec![],
        });
    }

    #[test]
    fn test_ldapserver_codec_searchresultentry() {
        do_test!(LdapMsg {
            msgid: 2_147_483_646,
            op: LdapOp::SearchResultEntry(LdapSearchResultEntry {
                dn: "cn=demo,dc=example,dc=com".to_string(),
                attributes: vec![
                    LdapPartialAttribute {
                        atype: "cn".to_string(),
                        vals: vec!["demo".to_string(),]
                    },
                    LdapPartialAttribute {
                        atype: "dn".to_string(),
                        vals: vec!["cn=demo,dc=example,dc=com".to_string(),]
                    },
                    LdapPartialAttribute {
                        atype: "objectClass".to_string(),
                        vals: vec!["cursed".to_string(),]
                    },
                ]
            }),
            ctrl: vec![],
        });
    }

    #[test]
    fn test_ldapserver_codec_searchresultdone() {
        do_test!(LdapMsg {
            msgid: 28799790,
            op: LdapOp::SearchResultDone(LdapResult {
                code: LdapResultCode::Success,
                matcheddn: "".to_string(),
                message: "Whargarble".to_string(),
                referral: vec![],
            }),
            ctrl: vec![],
        });
    }

    #[test]
    fn test_ldapserver_codec_extendedrequest() {
        do_test!(LdapMsg {
            msgid: 256,
            op: LdapOp::ExtendedRequest(LdapExtendedRequest {
                name: "1.3.6.1.4.1.4203.1.11.3".to_string(),
                value: None,
            }),
            ctrl: vec![],
        });
    }

    #[test]
    fn test_ldapserver_codec_extendedresponse() {
        do_test!(LdapMsg {
            msgid: 257,
            op: LdapOp::ExtendedResponse(LdapExtendedResponse {
                res: LdapResult {
                    code: LdapResultCode::Success,
                    matcheddn: "".to_string(),
                    message: "".to_string(),
                    referral: vec![],
                },
                name: Some("1.3.6.1.4.1.4203.1.11.3".to_string()),
                value: None,
            }),
            ctrl: vec![],
        });

        do_test!(LdapMsg {
            msgid: 257,
            op: LdapOp::ExtendedResponse(LdapExtendedResponse {
                res: LdapResult {
                    code: LdapResultCode::Success,
                    matcheddn: "".to_string(),
                    message: "".to_string(),
                    referral: vec![],
                },
                name: None,
                value: Some(Vec::from("hello")),
            }),
            ctrl: vec![],
        });
    }
}

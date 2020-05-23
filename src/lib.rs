mod proto;

use bytes::{Buf, BytesMut};
use lber::parse::Parser;
use lber::structure::StructureTag;
use lber::write as lber_write;
use lber::{Consumer, ConsumerState, Input, Move};
use std::convert::TryFrom;
use std::io;
use tokio_util::codec::{Decoder, Encoder};

pub use crate::proto::*;

pub struct LdapServerCodec;

impl Decoder for LdapServerCodec {
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

impl Encoder for LdapServerCodec {
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
    use crate::LdapServerCodec;
    use bytes::{Buf, BytesMut};
    use tokio_util::codec::{Decoder, Encoder};
    // use std::convert::TryInto;
    use lber::structures::Tag;

    macro_rules! do_test {
        ($req:expr) => {{
            let mut buf = BytesMut::new();
            let mut server_codec = LdapServerCodec;
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
            op: LdapOp::SimpleBind(LdapSimpleBind::new_anonymous()),
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
                value: Some("hello".to_string()),
            }),
            ctrl: vec![],
        });
    }
}

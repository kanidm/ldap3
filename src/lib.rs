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

impl Encoder<LdapMsg> for LdapServerCodec {
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

    #[test]
    fn test_ldapserver_codec_simplebind() {
        let mut buf = BytesMut::new();
        let mut server_codec = LdapServerCodec;
        // Encode a request
        let req = LdapMsg {
            msgid: 1,
            op: LdapOp::SimpleBind(LdapSimpleBind::new_anonymous()),
            ctrl: vec![],
        };
        assert!(server_codec.encode(req.clone(), &mut buf).is_ok());
        // Now pass it to the "server" to decode.
        println!("{:?}", buf);

        let res = server_codec.decode(&mut buf).expect("failed to decode");
        let msg = res.expect("None found?");
        println!("{:?}", msg);
        assert!(req == msg)
    }
}

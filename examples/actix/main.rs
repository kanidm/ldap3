use actix::prelude::*;
use futures_util::stream::StreamExt;
use ldap3_server::*;
use std::io;
use std::net;
use std::str::FromStr;
use tokio::io::WriteHalf;
use tokio::net::{TcpListener, TcpStream};
use tokio_util::codec::FramedRead;

#[derive(Message)]
#[rtype(result = "()")]
struct TcpConnect(pub TcpStream, pub net::SocketAddr);

pub struct LdapServer;

pub struct LdapSession {
    dn: String,
    framed: actix::io::FramedWrite<WriteHalf<TcpStream>, LdapServerCodec>,
}

impl Actor for LdapSession {
    type Context = actix::Context<Self>;
}

impl actix::io::WriteHandler<io::Error> for LdapSession {}

impl StreamHandler<Result<LdapMsg, io::Error>> for LdapSession {
    fn handle(&mut self, msg: Result<LdapMsg, io::Error>, ctx: &mut Self::Context) {
        println!("{:?}", msg);

        let msg = match msg {
            Ok(m) => m,
            Err(_) => {
                // Dc
                ctx.stop();
                return;
            }
        };

        let resp = match msg.op {
            LdapOp::SimpleBind(lsb) => self.do_bind(msg.msgid, &lsb),
            LdapOp::UnbindRequest => {
                // shutdown
                ctx.stop();
                return;
            }
            LdapOp::ExtendedRequest(lep) => {
                println!("{:?}", lep);
                match lep.name.as_str() {
                    "1.3.6.1.4.1.4203.1.11.3" => self.do_whoami(msg.msgid),
                    _ => LdapMsg::new(
                        msg.msgid,
                        LdapOp::ExtendedResponse(LdapExtendedResponse::new_operationserror(
                            "Unknown ExtendedRequest OID",
                        )),
                    ),
                }
            }
            // Invalid states
            LdapOp::BindResponse(_) | LdapOp::ExtendedResponse(_) => {
                // shutdown
                ctx.stop();
                return;
            }
        };
        self.framed.write(resp)
    }
}

impl LdapSession {
    pub fn new(framed: actix::io::FramedWrite<WriteHalf<TcpStream>, LdapServerCodec>) -> Self {
        LdapSession {
            dn: "Anonymous".to_string(),
            framed,
        }
    }

    pub fn do_bind(&mut self, msgid: i32, lsb: &LdapSimpleBind) -> LdapMsg {
        let res = if lsb.dn == "cn=Directory Manager" && lsb.pw == "password" {
            self.dn = lsb.dn.to_string();
            LdapBindResponse::new_success("")
        } else if lsb.dn == "" && lsb.pw == "" {
            self.dn = "Anonymous".to_string();
            LdapBindResponse::new_success("")
        } else {
            LdapBindResponse::new_invalidcredentials(lsb.dn.as_str(), "Failed")
        };
        LdapMsg::new(msgid, LdapOp::BindResponse(res))
    }

    pub fn do_whoami(&mut self, msgid: i32) -> LdapMsg {
        LdapMsg::new(
            msgid,
            LdapOp::ExtendedResponse(LdapExtendedResponse::new_success(
                None,
                Some(format!("dn: {}", self.dn).as_str()),
            )),
        )
    }
}

impl Actor for LdapServer {
    type Context = Context<Self>;
}

impl Handler<TcpConnect> for LdapServer {
    type Result = ();
    fn handle(&mut self, msg: TcpConnect, _: &mut Context<Self>) {
        LdapSession::create(move |ctx| {
            let (r, w) = tokio::io::split(msg.0);
            LdapSession::add_stream(FramedRead::new(r, LdapServerCodec), ctx);
            LdapSession::new(actix::io::FramedWrite::new(w, LdapServerCodec, ctx))
        });
    }
}

#[actix_rt::main]
async fn main() {
    let addr = net::SocketAddr::from_str("127.0.0.1:12345").unwrap();
    let listener = Box::new(TcpListener::bind(&addr).await.unwrap());

    LdapServer::create(move |ctx| {
        ctx.add_message_stream(Box::leak(listener).incoming().map(|st| {
            let st = st.unwrap();
            let addr = st.peer_addr().unwrap();
            TcpConnect(st, addr)
        }));
        LdapServer {}
    });

    println!("ldap://127.0.0.1:12345");

    tokio::signal::ctrl_c().await.unwrap();
    System::current().stop();
}

use actix::prelude::*;
use futures_util::stream::StreamExt;
use ldap3_server::simple::*;
use ldap3_server::LdapCodec;
use std::convert::TryFrom;
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
    framed: actix::io::FramedWrite<WriteHalf<TcpStream>, LdapCodec>,
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
                self.framed.write(DisconnectionNotice::gen(
                    LdapResultCode::Other,
                    "Internal Server Error",
                ));
                ctx.stop();
                return;
            }
        };

        let server_op = match ServerOps::try_from(msg) {
            Ok(v) => v,
            Err(_) => {
                self.framed.write(DisconnectionNotice::gen(
                    LdapResultCode::ProtocolError,
                    "Invalid Request",
                ));
                ctx.stop();
                return;
            }
        };

        let resp = match server_op {
            ServerOps::SimpleBind(sbr) => vec![self.do_bind(&sbr)],
            ServerOps::Search(sr) => self.do_search(&sr),
            ServerOps::Unbind(_) => {
                // No need to notify on unbind (per rfc4511)
                ctx.stop();
                return;
            }
            ServerOps::Whoami(wr) => vec![self.do_whoami(&wr)],
        };
        resp.into_iter().for_each(|msg| self.framed.write(msg))
    }
}

impl LdapSession {
    pub fn new(framed: actix::io::FramedWrite<WriteHalf<TcpStream>, LdapCodec>) -> Self {
        LdapSession {
            dn: "Anonymous".to_string(),
            framed,
        }
    }

    pub fn do_bind(&mut self, sbr: &SimpleBindRequest) -> LdapMsg {
        if sbr.dn == "cn=Directory Manager" && sbr.pw == "password" {
            self.dn = sbr.dn.to_string();
            sbr.gen_success()
        } else if sbr.dn == "" && sbr.pw == "" {
            self.dn = "Anonymous".to_string();
            sbr.gen_success()
        } else {
            sbr.gen_invalid_cred()
        }
    }

    pub fn do_search(&mut self, lsr: &SearchRequest) -> Vec<LdapMsg> {
        vec![
            lsr.gen_result_entry(LdapSearchResultEntry {
                dn: "cn=hello,dc=example,dc=com".to_string(),
                attributes: vec![
                    LdapPartialAttribute {
                        atype: "objectClass".to_string(),
                        vals: vec!["cursed".to_string()],
                    },
                    LdapPartialAttribute {
                        atype: "cn".to_string(),
                        vals: vec!["hello".to_string()],
                    },
                ],
            }),
            lsr.gen_result_entry(LdapSearchResultEntry {
                dn: "cn=world,dc=example,dc=com".to_string(),
                attributes: vec![
                    LdapPartialAttribute {
                        atype: "objectClass".to_string(),
                        vals: vec!["cursed".to_string()],
                    },
                    LdapPartialAttribute {
                        atype: "cn".to_string(),
                        vals: vec!["world".to_string()],
                    },
                ],
            }),
            lsr.gen_success(),
        ]
    }

    pub fn do_whoami(&mut self, wr: &WhoamiRequest) -> LdapMsg {
        wr.gen_success(format!("dn: {}", self.dn).as_str())
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
            LdapSession::add_stream(FramedRead::new(r, LdapCodec), ctx);
            LdapSession::new(actix::io::FramedWrite::new(w, LdapCodec, ctx))
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

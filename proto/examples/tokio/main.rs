#[macro_use]
extern crate tracing;

use tokio::net::{TcpListener, TcpStream};
// use tokio::stream::StreamExt;
use futures::SinkExt;
use futures::StreamExt;
use std::convert::TryFrom;
use std::net;
use std::str::FromStr;
use tokio_util::codec::{FramedRead, FramedWrite};

use ldap3_proto::LdapCodec;
use ldap3_proto::simple::*;

pub struct LdapSession {
    dn: String,
}

impl LdapSession {
    pub fn do_bind(&mut self, sbr: &SimpleBindRequest) -> LdapMsg {
        if sbr.dn == "cn=Directory Manager" && sbr.pw == "password" {
            self.dn = sbr.dn.to_string();
            sbr.gen_success()
        } else if sbr.dn.is_empty() && sbr.pw.is_empty() {
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
                        vals: vec!["cursed".as_bytes().to_vec()],
                    },
                    LdapPartialAttribute {
                        atype: "cn".to_string(),
                        vals: vec!["hello".as_bytes().to_vec()],
                    },
                ],
            }),
            lsr.gen_result_entry(LdapSearchResultEntry {
                dn: "cn=world,dc=example,dc=com".to_string(),
                attributes: vec![
                    LdapPartialAttribute {
                        atype: "objectClass".to_string(),
                        vals: vec!["cursed".as_bytes().to_vec()],
                    },
                    LdapPartialAttribute {
                        atype: "cn".to_string(),
                        vals: vec!["world".as_bytes().to_vec()],
                    },
                ],
            }),
            lsr.gen_success(),
        ]
    }

    pub fn do_compare(&mut self, cp: &CompareRequest) -> LdapMsg {
        cp.gen_compare_true()
    }

    pub fn do_whoami(&mut self, wr: &WhoamiRequest) -> LdapMsg {
        wr.gen_success(format!("dn: {}", self.dn).as_str())
    }
}

async fn handle_client(socket: TcpStream, _paddr: net::SocketAddr) {
    // Configure the codec etc.
    let (r, w) = tokio::io::split(socket);
    let mut reqs = FramedRead::new(r, LdapCodec::default());
    let mut resp = FramedWrite::new(w, LdapCodec::default());

    let mut session = LdapSession {
        dn: "Anonymous".to_string(),
    };

    while let Some(msg) = reqs.next().await {
        debug!(?msg, "ldap message");
        let server_op = match msg.map_err(|_e| ()).and_then(ServerOps::try_from) {
            Ok(v) => v,
            Err(_) => {
                let _err = resp
                    .send(DisconnectionNotice::gen_response(
                        LdapResultCode::Other,
                        "Internal Server Error",
                    ))
                    .await;
                let _err = resp.flush().await;
                return;
            }
        };

        let result = match server_op {
            ServerOps::SimpleBind(sbr) => vec![session.do_bind(&sbr)],
            ServerOps::Search(sr) => session.do_search(&sr),
            ServerOps::Unbind(_) => {
                // No need to notify on unbind (per rfc4511)
                return;
            }
            ServerOps::Compare(cp) => vec![session.do_compare(&cp)],
            ServerOps::Whoami(wr) => vec![session.do_whoami(&wr)],
        };

        for rmsg in result.into_iter() {
            if resp.send(rmsg).await.is_err() {
                return;
            }
        }

        if resp.flush().await.is_err() {
            return;
        }
    }
    // Client disconnected
}

async fn acceptor(listener: Box<TcpListener>) {
    loop {
        match listener.accept().await {
            Ok((socket, paddr)) => {
                tokio::spawn(handle_client(socket, paddr));
            }
            Err(_e) => {
                //pass
            }
        }
    }
}

#[tokio::main]
async fn main() -> () {
    tracing_subscriber::fmt::init();
    let addr = net::SocketAddr::from_str("127.0.0.1:12345").expect("Unable to parse address");
    let listener = Box::new(
        TcpListener::bind(&addr)
            .await
            .expect("Failed to bind to address"),
    );

    // Initiate the acceptor task.
    tokio::spawn(acceptor(listener));

    info!("started ldap://127.0.0.1:12345 ...");
    tokio::signal::ctrl_c()
        .await
        .expect("Failed to listen for ctrl_c signal");
}

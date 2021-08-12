use futures::SinkExt;
use futures::StreamExt;
use std::collections::{BTreeMap, HashMap};
use std::convert::TryFrom;
use std::net;
use std::str::FromStr;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio_util::codec::{FramedRead, FramedWrite};

use ldap3_server::simple::*;
use ldap3_server::LdapCodec;

type Attrs = HashMap<String, Vec<String>>;
type DB = BTreeMap<String, Attrs>;

pub struct LdapSession {
    dn: String,
}

fn apply_filter_to_entry(filter: &LdapFilter, attrs: &Attrs) -> bool {
    let x = match filter {
        LdapFilter::And(inner) => inner.iter().all(|f| apply_filter_to_entry(f, attrs)),
        LdapFilter::Or(inner) => inner.iter().any(|f| apply_filter_to_entry(f, attrs)),
        LdapFilter::Not(inner) => !apply_filter_to_entry(&inner, attrs),
        LdapFilter::Present(attr) => attrs.contains_key(attr.to_lowercase().as_str()),
        LdapFilter::Equality(attr, value) => attrs
            .get(attr.to_lowercase().as_str())
            .map(|v| v.contains(&value.to_lowercase()))
            .unwrap_or(false),
        LdapFilter::Substring(attr, sub) => {
            // too hard basket XD
            false
        }
    };
    eprintln!("{:?} => eval {}", filter, x);
    x
}

impl LdapSession {
    pub fn do_bind(&mut self, sbr: &SimpleBindRequest, db: &DB) -> LdapMsg {
        if db.contains_key(&sbr.dn) && sbr.pw == "password" {
            self.dn = sbr.dn.to_string();
            sbr.gen_success()
        } else if sbr.dn == "" && sbr.pw == "" {
            self.dn = "Anonymous".to_string();
            sbr.gen_success()
        } else {
            sbr.gen_invalid_cred()
        }
    }

    pub fn do_search(&mut self, lsr: &SearchRequest, db: &DB) -> Vec<LdapMsg> {
        eprintln!("{:?}", lsr);
        if lsr.base == "" {
            vec![
                lsr.gen_result_entry(LdapSearchResultEntry {
                    dn: "".to_string(),
                    attributes: vec![
                        LdapPartialAttribute {
                            atype: "objectClass".to_string(),
                            vals: vec!["top".to_string()],
                        },
                        LdapPartialAttribute {
                            atype: "vendorName".to_string(),
                            vals: vec!["Kanidm Project".to_string()],
                        },
                        LdapPartialAttribute {
                            atype: "vendorVersion".to_string(),
                            vals: vec!["ldap3_server_example".to_string()],
                        },
                        LdapPartialAttribute {
                            atype: "supportedLDAPVersion".to_string(),
                            vals: vec!["3".to_string()],
                        },
                        LdapPartialAttribute {
                            atype: "supportedExtension".to_string(),
                            vals: vec!["1.3.6.1.4.1.4203.1.11.3".to_string()],
                        },
                        LdapPartialAttribute {
                            atype: "supportedFeatures".to_string(),
                            vals: vec!["1.3.6.1.4.1.4203.1.5.1".to_string()],
                        },
                        LdapPartialAttribute {
                            atype: "defaultnamingcontext".to_string(),
                            vals: vec!["dc=example,dc=com".to_string()],
                        },
                    ],
                }),
                lsr.gen_success(),
            ]
        } else {
            db.iter()
                .filter_map(|(dn, attrs)| {
                    eprintln!(" --> {}", dn);
                    if ((lsr.scope == LdapSearchScope::Base && &lsr.base == dn)
                        || dn.ends_with(&lsr.base))
                        && apply_filter_to_entry(&lsr.filter, attrs)
                    {
                        Some(
                            lsr.gen_result_entry(LdapSearchResultEntry {
                                dn: dn.clone(),
                                attributes: attrs
                                    .iter()
                                    // Ldap is so fucken dumb. We have to return attrs in the
                                    // same capitalisation as requested. ffs.
                                    .filter_map(|(k, v)| {
                                        let nk = lsr
                                            .attrs
                                            .iter()
                                            .find(|rk| rk.to_lowercase() == k.to_lowercase())
                                            .cloned();

                                        if lsr.attrs.is_empty()
                                            || lsr.attrs.contains(&"*".to_string())
                                            || lsr.attrs.contains(&"+".to_string())
                                            || nk.is_some()
                                        {
                                            Some(LdapPartialAttribute {
                                                atype: nk.unwrap_or_else(|| k.clone()),
                                                vals: v.clone(),
                                            })
                                        } else {
                                            None
                                        }
                                    })
                                    .collect(),
                            }),
                        )
                    } else {
                        None
                    }
                })
                .chain(std::iter::once(lsr.gen_success()))
                .collect()
        }
    }

    pub fn do_whoami(&mut self, wr: &WhoamiRequest) -> LdapMsg {
        wr.gen_success(format!("dn: {}", self.dn).as_str())
    }
}

async fn handle_client(socket: TcpStream, paddr: net::SocketAddr, db: Arc<DB>) {
    eprintln!("paddr -> {:?}", paddr);
    // Configure the codec etc.
    let (r, w) = tokio::io::split(socket);
    let mut reqs = FramedRead::new(r, LdapCodec);
    let mut resp = FramedWrite::new(w, LdapCodec);

    let mut session = LdapSession {
        dn: "Anonymous".to_string(),
    };

    while let Some(msg) = reqs.next().await {
        let server_op = match msg
            .map_err(|_e| ())
            .and_then(|msg| ServerOps::try_from(msg))
        {
            Ok(v) => v,
            Err(_) => {
                let _err = resp
                    .send(DisconnectionNotice::gen(
                        LdapResultCode::Other,
                        "Internal Server Error",
                    ))
                    .await;
                let _err = resp.flush().await;
                return;
            }
        };

        let result = match server_op {
            ServerOps::SimpleBind(sbr) => vec![session.do_bind(&sbr, db.as_ref())],
            ServerOps::Search(sr) => session.do_search(&sr, db.as_ref()),
            ServerOps::Unbind(_) => {
                // No need to notify on unbind (per rfc4511)
                return;
            }
            ServerOps::Whoami(wr) => vec![session.do_whoami(&wr)],
            ServerOps::ExtendedOperation(exop) => {
                vec![exop.gen_protocolerror("")]
            }
        };

        for rmsg in result.into_iter() {
            if let Err(_) = resp.send(rmsg).await {
                return;
            }
        }

        if let Err(_) = resp.flush().await {
            return;
        }
    }
    // Client disconnected
}

async fn acceptor(db: Arc<DB>, listener: Box<TcpListener>) {
    loop {
        match listener.accept().await {
            Ok((socket, paddr)) => {
                tokio::spawn(handle_client(socket, paddr, db.clone()));
            }
            Err(_e) => {
                //pass
            }
        }
    }
}

#[tokio::main]
async fn main() -> () {
    let laddr = "0.0.0.0:3636";
    let addr = net::SocketAddr::from_str(laddr).unwrap();
    let listener = Box::new(TcpListener::bind(&addr).await.unwrap());

    // Simple Db
    let mut db = BTreeMap::new();

    // Insert some default content.
    let mut attrs = HashMap::new();
    attrs.insert(
        "objectclass".to_string(),
        vec!["top".to_string(), "domain".to_string()],
    );
    attrs.insert("dc".to_string(), vec!["example".to_string()]);
    attrs.insert(
        "entryuuid".to_string(),
        vec!["883a221d-2875-4531-8e9b-f08e0c2e91ea".to_string()],
    );
    db.insert("dc=example,dc=com".to_string(), attrs);

    let mut user = HashMap::new();
    user.insert(
        "objectclass".to_string(),
        vec!["posixaccount".to_string(), "account".to_string()],
    );
    user.insert(
        "entryuuid".to_string(),
        vec!["3e1c484b-f1b0-462c-a840-a4cf13b67e99".to_string()],
    );
    user.insert("uidnumber".to_string(), vec!["12345".to_string()]);
    user.insert("gidnumber".to_string(), vec!["12345".to_string()]);
    user.insert("gecos".to_string(), vec!["TestAccount".to_string()]);
    user.insert("uid".to_string(), vec!["testacct".to_string()]);
    user.insert("cn".to_string(), vec!["testacct".to_string()]);
    user.insert(
        "homedirectory".to_string(),
        vec!["/home/testacct".to_string()],
    );
    user.insert("loginshell".to_string(), vec!["/bin/bash".to_string()]);

    db.insert("uid=testacct,dc=example,dc=com".to_string(), user);

    // Initiate the acceptor task.
    tokio::spawn(acceptor(Arc::new(db), listener));

    println!("started ldap://{} ...", laddr);
    tokio::signal::ctrl_c().await.unwrap();
}

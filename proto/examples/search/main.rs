use std::{env, net::SocketAddr, str::FromStr, vec};

use futures_util::{SinkExt, StreamExt};
use ldap3_proto::{
    parse_ldap_filter_str,
    proto::{LdapBindCred, LdapBindRequest, LdapOp, LdapSearchRequest},
    LdapCodec, LdapMsg, LdapResultCode,
};
use tokio::net::TcpStream;
use tokio_util::codec::Framed;
use tracing::Level;

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let subs = tracing_subscriber::FmtSubscriber::builder()
        .with_max_level(Level::DEBUG)
        .finish();
    tracing::subscriber::set_global_default(subs).expect("setting default subscriber failed");

    let ldap_password = env::var("LDAP_PASSWORD").unwrap(); // password
    let ldap_server_addr = env::var("LDAP_SERVER_ADDR").unwrap(); // domain.com:port
    let ldap_username_dn = env::var("LDAP_USERNAME_DN").unwrap(); // username@domain
    let addr = SocketAddr::from_str(&ldap_server_addr)
        .unwrap_or_else(|_| panic!("Unable to parse address, addr is {:?}", &ldap_server_addr));

    let tcpstream = TcpStream::connect(addr).await?;

    let mut framed = Framed::new(tcpstream, LdapCodec::default());

    let msg = LdapMsg {
        msgid: 1,
        op: LdapOp::BindRequest(LdapBindRequest {
            dn: ldap_username_dn,
            cred: LdapBindCred::Simple(ldap_password),
        }),
        ctrl: vec![],
    };

    framed.send(msg).await?;
    loop {
        if let Some(Ok(msg)) = framed.next().await {
            if let LdapOp::BindResponse(res) = msg.op {
                match res.res.code {
                    LdapResultCode::Success => {
                        println!("Bind successful");
                        break;
                    }
                    _ => {
                        panic!("Bind failed: {:?}", res)
                    }
                }
            }
        } else {
            panic!("Unable to get bind response")
        }
    }

    let filter = parse_ldap_filter_str("(cn=*Info*)")?;
    let search_req = LdapSearchRequest {
        attrs: vec!["cn".to_string()],
        base: "CN=Schema,CN=Configuration,DC=example,DC=com".to_string(),
        filter,
        scope: ldap3_proto::LdapSearchScope::Subtree,
        sizelimit: 10,
        timelimit: 100,
        aliases: ldap3_proto::proto::LdapDerefAliases::Never,
        typesonly: true,
    };

    let msg = LdapMsg {
        ctrl: vec![],
        msgid: 1,
        op: LdapOp::SearchRequest(search_req),
    };

    framed.send(msg).await?;

    loop {
        let res = framed.next().await.expect("no meg")?;
        if let LdapOp::SearchResultDone(..) = &res.op {
            break;
        }
    }

    Ok(())
}

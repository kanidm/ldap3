use std::convert::TryFrom;
use std::net::SocketAddr;
use std::pin::Pin;
use std::str::FromStr;
use tokio::net::TcpStream;
use tokio_util::codec::Framed;

use futures_util::sink::SinkExt;
use futures_util::stream::StreamExt;

use ldap3_proto::proto::*;
use ldap3_proto::LdapCodec;

use openssl::ssl::{Ssl, SslConnector, SslMethod, SslVerifyMode};
use tokio_openssl::SslStream;

#[tokio::main]
async fn main() -> Result<(), ()> {
    let addr = SocketAddr::from_str("172.24.20.4:3636").unwrap();

    let tcpstream = TcpStream::connect(addr)
        .await
        .map_err(|e| eprintln!("Failed to connect to -> {:?}", e))?;

    // Now add TLS
    let mut tls_parms = SslConnector::builder(SslMethod::tls_client()).map_err(|e| {
        eprintln!("openssl -> {:?}", e);
    })?;
    tls_parms.set_verify(SslVerifyMode::NONE);
    let tls_parms = tls_parms.build();

    let mut tlsstream = Ssl::new(tls_parms.context())
        .and_then(|tls_obj| SslStream::new(tls_obj, tcpstream))
        .map_err(|e| {
            eprintln!("Failed to initialise TLS -> {:?}", e);
        })?;

    let _ = SslStream::connect(Pin::new(&mut tlsstream))
        .await
        .map_err(|e| {
            eprintln!("Failed to initialise TLS -> {:?}", e);
        })?;

    let mut framed = Framed::new(tlsstream, LdapCodec::default());
    // let mut framed = Framed::new(tcpstream, LdapCodec);

    let dn = "uid=demo_user,ou=people,dc=example,dc=com".to_string();
    let pw = "password".to_string();

    let msg = LdapMsg {
        msgid: 1,
        op: LdapOp::BindRequest(LdapBindRequest {
            dn,
            cred: LdapBindCred::Simple(pw),
        }),
        ctrl: vec![],
    };

    let _ = framed.send(msg).await.map_err(|e| {
        eprintln!("Unable to send bind -> {:?}", e);
    })?;

    if let Some(Ok(msg)) = framed.next().await {
        if let LdapOp::BindResponse(res) = msg.op {
            if res.res.code != LdapResultCode::Success {
                eprintln!("Failed to bind -> {:?}", res);
                return Err(());
            }
        }
    }
    println!("Bind success ✅ ");

    let pwchg = LdapPasswordModifyRequest {
        user_identity: Some("uid=demo_user,ou=people,dc=example,dc=com".to_string()),
        old_password: Some("password".to_string()),
        // new_password: Some("password".to_string()),
        new_password: None,
    };

    // Now try to change password.
    let msg = LdapMsg {
        msgid: 2,
        op: LdapOp::ExtendedRequest(pwchg.into()),
        ctrl: vec![],
    };

    let _ = framed.send(msg).await.map_err(|e| {
        eprintln!("Unable to send pwchg -> {:?}", e);
    })?;

    if let Some(Ok(msg)) = framed.next().await {
        if let LdapOp::ExtendedResponse(res) = msg.op {
            if res.res.code != LdapResultCode::Success {
                eprintln!("Failed to pwchg -> {:?}", res);
                return Err(());
            } else {
                // eprintln!("pwchg -> {:?}", res);
                if res.value.is_some() {
                    let lpmr = LdapPasswordModifyResponse::try_from(&res)
                        .expect("Failed to decode response.");
                    println!("New Password -> {:?}", lpmr.gen_password.unwrap());
                }
            }
        }
    }
    println!("PwChg success ✅ ");

    Ok(())
}

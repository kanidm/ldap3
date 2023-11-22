use core::panic;
use futures_util::future::err;
use sspi::builders::EmptyInitializeSecurityContext;
use sspi::AuthIdentity;
use sspi::ClientRequestFlags;
use sspi::CredentialUse;
use sspi::DataRepresentation;
use sspi::Ntlm;
use sspi::SecurityBuffer;
use sspi::SecurityBufferType;
use sspi::SecurityStatus;
use sspi::Sspi;
use sspi::SspiImpl;
use sspi::Username;
use std::env;
use std::net::SocketAddr;
use std::str::FromStr;
use tokio::net::TcpStream;
use tokio_util::codec::Framed;
use tracing::Level;

use futures_util::sink::SinkExt;
use futures_util::stream::StreamExt;

use ldap3_proto::proto::*;
use ldap3_proto::LdapCodec;

#[tokio::main]
async fn main() -> Result<(), ()> {
    let subs = tracing_subscriber::FmtSubscriber::builder()
        .with_max_level(Level::DEBUG)
        .finish();
    tracing::subscriber::set_global_default(subs).expect("setting default subscriber failed");

    let ldap_password = env::var("LDAP_PASSWORD").unwrap(); // password
    let ldap_server_addr = env::var("LDAP_SERVER_ADDR").unwrap(); // domain.com:port
    let ldap_username = env::var("LDAP_USERNAME").unwrap(); // username@domain
    let addr = SocketAddr::from_str(&ldap_server_addr).expect(&format!(
        "Unable to parse address, addr is {:?}",
        &ldap_server_addr
    ));

    let tcpstream = TcpStream::connect(addr)
        .await
        .map_err(|e| eprintln!("Failed to connect to -> {:?}", e))?;

    let mut framed = Framed::new(tcpstream, LdapCodec::default());

    let mut ntlm = AuthProvier::new(&ldap_username, &ldap_password);
    let ntlm_token = ntlm.step(&[]).unwrap();

    let msg = LdapMsg {
        msgid: 1,
        op: LdapOp::BindRequest(LdapBindRequest {
            dn: "".to_string(),
            cred: LdapBindCred::SASL(SaslCredentials {
                mechanism: "GSS-SPNEGO".to_string(),
                credentials: ntlm_token,
            }),
        }),
        ctrl: vec![],
    };

    let _ = framed.send(msg).await.map_err(|e| {
        eprintln!("Unable to send bind -> {:?}", e);
    })?;
    loop {
        if let Some(Ok(msg)) = dbg!(framed.next().await) {
            if let LdapOp::BindResponse(res) = dbg!(msg.op) {
                if res.res.code == LdapResultCode::Success {
                    break;
                } else if res.res.code == LdapResultCode::SaslBindInProgress {
                    if let Some(ref cred) = res.saslcreds {
                        let ntlm_token = ntlm.step(cred).unwrap();
                        let msg = LdapMsg {
                            msgid: 2,
                            op: LdapOp::BindRequest(LdapBindRequest {
                                dn: "".to_string(),
                                cred: LdapBindCred::SASL(SaslCredentials {
                                    mechanism: "GSS-SPNEGO".to_string(),
                                    credentials: ntlm_token,
                                }),
                            }),
                            ctrl: vec![],
                        };

                        let _ = framed.send(msg).await.map_err(|e| {
                            eprintln!("Unable to send bind -> {:?}", e);
                        })?;
                    }
                    dbg!(res);
                } else {
                    panic!("Bind failed: {:?}", res)
                }
            }
        } else {
            panic!("Unable to get bind response")
        }
    }

    print!("Bind successful");
    Ok(())
}

struct AuthProvier {
    ntlm: Ntlm,
    credentials_handle: <Ntlm as SspiImpl>::CredentialsHandle,
}

impl AuthProvier {
    fn new(ldap_username: &str, ldap_password: &str) -> Self {
        let identity = AuthIdentity {
            username: Username::parse(ldap_username).unwrap(),
            password: ldap_password.to_string().into(),
        };

        let mut ntlm = Ntlm::new();

        let acq_cred_result = ntlm
            .acquire_credentials_handle()
            .with_credential_use(CredentialUse::Outbound)
            .with_auth_data(&identity)
            .execute()
            .unwrap();

        Self {
            ntlm,
            credentials_handle: acq_cred_result.credentials_handle,
        }
    }

    fn step(&mut self, input: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut output_buffer = vec![SecurityBuffer::new(Vec::new(), SecurityBufferType::Token)];

        let mut input_buffer = vec![SecurityBuffer::new(
            input.to_vec().clone(),
            SecurityBufferType::Token,
        )];
        let mut builder =
            EmptyInitializeSecurityContext::<<Ntlm as SspiImpl>::CredentialsHandle>::new()
                .with_credentials_handle(&mut self.credentials_handle)
                .with_context_requirements(
                    ClientRequestFlags::CONFIDENTIALITY | ClientRequestFlags::ALLOCATE_MEMORY,
                )
                .with_target_data_representation(DataRepresentation::Native)
                .with_target_name("ldap/ldapserver.domain.com")
                .with_input(&mut input_buffer)
                .with_output(&mut output_buffer);

        let result = self
            .ntlm
            .initialize_security_context_impl(&mut builder)
            .resolve_to_result()?;

        if [
            SecurityStatus::CompleteAndContinue,
            SecurityStatus::CompleteNeeded,
        ]
        .contains(&result.status)
        {
            println!("Completing the token...");
            self.ntlm.complete_auth_token(&mut output_buffer)?;
        }

        Ok(output_buffer[0].buffer.clone())
    }
}

use crate::LdapClient;
use crate::*;
use base64urlsafedata::Base64UrlSafeData;

#[derive(Debug)]
pub struct LdapSyncReplEntry {
    // pub entry_uuid: Uuid,
    pub entry: LdapEntry,
}

#[derive(Debug)]
pub struct LdapSyncRepl {
    pub cookie: Option<Base64UrlSafeData>,
    pub entries: Vec<LdapSyncReplEntry>,
    pub delete_uuids: Vec<Uuid>,
    pub present_uuids: Vec<Uuid>,
}

impl LdapClient {
    #[tracing::instrument(level = "debug", skip_all)]
    pub async fn ad_dirsync(
        &mut self,
        basedn: String,
        cookie: Option<Vec<u8>>,
    ) -> crate::LdapResult<LdapSyncRepl> {
        let msgid = self.get_next_msgid();

        let msg = LdapMsg {
            msgid,
            op: LdapOp::SearchRequest(LdapSearchRequest {
                base: basedn,
                scope: LdapSearchScope::Subtree,
                aliases: LdapDerefAliases::Never,
                sizelimit: 0,
                timelimit: 0,
                typesonly: false,
                filter: LdapFilter::Present("objectClass".to_string()),
                attrs: vec![],
            }),
            ctrl: vec![LdapControl::AdDirsync {
                flags: 0,
                max_bytes: 0,
                cookie,
            }],
        };

        self.write_transport.send(msg).await?;

        let mut entries = Vec::new();
        let delete_uuids = Vec::new();
        let present_uuids = Vec::new();

        loop {
            let mut msg = self.read_transport.next().await?;

            match msg.op {
                // Happy cases here
                LdapOp::SearchResultDone(proto::LdapResult {
                    code: LdapResultCode::Success,
                    message: _,
                    matcheddn: _,
                    referral: _,
                }) => {
                    trace!("SearchResultDone");
                    if let Some(LdapControl::AdDirsync {
                        flags: _,
                        max_bytes: _,
                        cookie,
                    }) = msg.ctrl.pop()
                    {
                        let cookie = cookie.map(Base64UrlSafeData);
                        break Ok(LdapSyncRepl {
                            cookie,
                            entries,
                            delete_uuids,
                            present_uuids,
                        });
                    } else {
                        error!("Invalid Ad Dirsync Control encountered");
                        break Err(LdapError::InvalidProtocolState);
                    }
                }
                LdapOp::SearchResultEntry(entry) => {
                    entries.push(LdapSyncReplEntry {
                        // entry_uuid,
                        // state,
                        entry: entry.into(),
                    })
                },
                LdapOp::SearchResultReference(_search_reference) => {
                    // pass
                },
                // Error cases below
                LdapOp::SearchResultDone(proto::LdapResult {
                    code,
                    message,
                    matcheddn: _,
                    referral: _,
                }) => {
                    error!(%message);
                    break Err(LdapError::from(code));
                }
                op => {
                    trace!(?op, "<<<<==== ");
                    break Err(LdapError::InvalidProtocolState);
                }
            };
        }
    }
}

use crate::LdapClient;
use crate::*;

#[derive(Debug)]
pub struct LdapSyncReplEntry {
    pub entry_uuid: Uuid,
    pub state: SyncStateValue,
    pub entry: LdapEntry,
}

#[derive(Debug)]
pub struct LdapSyncRepl {
    pub cookie: Option<String>,
    pub refresh_deletes: bool,
    pub entries: Vec<LdapSyncReplEntry>,
    pub delete_uuids: Vec<Uuid>,
    pub present_uuids: Vec<Uuid>,
}

impl LdapClient {
    #[tracing::instrument(level = "debug", skip_all)]
    pub async fn syncrepl(
        &mut self,
        basedn: String,
        cookie: Option<Vec<u8>>,
        mode: SyncRequestMode,
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
            ctrl: vec![LdapControl::SyncRequest {
                criticality: true,
                mode,
                cookie,
                reload_hint: false,
            }],
        };

        self.write_transport.send(msg).await?;

        let mut entries = Vec::new();
        let mut delete_uuids = Vec::new();
        let mut present_uuids = Vec::new();

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
                    if let Some(LdapControl::SyncDone {
                        cookie,
                        refresh_deletes,
                    }) = msg.ctrl.pop()
                    {
                        let cookie =
                            cookie.map(|bin| base64::encode_config(&bin, base64::STANDARD_NO_PAD));
                        break Ok(LdapSyncRepl {
                            cookie,
                            refresh_deletes,
                            entries,
                            delete_uuids,
                            present_uuids,
                        });
                    } else {
                        error!("Invalid Sync Control encountered");
                        break Err(LdapError::InvalidProtocolState);
                    }
                }
                LdapOp::IntermediateResponse(LdapIntermediateResponse::SyncInfoIdSet {
                    cookie: _,
                    refresh_deletes,
                    syncuuids,
                }) => {
                    trace!(?refresh_deletes, ?syncuuids);
                    //  Multiple empty entries with a Sync State Control of state delete
                    // SHOULD be coalesced into one or more Sync Info Messages of syncIdSet
                    // value with refreshDeletes set to TRUE.  syncUUIDs contain a set of
                    // UUIDs of the entries and references that have been deleted from the
                    // content since the last Sync Operation.  syncUUIDs may be empty.  The
                    // Sync Info Message of syncIdSet may contain a cookie to represent the
                    // state of the content after performing the synchronization of the
                    // entries in the set.
                    if refresh_deletes {
                        delete_uuids.extend(syncuuids.into_iter())
                    } else {
                        present_uuids.extend(syncuuids.into_iter())
                    }
                }
                LdapOp::IntermediateResponse(LdapIntermediateResponse::SyncInfoRefreshDelete {
                    cookie: _,
                    done: false,
                }) => {
                    // These are no-ops that are skipped for our purposes
                    // They are intended to deliniate the seperate phases, but we actually don't
                    // care until we get the search result done.
                }
                LdapOp::IntermediateResponse(
                    LdapIntermediateResponse::SyncInfoRefreshPresent {
                        cookie: _,
                        done: false,
                    },
                ) => {
                    // These are no-ops that are skipped for our purposes
                    // They are intended to deliniate the seperate phases, but we actually don't
                    // care until we get the search result done.
                }
                LdapOp::SearchResultEntry(entry) => {
                    if let Some(LdapControl::SyncState {
                        state,
                        entry_uuid,
                        cookie,
                    }) = msg.ctrl.pop()
                    {
                        if let Some(cookie) = cookie {
                            trace!(?cookie);
                        }
                        entries.push(LdapSyncReplEntry {
                            entry_uuid,
                            state,
                            entry: entry.into(),
                        })
                    } else {
                        error!("Invalid Sync Control encountered");
                        break Err(LdapError::InvalidProtocolState);
                    }
                }
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

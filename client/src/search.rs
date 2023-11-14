use crate::LdapClient;
use crate::*;

#[derive(Debug)]
pub struct LdapSearchResult {
    pub entries: Vec<LdapEntry>,
}

impl LdapClient {
    #[tracing::instrument(level = "debug", skip_all)]
    pub async fn search(
        &mut self,
        basedn: String,
        filter: LdapFilter,
    ) -> crate::LdapResult<LdapSearchResult> {
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
                filter,
                attrs: vec!["*".to_string(), "+".to_string()],
            }),
            ctrl: vec![],
        };

        self.write_transport.send(msg).await?;

        let mut entries: Vec<LdapEntry> = Vec::new();

        loop {
            let msg = self.read_transport.next().await?;

            match msg.op {
                // Happy cases here
                LdapOp::SearchResultDone(proto::LdapResult {
                    code: LdapResultCode::Success,
                    message: _,
                    matcheddn: _,
                    referral: _,
                }) => {
                    trace!("SearchResultDone");
                    break Ok(LdapSearchResult { entries });
                }
                LdapOp::SearchResultEntry(entry) => {
                    entries.push(entry.into());
                }
                // Error cases below
                LdapOp::SearchResultReference(_) => {
                    //pass
                }
                LdapOp::SearchResultDone(proto::LdapResult {
                    code,
                    message,
                    matcheddn: _,
                    referral: _,
                }) => {
                    error!(%message);
                    break Err(LdapError::from(code));
                },
                op => {
                    trace!(?op, "<<<<==== ");
                    break Err(LdapError::InvalidProtocolState);
                }
            };
        }
    }
}

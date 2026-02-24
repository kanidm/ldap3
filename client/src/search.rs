use std::future::{Future, IntoFuture};

use crate::LdapClient;
use crate::*;

#[derive(Debug)]
pub struct LdapSearchResult {
    pub entries: Vec<LdapEntry>,
}

impl LdapClient {
    pub fn search(&mut self, basedn: impl Into<String>, filter: LdapFilter) -> SearchBuilder<'_> {
        SearchBuilder {
            client: self,
            basedn: basedn.into(),
            filter,
            scope: LdapSearchScope::Subtree,
            attrs: vec![String::from("*"), String::from("+")],
        }
    }
}

#[derive(Debug)]
pub struct SearchBuilder<'c> {
    client: &'c mut LdapClient,
    basedn: String,
    filter: LdapFilter,
    scope: LdapSearchScope,
    attrs: Vec<String>,
}

impl SearchBuilder<'_> {
    pub fn scope(self, scope: LdapSearchScope) -> Self {
        Self { scope, ..self }
    }

    pub fn attrs(self, attrs: impl IntoIterator<Item: Into<String>>) -> Self {
        Self {
            attrs: attrs.into_iter().map(Into::into).collect(),
            ..self
        }
    }

    #[tracing::instrument(name = "search", level = "debug", skip_all)]
    pub async fn send(self) -> crate::LdapResult<LdapSearchResult> {
        let msgid = self.client.get_next_msgid();

        let msg = LdapMsg {
            msgid,
            op: LdapOp::SearchRequest(LdapSearchRequest {
                base: self.basedn,
                scope: self.scope,
                aliases: LdapDerefAliases::Never,
                sizelimit: 0,
                timelimit: 0,
                typesonly: false,
                filter: self.filter,
                attrs: self.attrs,
            }),
            ctrl: vec![],
        };

        self.client.write_transport.send(msg).await?;

        let mut entries: Vec<LdapEntry> = Vec::new();

        loop {
            let msg = self.client.read_transport.next().await?;

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
                }
                op => {
                    trace!(?op, "<<<<==== ");
                    break Err(LdapError::InvalidProtocolState);
                }
            };
        }
    }
}

// this implementation allows for .await on a SearchBuilder
impl<'c> IntoFuture for SearchBuilder<'c> {
    type Output = crate::LdapResult<LdapSearchResult>;

    // FIXME: donnot box future when it is possible to name future from Self::send
    // type IntoFuture = Self::send(..);
    type IntoFuture = std::pin::Pin<Box<dyn Future<Output = Self::Output> + Send + Sync + 'c>>;

    fn into_future(self) -> Self::IntoFuture {
        Box::pin(self.send())
    }
}

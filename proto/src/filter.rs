//! LDAP Filter Parser

use crate::LdapFilter;
use nom::character::complete;
use nom::sequence::{delimited, separated_pair};

use nom::bytes::complete::is_not;

fn expr_parser<'a>(f: &'a str) -> nom::IResult<&'a str, LdapFilter> {
    // We have some inner expression. Can we match what it is?
    separated_pair(is_not("="), complete::char('='), complete::char('*'))(f).map(
        |(rem, (pres_attr, _))| {
            trace!(?pres_attr);
            (rem, LdapFilter::Present(pres_attr.to_string()))
        },
    )
}

pub fn parse_ldap_filter_str(f: &str) -> Result<LdapFilter, ()> {
    delimited(complete::char('('), expr_parser, complete::char(')'))(f)
        .map(|(rem, filter)| {
            trace!(%rem);
            filter
        })
        .map_err(|e| {
            error!(?e, "Unable to parse LDAP Filter");
        })
}

#[cfg(test)]
mod test {
    use super::parse_ldap_filter_str;
    use crate::LdapFilter;

    #[test]
    fn test_objectclass_pres() {
        let _ = tracing_subscriber::fmt::try_init();
        let f = parse_ldap_filter_str("(objectClass=*)").expect("Failed to parse filter");

        assert!(f == LdapFilter::Present("objectClass".to_string()));
    }
}

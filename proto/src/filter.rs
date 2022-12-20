//! LDAP Filter Parser

use crate::LdapFilter;

lalrpop_mod!(pub ldapfilter);

pub fn parse_ldap_filter_str(f: &str) -> Result<LdapFilter, ()> {
    ldapfilter::TermParser::new()
        .parse(f)
        .map(|filter| {
            trace!(?filter);
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
    fn test_ldapfilter_pres() {
        let f = parse_ldap_filter_str("(objectClass=*)").expect("Failed to parse filter");
        assert!(f == LdapFilter::Present("objectClass".to_string()));
    }

    #[test]
    fn test_ldapfilter_eq() {
        let f = parse_ldap_filter_str("(objectClass=test)").expect("Failed to parse filter");
        assert!(f == LdapFilter::Equality("objectClass".to_string(), "test".to_string()));
    }

    #[test]
    fn test_ldapfilter_gte() {
        let f = parse_ldap_filter_str("(objectClass>=test)").expect("Failed to parse filter");
        assert!(f == LdapFilter::GreaterOrEqual("objectClass".to_string(), "test".to_string()));
    }

    #[test]
    fn test_ldapfilter_lte() {
        let f = parse_ldap_filter_str("(objectClass<=test)").expect("Failed to parse filter");
        assert!(f == LdapFilter::LessOrEqual("objectClass".to_string(), "test".to_string()));
    }

    #[test]
    fn test_ldapfilter_approx() {
        let f = parse_ldap_filter_str("(objectClass~=test)").expect("Failed to parse filter");
        assert!(f == LdapFilter::Approx("objectClass".to_string(), "test".to_string()));
    }

    #[test]
    fn test_ldapfilter_not() {
        let f = parse_ldap_filter_str("(!(objectClass=test))").expect("Failed to parse filter");
        assert!(
            f == LdapFilter::Not(Box::new(LdapFilter::Equality(
                "objectClass".to_string(),
                "test".to_string()
            )))
        );
    }

    #[test]
    fn test_ldapfilter_and() {
        let f = parse_ldap_filter_str("(&(objectClass=*))").expect("Failed to parse filter");
        assert!(f == LdapFilter::And(vec![LdapFilter::Present("objectClass".to_string())]));

        let f = parse_ldap_filter_str("(&(objectClass=*)(uid=*))").expect("Failed to parse filter");
        assert!(
            f == LdapFilter::And(vec![
                LdapFilter::Present("objectClass".to_string()),
                LdapFilter::Present("uid".to_string())
            ])
        );
    }

    #[test]
    fn test_ldapfilter_or() {
        let f = parse_ldap_filter_str("(|(objectClass=*))").expect("Failed to parse filter");
        assert!(f == LdapFilter::Or(vec![LdapFilter::Present("objectClass".to_string())]));

        let f = parse_ldap_filter_str("(|(objectClass=*)(uid=*))").expect("Failed to parse filter");
        assert!(
            f == LdapFilter::Or(vec![
                LdapFilter::Present("objectClass".to_string()),
                LdapFilter::Present("uid".to_string())
            ])
        );
    }

    #[test]
    fn test_ldapfilter_nested() {
        let f = parse_ldap_filter_str("(|(&(objectClass=*)(uid=*)(!(cn=foo)))(&(a=b)(|(b=c))))")
            .expect("Failed to parse filter");
        assert!(
            f == LdapFilter::Or(vec![
                LdapFilter::And(vec![
                    LdapFilter::Present("objectClass".to_string()),
                    LdapFilter::Present("uid".to_string()),
                    LdapFilter::Not(Box::new(LdapFilter::Equality(
                        "cn".to_string(),
                        "foo".to_string()
                    )))
                ]),
                LdapFilter::And(vec![
                    LdapFilter::Equality("a".to_string(), "b".to_string()),
                    LdapFilter::Or(vec![LdapFilter::Equality("b".to_string(), "c".to_string()),])
                ]),
            ])
        );
    }
}

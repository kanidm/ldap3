//! LDAP Filter Parser

use crate::LdapFilter;

lalrpop_mod!(pub ldapfilter);

pub fn parse_ldap_filter_str(f: &str) -> Result<LdapFilter, ()> {
    ldapfilter::TermParser::new().parse(f)
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
    fn test_objectclass_pres() {
        let _ = tracing_subscriber::fmt::try_init();
        let f = parse_ldap_filter_str("(objectClass=*)").expect("Failed to parse filter");
        eprintln!("{:?}", f);
        assert!(f == LdapFilter::Present("objectClass".to_string()));
    }

    #[test]
    fn test_objectclass_eq() {
        let _ = tracing_subscriber::fmt::try_init();
        let f = parse_ldap_filter_str("(objectClass=test)").expect("Failed to parse filter");
        eprintln!("{:?}", f);
        assert!(f == LdapFilter::Equality("objectClass".to_string(), "test".to_string()));
    }

    #[test]
    fn test_objectclass_not() {
        let _ = tracing_subscriber::fmt::try_init();
        let f = parse_ldap_filter_str("(!(objectClass=test))").expect("Failed to parse filter");
        eprintln!("{:?}", f);
        assert!(f == 
            LdapFilter::Not(
                Box::new(LdapFilter::Equality("objectClass".to_string(), "test".to_string())))
        );
    }

    #[test]
    fn test_objectclass_and() {
        let _ = tracing_subscriber::fmt::try_init();
        let f = parse_ldap_filter_str("(&(objectClass=*))").expect("Failed to parse filter");
        eprintln!("{:?}", f);
        assert!(f == 
            LdapFilter::And(vec![
            LdapFilter::Present("objectClass".to_string())
            ])
        );

        let f = parse_ldap_filter_str("(&(objectClass=*)(uid=*))").expect("Failed to parse filter");
        eprintln!("{:?}", f);
        assert!(f == 
            LdapFilter::And(vec![
            LdapFilter::Present("objectClass".to_string()),
            LdapFilter::Present("uid".to_string())
            ])
        );
    }

    #[test]
    fn test_objectclass_or() {
        let _ = tracing_subscriber::fmt::try_init();
        let f = parse_ldap_filter_str("(|(objectClass=*))").expect("Failed to parse filter");
        eprintln!("{:?}", f);
        assert!(f == 
            LdapFilter::Or(vec![
            LdapFilter::Present("objectClass".to_string())
            ])
        );

        let f = parse_ldap_filter_str("(|(objectClass=*)(uid=*))").expect("Failed to parse filter");
        eprintln!("{:?}", f);
        assert!(f == 
            LdapFilter::Or(vec![
            LdapFilter::Present("objectClass".to_string()),
            LdapFilter::Present("uid".to_string())
            ])
        );
    }

}

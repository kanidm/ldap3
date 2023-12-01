//! LDAP Filter Parser

use crate::{proto::LdapSubstringFilter, LdapFilter};

peg::parser! {
    pub(crate) grammar ldapfilter() for str {

        pub rule parse() -> LdapFilter =
            separator()* "(" e:term() ")" separator()* { e }

        rule term() -> LdapFilter =
            not()
            / and()
            / or()
            // / pres()
            / gte()
            / lte()
            / approx()
            / eq()

        rule not() -> LdapFilter =
            separator()* "!" f:parse() { LdapFilter::Not(Box::new(f)) }

        rule and() -> LdapFilter =
            separator()* "&" v:(parse()+) { LdapFilter::And(v) }

        rule or() -> LdapFilter =
            separator()* "|" v:(parse()+) { LdapFilter::Or(v) }

        rule gte() -> LdapFilter =
            a:attr() ">=" v:value() { LdapFilter::GreaterOrEqual(a, v) }

        rule lte() -> LdapFilter =
            a:attr() "<=" v:value() { LdapFilter::LessOrEqual(a, v) }

        rule approx() -> LdapFilter =
            a:attr() "~=" v:value() { LdapFilter::Approx(a, v) }

        rule eq() -> LdapFilter =
            a:attr() "=" v:value() {
                if v == "*"{
                    LdapFilter::Present(a)
                }
                 else if !v.contains('*') {
                    LdapFilter::Equality(a, v)
                }else{
                    let substring_filter :LdapSubstringFilter = v.into();
                    LdapFilter::Substring(a, substring_filter)
                }
            }


        rule separator()
          = ['\n' | ' ' | '\t' ]

        rule operator()
          = ['='  | '\n' | ' ' | '\t' | '(' | ')' | '~' | '>' | '<' | '!' | '&' | '|' ]

        rule attr() -> String =
            separator()* s:attrdesc() separator()* { s }

        rule value() -> String =
            separator()* s:octetstr() separator()* { s }

        // Should this actually be vec<u8>?
        // Probably isn't rfc compliant, but we have to avoid special chars unless quoted.
        pub(crate) rule octetstr() -> String =
            quotedoctetstr() / bareoctetstr()

        rule quotedoctetstr() -> String =
            "\"" s:$((!"\""[_])*) "\"" { s.to_string() }

        rule bareoctetstr() -> String =
            s:$((!operator()[_])*) { s.to_string() }

        // Per the rfc this also could be an oid with types/options, but lazy for now.
        pub(crate) rule attrdesc() -> String =
            a:descr()



        // descr is:
        //   keystring = leadkeychar *keychar
        //   leadkeychar = ALPHA
        //   keychar = ALPHA / DIGIT / HYPHEN
        rule descr() -> String =
            s:$([ 'a'..='z' | 'A'..='Z']['a'..='z' | 'A'..='Z' | '0'..='9' | '-' ]*) { s.to_string() }
    }
}

pub fn parse_ldap_filter_str(
    f: &str,
) -> Result<LdapFilter, peg::error::ParseError<peg::str::LineCol>> {
    ldapfilter::parse(f)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::LdapFilter;

    #[test]
    fn test_attrdesc() {
        assert_eq!(ldapfilter::attrdesc("abcd"), Ok("abcd".to_string()));
        assert_eq!(ldapfilter::attrdesc("a-b-1-d"), Ok("a-b-1-d".to_string()));

        // can't be 0 char
        assert!(ldapfilter::attrdesc("").is_err());
        // can't start with num or -
        assert!(ldapfilter::attrdesc("-abcd").is_err());
        assert!(ldapfilter::attrdesc("1abcd").is_err());
    }

    #[test]
    fn test_octetstr() {
        assert_eq!(ldapfilter::octetstr("abcd"), Ok("abcd".to_string()));
        // Can't be empty.
        assert!(ldapfilter::attrdesc("").is_err());
        // Fails with operator chars
        assert!(ldapfilter::attrdesc("*").is_err());
        assert!(ldapfilter::attrdesc("a=b").is_err());

        // works when quoted
        assert_eq!(ldapfilter::octetstr("\"*\""), Ok("*".to_string()));
        assert_eq!(
            ldapfilter::octetstr("\"lol=lol\""),
            Ok("lol=lol".to_string())
        );
    }

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

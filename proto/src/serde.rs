
use crate::filter::ldapfilter;
use crate::proto::LdapFilter;
use std::fmt;

use serde::{
    de,
    Deserialize, Deserializer
};


impl<'de> Deserialize<'de> for LdapFilter {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        fn de_error<E: de::Error>(e: peg::error::ParseError<peg::str::LineCol>) -> E {
            E::custom(format_args!("LdapFilter parsing failed: {}", e))
        }

        struct LdapFilterVisitor;

        impl<'vi> de::Visitor<'vi> for LdapFilterVisitor {
            type Value = LdapFilter;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, "an LDAP Filter")
            }

            fn visit_str<E: de::Error>(self, value: &str) -> Result<LdapFilter, E> {
                ldapfilter::parse(value).map_err(de_error)
            }
        }

        deserializer.deserialize_str(LdapFilterVisitor)
    }
}




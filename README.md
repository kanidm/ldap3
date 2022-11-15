# Ldap3 Protocol Bindings and Async Client

This is a work-in-progress of LDAP3 protocol bindings and an async client library.

This is *not* an LDAP3 server - it is the required parts to allow you to build one
using a TCP/TLS server. You will and should develop your own state machine, and
should consider the many security risks of LDAP3 such as filter stack limits,
request sizelimits, number of entries limited in results, binds and how you
check access controls, and more.

## Structure

### Proto

This library contains all the needed protocol bindings, mapped to their BER structures
in `proto`, as well as a set of `simple` wrappers of common operations required for
a server, discarding many of the esoteric options that are generally not required.

### Client

The client is a tokio based async client library. It is still in development, so not
all features are supported.

### Cli

This is a thin wrapper over the async client for minimal usage and testing.

## Protocol Support ScoreCard

| name | from rfc | implemented? |
| ---- | -------- | ------------ |
| bind | rfc4511  | ✅ (only simple bind will be supported) |
| unbind | rfc4511 | ✅ |
| search | rfc4511 | ✅ |
| filter | rfc4511 | 🔨 (excluding ge, le, aprx, ext) |
| modify | rfc4511 | ✅ |
| add | rfc4511 | ✅ |
| delete | rfc4511 | ✅ |
| modRDN | rfc4511 | ✅ |
| compare | rfc4511 | ❌ |
| abandon | rfc4511 | ✅ |
| extended | rfc4511 | ✅ (may need extension) |
| whoami | rfc4532 | ✅ |
| disconnection notice | rfc4511 | ✅ |
| content sync | rfc4533 | ✅ |

## Things we won't add

StartTLS has a number of security issues compared to LDAPS, and should *not* be used, or developed
as it is not only more complex, but also worse than LDAPS. Use LDAPS.

SASL is extremely complicated, and there are very few clients that require it over simple bind. It's
not really worth the time to add it. If it is contributed, I will only accept SASL as an
authentication mechanism - I won't accept the SASL transport encryption layer, as it's just
too complicated. Again, use LDAPS.

## Notes:

LDAP - the trashfire we have, not the trashfire we want.


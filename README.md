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
| bind | rfc4511  | ✅ (Support Both Simple and SASL bind (Security Providers Not included), see below) |
| unbind | rfc4511 | ✅ |
| search | rfc4511 | ✅ |
| filter | rfc4511 | ✅ |
| modify | rfc4511 | ✅ |
| add | rfc4511 | ✅ |
| delete | rfc4511 | ✅ |
| modRDN | rfc4511 | ✅ |
| compare | rfc4511 | ✅ |
| abandon | rfc4511 | ✅ |
| extended | rfc4511 | ✅ (may need extension) |
| whoami | rfc4532 | ✅ |
| disconnection notice | rfc4511 | ✅ |
| content sync | rfc4533 | ✅ |

## Things we won't add

StartTLS has a number of security issues compared to LDAPS, and should *not* be used, or developed
as it is not only more complex, but also worse than LDAPS. Use LDAPS.

SASL is highly complex, and only a few clients require it over a simple bind.
Our support is limited to the SASL binding authentication interface, 
for which an example is available under the './proto' crate.
Users are free to choose any security provider they prefer. 
However, we do not support the SASL transport encryption layer or any implementations of security providers,
as these are overly complicated and do not align with our crate's objectives. If encryption is a necessity, we recommend using LDAPS instead.

## Notes:

LDAP - the trashfire we have, not the trashfire we want.


# Ldap3 Server (Protocol Bindings)

This is a work-in-progress of LDAP3 server and client capable protocol bindings.

This is *not* and LDAP3 server - it is the required parts to allow you to build one
using a TCP server. You will and should develop your own server state machine, and
should consider the many security risks of LDAP3 such as filter stack limits,
request sizelimits, number of entries limited in results, binds and how you
check access controls, and more.

## Examples

There is an example, hardcoded server using Actix in `examples`

## ScoreCard

| name | from rfc | implemented? |
| ---- | -------- | ------------ |
| bind | rfc4511  | ✅ (only simple bind) |
| unbind | rfc4511 | ✅ |
| search | rfc4511 | ✅ |
| filter | rfc4511 | 🔨 (excluding sub, ge, le, aprx, ext) |
| modify | rfc4511 | ❌ |
| add | rfc4511 | ❌ |
| delete | rfc4511 | ❌ |
| modRDN | rfc4511 | ❌ |
| compare | rfc4511 | ❌ |
| abandon | rfc4511 | ❌ |
| extended | rfc4511 | ✅ (may need changes) |
| whoami | rfc4532 | ✅ |

## Things we probably won't add

I have no interest in adding StartTLS or SASL support.

StartTLS has a number of security issues compared to LDAPS, and should *not* be used, or developed
as it is not only more complex, but also worse than LDAPS. Use LDAPS.

SASL is extremely complicated, and there are very few clients that require it over simple bind. It's
not really worth the time to add it - if someone contributes it, great! But I won't be actively
pursuing it.

## Notes:

LDAP - the trashfire we have, not the trashfire we want.

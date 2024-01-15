# Doing a release

Make sure you've done all the tests and clippying and things.

## Checks

Fix (what you can) for outdated packages:

```shell
cargo audit
```

## Release order

```shell
cargo publish -p "ldap3_proto"
cargo publish -p "ldap3_client"
cargo publish -p "ldap3_cli"
```

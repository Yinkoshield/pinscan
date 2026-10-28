# Drop your research CA here

This directory is where the module picks up the CA(s) to trust. It ships empty
on purpose — pinscan never bundles a CA.

Place your research CA here named by its OpenSSL `subject_hash_old`, i.e.
`<hash>.0`. That is exactly what `pinscan ca-module` already produces:

```sh
pinscan ca-module -o /tmp/pinscan-ca
cp /tmp/pinscan-ca/system/etc/security/cacerts/*.0 ./
```

`service.sh` merges every `*.0` here with the device's real roots into the
per-app trust store at boot. See [../README.md](../README.md).

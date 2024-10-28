# Rocli

This tool converts a yaml configuration file and attestation token to Veraisons endorsements and reference values which can later be used to Veraisons provisioning.
[Islet Veraison demo](https://github.com/islet-project/islet/tree/main/examples/veraison) contains a full example showing how rocli can be used to setup a RA-TLS server with veraison as token verifier.

## Preparing Jsons for [cocli](https://github.com/veraison/cocli) to provision Veraison

### Create an config file for rocli
```yml
lang: "en-US"

tag_identity:
  id: "366D0A0A-5988-45ED-8488-2F2A544F6242"
  version: 0

entities:
  - name: "ACME Ltd."
    regid: "https://example.com"
    comid_roles:
      - tagCreator
      - creator
      - maintainer
    corim_roles:
      - manifestCreator


validity:
  not-before: "2021-12-31T00:00:00Z"
  not-after: "2025-12-31T00:00:00Z"

profiles:
  - "http://arm.com/cca/ssd/1"
  - "http://arm.com/CCA-SSD/1.0.0"

environment:
  vendor: "ACME"
  model: "ACME"
```

### Create `endorsements.json`

```sh
rocli --config demo/config.yml -o endorsements.json \
    --token demo/token/token.bin endorsements \
    --cpak demo/claims/cpak_public.pem
```

### Create `refvals.json`

```sh
rocli --config demo/config.yml -o refvals.json \
    --token demo/token/token.bin refvals
```

### Create `corim.json`

```sh
rocli --config demo/config.yml -o corim.json \
    --token demo/token/token.bin corim
```

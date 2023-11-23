## Generate certs for CA & server (optional, certs are in `server/cert`)

[https://mcilis.medium.com/how-to-create-a-server-certificate-with-configuration-using-openssl-ea3d2c4506ac](https://mcilis.medium.com/how-to-create-a-server-certificate-with-configuration-using-openssl-ea3d2c4506ac)

## Start and provison veraison
Use [rocli](https://github.sec.samsung.net/SYSSEC/rocli) tool using instructions in `rocli/demo` directory.

## Running Veraison

```
git clone https://github.com/veraison/services
git clone https://github.sec.samsung.net/SYSSEC/rocli
git clone https://github.sec.samsung.net/SYSSEC/ratls

cd services
cat ../rocli/veraison-patch | git apply

make docker-deploy
source deployments/docker/env.bash
```

### Check if its alive
```
veraison status
```
All 3 services needs to be running

### Provision values

#### Install dependencies:
```
go install github.com/veraison/corim/cocli@latest
go install github.com/veraison/ear/arc@latest
go install github.com/veraison/evcli@latest
```

#### Run provisioning
```
cd rocli/demo
./run.sh
```

It should end with with the approval from CCA_SSD_PLATFORM.

## "Reprovisioning"
### Checking what is in stores already
```
veraison stores
```

### To clear stores run:
```
veraison clear-stores
```
This is handy when uploading another reference values for the same id, as veraison might complain and crazy stuff **WILL** happen.

## Run RaTls server
```sh
cd server
cargo run -- -c cert/server.crt -k cert/server.key -p keys/pkey.jwk
```

## Run RaTls client 
```sh
cd client
cargo run -- -r root-ca.crt -t token.bin
```

## Expected result:

### Server:
```
    Finished dev [unoptimized + debuginfo] target(s) in 4.35s
     Running `target/debug/server -c cert/server.crt -k cert/server.key -p keys/pkey.jwk`
[2023-07-13T15:44:14Z INFO  server] New connection accepted
[2023-07-13T15:44:17Z DEBUG rustls::server::hs] decided upon suite TLS13_AES_256_GCM_SHA384
[2023-07-13T15:44:17Z INFO  ratls::cert_verifier] Received client CCA token:
== Realm Token cose:
Protected header               = Header { alg: Some(Assigned(ES384)), crit: [], content_type: None, key_id: [], iv: [], partial_iv: [], counter_signatures: [], rest: [] }
Unprotected header             = Header { alg: None, crit: [], content_type: None, key_id: [], iv: [], partial_iv: [], counter_signatures: [], rest: [] }
Signature                      = [536a25598b9aadbefdc435dfee855644e07fe28abe1c9f4bf525c0ffa3c34e7f19f9c9f3c5eeda0cadf8fa4599f1e0097faffd144e141ae126cecc86f90d37b7bf49c0e59c88fa10eeabda3e9001a5c67aa82c4913ba5f2a9e0925ed06029797]
== End of Realm Token cose

== Realm Token:
Realm challenge                (#10) = [77489c5a49e016107d28c7a877e97e5232f2aed10b6bf78dbdd7b6f845e5575530e82dc5864cfe19d4cdf6016ab6a53706db68bc5ee6283039b12f400385dab8]
Realm signing public key       (#44237) = [040c843c65cd15e364d9f93559fbcf4c896628446aa08631cd6e3e3a279c09878077d91577b50bcbd2ba896f56214feecbee0a4e7defddf7cf9b2f8a2482144de031da083cae341129acced6f5543e2442a45bca4244cfc6b081a5ecfe07ae8cac]
Realm initial measurement      (#44238) = [fdd82b3e2ef1da0091a3a9ce22549c4258265968d9c6487ea9886664b94a9b61]
Realm hash algo id             (#44236) = "sha-256"
Realm personalization value    (#44235) = [00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000]
Realm public key hash algo id  (#44240) = "sha-256"
Realm measurements             (#44239)
  Realm extensible measurement   (#0) = [0000000000000000000000000000000000000000000000000000000000000000]
  Realm extensible measurement   (#2) = [0000000000000000000000000000000000000000000000000000000000000000]
  Realm extensible measurement   (#1) = [0000000000000000000000000000000000000000000000000000000000000000]
  Realm extensible measurement   (#3) = [0000000000000000000000000000000000000000000000000000000000000000]
== End of Realm Token.


== Platform Token cose:
Protected header               = Header { alg: Some(Assigned(ES384)), crit: [], content_type: None, key_id: [], iv: [], partial_iv: [], counter_signatures: [], rest: [] }
Unprotected header             = Header { alg: None, crit: [], content_type: None, key_id: [], iv: [], partial_iv: [], counter_signatures: [], rest: [] }
Signature                      = [6afb300157428897bb3cdf198c5fcf93cc7505008d838520174df3612ed0613d7987d3bcaf8e1158136e3bbef1071668954b05e690bae8447aa3babd4bd9764488e2783ff009a3dc4818bc84c62d0e2f369126a81ba0b75b02c7636334ebcc7f]
== End of Platform Token cose

== Platform Token:
Lifecycle                      (#2395) = 12288
Verification service           (#2400) = "http://whatever.com"
Challange                      (#10) = [21baae2c2a77f5dfc220e548221e3456a826677d9d4ac2532a024e0f610c10b2]
Configuration                  (#2401) = [efbeadde]
Platform hash algo             (#2402) = "sha-256"
Profile                        (#265) = "http://arm.com/CCA-SSD/1.0.0"
Instance ID                    (#256) = [011be9c336d7a70b661382934a260192351ac61d24e20d882f494abee87f8a1e98]
Implementation ID              (#2396) = [aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbccccccccccccccccdddddddddddddddd]
Platform SW components         (#2399)
  SW component #0:
    SW Type                        (#1) = "BL1"
    Version                        (#4) = "0.1.0"
    Measurement value              (#2) = [697de4407dae45c07506d1f00b3dbf5ce1db41f69e1750a311f91d213e119889]
    Hash algorithm                 (#6) = "sha-256"
    Signer ID                      (#5) = [c6c32a957df4c6698c550b695d022ed5180cae71f8b49cbb75e6061c2ef497e1]
  SW component #1:
    Hash algorithm                 (#6) = "sha-512"
    Version                        (#4) = "1.9.0+0"
    Signer ID                      (#5) = [a064b1ad60fa183394dda57891357f972e4fe722782adff1854c8b2a142c0410]
    SW Type                        (#1) = "BL2"
    Measurement value              (#2) = [8e175a1dcd79b8b51ce9e259c2568305b73f5f26f5673a8cf781a94598e44f67fdf4926869ee7667e9120b5c1b97625cc96d347c23ce3c5f763bf1d9b54781f6]
== End of Platform Token

[2023-07-13T15:44:17Z DEBUG reqwest::connect] starting new connection: http://localhost:8080/
[2023-07-13T15:44:17Z INFO  veraison_verifier::verifier] Opened session with nonce /BIP8vXgU2l3UfFgLW33s7gBbFnfWPun9SNsnYO5OyE=
[2023-07-13T15:44:17Z INFO  veraison_verifier::verifier] Got verification results from Veraison
[2023-07-13T15:44:17Z INFO  veraison_verifier::verifier] Session /BIP8vXgU2l3UfFgLW33s7gBbFnfWPun9SNsnYO5OyE= deleted
[2023-07-13T15:44:17Z INFO  veraison_verifier::verifier] Submod CCA_SSD_PLATFORM affirms token
[2023-07-13T15:44:17Z INFO  veraison_verifier::verifier] Verification passed successfully
[2023-07-13T15:44:17Z INFO  server] Message from client: "GIT"
[2023-07-13T15:44:17Z INFO  server] Connection closed
```

### Client
```
    Finished dev [unoptimized + debuginfo] target(s) in 0.06s
     Running `target/debug/client -r root-ca.crt -t token.bin`
[2023-07-13T15:45:18Z DEBUG rustls::client::hs] No cached session for DnsName("localhost")
[2023-07-13T15:45:18Z DEBUG rustls::client::hs] Not resuming any session
[2023-07-13T15:45:18Z INFO  client] Connection established
[2023-07-13T15:45:18Z DEBUG rustls::client::hs] Using ciphersuite TLS13_AES_256_GCM_SHA384
[2023-07-13T15:45:18Z DEBUG rustls::client::tls13] Not resuming
[2023-07-13T15:45:18Z DEBUG rustls::client::tls13] TLS1.3 encrypted extensions: [ServerNameAck]
[2023-07-13T15:45:18Z DEBUG rustls::client::hs] ALPN protocol is None
[2023-07-13T15:45:18Z DEBUG rustls::client::tls13] Got CertificateRequest CertificateRequestPayloadTLS13 { context: , extensions: [SignatureAlgorithms([ECDSA_NISTP384_SHA384, ECDSA_NISTP256_SHA256, ED25519, RSA_PSS_SHA512, RSA_PSS_SHA384, RSA_PSS_SHA256, RSA_PKCS1_SHA512, RSA_PKCS1_SHA384, RSA_PKCS1_SHA256]), AuthorityNames([DistinguishedName(4f584e333063355937376e7a3771423067734949613359306546544366303733505268473832466864626a43686733735a326e675a556a354a475a5639524b7665315934782b5a6c38527047497a2f6d4132663443773d3d)])] }
[2023-07-13T15:45:18Z DEBUG ratls::cert_resolver] Received challenge OXN30c5Y77nz7qB0gsIIa3Y0eFTCf073PRhG82FhdbjChg3sZ2ngZUj5JGZV9RKve1Y4x+Zl8RpGIz/mA2f4Cw==
[2023-07-13T15:45:18Z DEBUG rustls::client::common] Attempting client auth
[2023-07-13T15:45:18Z INFO  client] Work finished, exiting
```

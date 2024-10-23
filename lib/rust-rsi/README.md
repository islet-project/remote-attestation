# Introduction

Rust RSI is a library containing functions/helpers to perform RSI ioctl
operations as implemented by the linux-rsi kernel module
[here](https://github.com/islet-project/islet/tree/main/realm/linux-rsi), as
well as generic functions to parse/verify/print RSI attestation tokens.

It has initially been implemeneted as part of [rsictl](../../tools/rsictl) tool
but as more applications needed similar functionality it has been split into
this library.

# Content

The library contains following functionalities:

  * low level (unsafe) Rust bindings to RSI ioctl operations as implemented
    [here](https://github.com/islet-project/islet/tree/main/realm/linux-rsi)
    (currently not exported)
  * high level (safe) functions for the above bindings that make it easy to
    perform RSI operations from the user space
  * low level RSI attestation token parser and verifier (as COSE object) into
    claims
  * high level RSI attestation token parser into more humand readable structs of
    platform and realm tokens

# Current users

The library is currently used by the following applications:

  * [rsictl](../../tools/rsictl): command line tool for performing RSI
    operations
  * [ratls](../ratls): library implementing RaTLS protocol
  * [realm-verifier](../realm-verifier): a realm verifier library for RaTLS
  * [realm-manager](https://github.com/islet-project/realm-manager): application
    provisioning framework

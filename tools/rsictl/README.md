# Introduction

This is a command line tool to perform RSI operations from user space using RSI
ioctls as implemented
[here](https://github.com/islet-project/islet/tree/main/realm/linux-rsi). The
tool uses the [rust-rsi](../../lib/rust-rsi) library for all RSI related
functionalities.

# RSI operations

  * [get RSI specification version](#version-command) (ioctl)
  * [measurement read](#measurement-read-command) (ioctl)
  * [measurement extend](#measurement-extend-command) (ioctl)
  * [get and verify attestation token](#get-attestation-token-command) (ioctl)
  * [verify attestation token from file](#verify-and-print-token-command)
  * [verify platform token from file](#verify-and-print-platform-token-command)
  * [fetch sealing key material](#fetch-sealing-key-material-command) (ioctl)

# Usage

The tool can be compiled for either AARCH64 or X64 architectures. It can be used
with or without RSI kernel module loaded (obviously it cannot be loaded on X64
architectures) as some commands (namely `verify` and `verify-print`) are used
with an input from file. Commands requiring ioctl will only work on AARCH64
architecture with RSI kernel module loaded.

The tool is self documented and each operation contains description of its
parameters.

## Command list

```
tools/rsictl $ cargo run -- --help
Command line interface for the RSI kernel module

Usage: rsictl <COMMAND>

Commands:
  version          Prints RSI ABI version
  measur-read      Gets given measurement
  measur-extend    Extends given measurement
  attest           Gets attestation token
  verify           Verifies and prints the token from a file
  verify-platform  Verifies and prints the platform token from a file
  sealing-key      Fetch sealing key material
  help             Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

## Version command

```
tools/rsictl $ cargo run -- version --help
Prints RSI ABI version

Usage: rsictl version

Options:
  -h, --help  Print help
```

## Measurement read command

```
tools/rsictl $ cargo run -- measur-read --help
Gets given measurement

Usage: rsictl measur-read [OPTIONS] --index <INDEX>

Options:
  -n, --index <INDEX>    index to read, must be 0-4
  -o, --output <OUTPUT>  filename to write the measurement, none for stdout hexdump
  -h, --help             Print help
```

## Measurement extend command

```
tools/rsictl $ cargo run -- measur-extend --help
Extends given measurement

Usage: rsictl measur-extend [OPTIONS] --index <INDEX>

Options:
  -n, --index <INDEX>    index to extend, must be 1-4
  -r, --random <RANDOM>  length of random data to use (1-64) [default: 64]
  -i, --input <INPUT>    filename to extend the measurement with (1-64 bytes), none to use random
  -h, --help             Print help
```

## Get attestation token command

If the `output` parameter is not give then tool will verify and print the token
to stdout. If the output parameter is passed the token will be saved to file
without verification. It can be later printed and verified using `verify`
command.

```
tools/rsictl $ cargo run -- attest --help
Gets attestation token

Usage: rsictl attest [OPTIONS]

Options:
  -i, --input <INPUT>    filename with the challange (64 bytes), none to use random
  -o, --output <OUTPUT>  filename to write the token to, none to verify & print
  -k, --key <KEY>        filename with a CPAK public key, used only when verifying
  -h, --help             Print help
```

## Verify and print token command

```
tools/rsictl $ cargo run -- verify --help
Verifies and prints the token from a file

Usage: rsictl verify [OPTIONS] --input <INPUT>

Options:
  -i, --input <INPUT>  filename with the token to verify
  -k, --key <KEY>      filename with a CPAK public key
  -h, --help           Print help
```

## Verify and print platform token command

```
tools/rsictl $ cargo run -- verify-platform --help
Verifies and prints the platform token from a file

Usage: rsictl verify-platform --input <INPUT> --key <KEY>

Options:
  -i, --input <INPUT>  filename with the extracted platform token to verify
  -k, --key <KEY>      filename with the public cpak
  -h, --help           Print help
```

## Fetch sealing key material command

```
tools/rsictl $ cargo run -- sealing-key --help
Fetch sealing key material

Usage: rsictl sealing-key [OPTIONS]

Options:
  -f, --flags <FLAGS>
          Flags altering source material for sealing key derivation

          Possible values:
          - key:      Use VHUK_B insted of VHUK_A
          - rim:      Use RIM to calculate key material
          - realm-id: Use Realm ID to calculate key material

  -s, --svn <SVN>
          Use Security Version Number as key material

  -h, --help
          Print help (see a summary with '-h')
```

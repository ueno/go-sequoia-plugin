# go-sequoia-plugin

go-sequoia-plugin is an experimental Go [plugin] wrapping OpenPGP
signature operations backed by [sequoia-pgp].

## Prerequisites

- Rust toolchain
- Go toolchain
- sequoia-sq package
- Dependencies: openssl-devel, sqlite3-devel, and bzip2-devel

## Building

1. Run `make` or `make RELEASE=1`

## Usage

1. cd examples/sign
1. `go build`
1. generate an OpenPGP keypair for testing, e.g., `gpg2 --gen-key`, without passphrase
1. export the secret key, with `gpg2 --export-secret-key KEYID > KEYID.pgp`
1. import the secret key to sequoia-keystore, with `sq key import KEYID.pgp`
1. `./sign KEYID somefile`

## License

Apache-2.0

[plugin]: https://pkg.go.dev/plugin
[sequoia-pgp]: https://sequoia-pgp.org/

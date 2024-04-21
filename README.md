# go-sequoia-plugin

go-sequoia-plugin is an experimental Go [plugin] wrapping OpenPGP
signature operations backed by [sequoia-pgp], to be used as an
alternative
[mechanism](https://github.com/containers/image/blob/main/signature/mechanism.go)
for container [image](https://github.com/containers/image) signing.

## Prerequisites

- Rust toolchain
- Go toolchain
- sequoia-sq package for key manipulation
- Dependencies: openssl-devel, sqlite3-devel, and bzip2-devel

## Building

1. Run `make` or `make RELEASE=1`

## Usage

1. Generate an OpenPGP keypair for testing, e.g., `gpg2 --gen-key`, without passphrase
1. Export the secret key, with `gpg2 --export-secret-key KEYID > KEYID.pgp`
1. Import the secret key to sequoia-keystore, with `sq key import KEYID.pgp`
1. `cd cmd/sign`
1. `go build`
1. `./sign KEYID somefile`

## License

Apache-2.0

[plugin]: https://pkg.go.dev/plugin
[sequoia-pgp]: https://sequoia-pgp.org/

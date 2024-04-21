# go-sequoia-plugin

go-sequoia-plugin is a Go [plugin] wrapping OpenPGP signature
operations backed by [sequoia-pgp], to be used as an alternative
signing [mechanism] for container signing.

## How it works

The deliverable of this project is a Go plugin `sequoia.so`, which is
a shared library module accompanying Go type information. The plugin
is implemented using sequoia-pgp through Rust FFI and then [CGO].

Applications can dynamically load the plugin with
[`plugin.Open`](signature/mechanism_sequoia.go). That way, it is
possible to decouple the complicated build process involving both Rust
and Go toolchain out of the image/signature package.

## Prerequisites

- Rust toolchain
- Go toolchain
- sequoia-sq package for key manipulation
- Dependencies: capnproto, openssl-devel, sqlite3-devel, and bzip2-devel

## Building

1. Run `make` or `make RELEASE=1`

## Usage

### Preparation

1. Generate an OpenPGP keypair for testing, e.g., `gpg2 --gen-key`, without passphrase
1. Export the secret key, with `gpg2 --export-secret-key KEYID > KEYID.pgp`
1. Import the secret key to sequoia-keystore, with `sq key import --cert-store=$HOME/.local/share/sequoia/certs KEYID.pgp`

### Sign

1. `cd cmd/sign`
1. `go build`
1. `./sign KEYID somefile`

### Verify

1. `cd cmd/verify`
1. `go build`
1. `./verify somefile.sig somefile`

## License

Apache-2.0

[plugin]: https://pkg.go.dev/plugin
[sequoia-pgp]: https://sequoia-pgp.org/
[mechanism]: https://pkg.go.dev/github.com/containers/image/v5@v5.30.0/signature#SigningMechanism
[CGO]: https://go.dev/wiki/cgo

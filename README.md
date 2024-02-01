# go-sequoia-plugin

go-sequoia-plugin is an experimental Go [plugin] wrapping OpenPGP
signature operations backed by [sequoia-pgp].

## Building

1. Install the Rust toolchain
1. Install the Go toolchain
1. Run `make` or `make RELEASE=1`

## Usage

1. cd examples
1. `go run verify.go keyring.gpg foo.sig foo.txt`

## License

LGPL-2.0-or-later

[plugin]: https://pkg.go.dev/plugin
[sequoia-pgp]: https://sequoia-pgp.org/

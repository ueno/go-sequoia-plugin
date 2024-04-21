// SPDX-License-Identifier: Apache-2.0

package main

// #include "sequoia.h"
import "C"

import (
	"errors"
	"unsafe"
)

type pluginRoot struct{}

func (r *pluginRoot) NewMechanismFromDirectory(
	dir string,
) (any, error) {
	var cerr *C.Error
	cMechanism := C.pgp_mechanism_new_from_directory(C.CString(dir), &cerr)
	if cMechanism == nil {
		defer C.pgp_error_free(cerr)
		return nil, errors.New(C.GoString(cerr.message))
	}
	mechanism := &mechanism{
		mechanism: cMechanism,
	}
	return mechanism, nil
}

func (r *pluginRoot) NewEpehemralMechanism(
	keyring []byte,
) (any, error) {
	var cerr *C.Error
	cMechanism := C.pgp_mechanism_new_ephemeral(
		base(keyring),
		C.size_t(len(keyring)),
		&cerr)
	if cMechanism == nil {
		defer C.pgp_error_free(cerr)
		return nil, errors.New(C.GoString(cerr.message))
	}
	mechanism := &mechanism{
		mechanism: cMechanism,
	}
	return mechanism, nil
}

type mechanism struct{
	mechanism *C.Mechanism
}

func (m *mechanism) SignWithPassphrase(
	input []byte,
	keyIdentity string,
	passphrase string,
) ([]byte, error) {
	var cerr *C.Error
	var cPassphrase *C.char
	if passphrase == "" {
		cPassphrase = nil
	} else {
		cPassphrase = C.CString(passphrase)
	};
	sig := C.pgp_sign(
		m.mechanism,
		C.CString(keyIdentity),
		cPassphrase,
		base(input), C.size_t(len(input)),
		&cerr,
	)
	if sig == nil {
		defer C.pgp_error_free(cerr)
		return nil, errors.New(C.GoString(cerr.message))
	}
	defer C.pgp_signature_free(sig)
	var size C.size_t
	cData := C.pgp_signature_get_data(sig, &size)
	return C.GoBytes(unsafe.Pointer(cData), C.int(size)), nil
}

func (m *mechanism) Sign(
	input []byte,
	keyIdentity string,
) ([]byte, error) {
	return m.SignWithPassphrase(input, keyIdentity, "")
}

func (m *mechanism) Verify(
	unverifiedSignature []byte,
) (contents []byte, keyIdentity string, err error) {
	var cerr *C.Error
	result := C.pgp_verify(
		m.mechanism,
		base(unverifiedSignature), C.size_t(len(unverifiedSignature)),
		&cerr,
	)
	if result == nil {
		defer C.pgp_error_free(cerr)
		return nil, "", errors.New(C.GoString(cerr.message))
	}
	defer C.pgp_verification_result_free(result)
	var size C.size_t
	cContent := C.pgp_verification_result_get_content(result, &size)
	contents = C.GoBytes(unsafe.Pointer(cContent), C.int(size))
	cSigner := C.pgp_verification_result_get_signer(result)
	keyIdentity = C.GoString(cSigner)
	return
}

func (m *mechanism) Close() error {
	return nil
}

func (m *mechanism) SupportsSigning() error {
	return nil
}

func (m *mechanism) UntrustedSignatureContents(
	untrustedSignature []byte,
) (untrustedContents []byte, shortKeyIdentifier string, err error) {
	return nil, "", errors.New("")
}

// base returns the address of the underlying array in b,
// being careful not to panic when b has zero length.
func base(b []byte) *C.uchar {
	if len(b) == 0 {
		return nil
	}
	return (*C.uchar)(unsafe.Pointer(&b[0]))
}

var PluginRoot pluginRoot

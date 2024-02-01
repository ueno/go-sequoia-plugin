// SPDX-License-Identifier: LGPL-2.0-or-later

package main

// #include "sequoia.h"
import "C"

import (
	"errors"
	"unsafe"
)

type verifier struct{}

func (v *verifier) VerifyDetached(
	keyring []byte,
	signature []byte,
	data []byte,
) error {
	if C.pgp_verify_detached(
		base(keyring), C.size_t(len(keyring)),
		base(signature), C.size_t(len(signature)),
		base(data), C.size_t(len(data)),
	) == -1 {
		return errors.New("failed to verify signature")
	}
	return nil
}

// base returns the address of the underlying array in b,
// being careful not to panic when b has zero length.
func base(b []byte) *C.uchar {
	if len(b) == 0 {
		return nil
	}
	return (*C.uchar)(unsafe.Pointer(&b[0]))
}

var Verifier verifier

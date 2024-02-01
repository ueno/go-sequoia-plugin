// SPDX-License-Identifier: LGPL-2.0-or-later

package main

import (
	"fmt"
	"os"
	"plugin"
)

type Verifier interface {
	VerifyDetached(
		keyring []byte,
		signature []byte,
		data []byte,
	) error
}

func main() {
	if len(os.Args) != 4 {
		fmt.Println("verify KEYRING SIGNATURE DATA")
		os.Exit(1)
	}

	keyring, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	signature, err := os.ReadFile(os.Args[2])
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	data, err := os.ReadFile(os.Args[3])
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	plug, err := plugin.Open("../sequoia.so")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	symVerifier, err := plug.Lookup("Verifier")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	var verifier Verifier
	verifier, ok := symVerifier.(Verifier)
	if !ok {
		fmt.Println("unexpected type from module symbol")
		os.Exit(1)
	}

	err = verifier.VerifyDetached(keyring, signature, data)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	fmt.Println("signature verification was successful")
}

// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Println("sign KEYID DATA")
		os.Exit(1)
	}

	keyid := os.Args[1]
	inputFile := os.Args[2]
	input, err := os.ReadFile(inputFile)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	mechanism, err := NewGPGSigningMechanism()
	if err != nil {
		fmt.Println("unable to create signing mechanism: " + err.Error())
		os.Exit(1)
	}

	signature, err := mechanism.Sign(input, keyid)
	if err != nil {
		fmt.Println("error: " + err.Error())
		os.Exit(1)
	}

	output, err := os.Create(fmt.Sprintf("%s.sig", inputFile))
	if err != nil {
		panic(err)
	}
	defer func() {
		if err := output.Close(); err != nil {
			panic(err)
		}
	}()

	output.Write(signature)
}

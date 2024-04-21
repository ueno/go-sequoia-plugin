// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"

	"github.com/ueno/go-sequoia-plugin/signature"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Println("verify SIGNATURE CONTENTS")
		os.Exit(1)
	}

	inputFile := os.Args[1]
	outputFile := os.Args[2]

	input, err := os.ReadFile(inputFile)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	mechanism, err := signature.NewGPGSigningMechanism()
	if err != nil {
		fmt.Println("unable to create signing mechanism: " + err.Error())
		os.Exit(1)
	}

	contents, keyIdentifier, err := mechanism.Verify(input)
	if err != nil {
		fmt.Println("error: " + err.Error())
		os.Exit(1)
	}

	fmt.Printf("Successfully verified signature created by %v\n",
		keyIdentifier)

	output, err := os.Create(outputFile)
	if err != nil {
		panic(err)
	}
	defer func() {
		if err := output.Close(); err != nil {
			panic(err)
		}
	}()

	output.Write(contents)
}

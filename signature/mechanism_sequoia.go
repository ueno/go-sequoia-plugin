// SPDX-License-Identifier: Apache-2.0

package signature

import (
	"github.com/containers/image/v5/signature"
	"log"
	"plugin"
	"sync"
)

var (
	initOnce   sync.Once
	pluginRoot PluginRoot
)

type PluginRoot interface {
	NewMechanismFromDirectory(
		dir string,
	) (any, error)

	NewEpehemralMechanism(
		keyring []byte,
	) (any, error)
}

func init() {
	initOnce.Do(func() {
		plug, err := plugin.Open("../../sequoia.so")
		if err != nil {
			log.Fatal(err)
		}

		symPluginRoot, err := plug.Lookup("PluginRoot")
		if err != nil {
			log.Fatal(err)
		}

		pluginRoot = symPluginRoot.(PluginRoot)
	})
}

func NewGPGSigningMechanism() (signature.SigningMechanism, error) {
	mech, err := pluginRoot.NewMechanismFromDirectory("")
	if err != nil {
		return nil, err
	}

	return mech.(signature.SigningMechanism), nil
}

func NewEphemeralGPGSigningMechanism(blob []byte) (signature.SigningMechanism, []string, error) {
	mech, err := pluginRoot.NewEpehemralMechanism(blob)
	if err != nil {
		return nil, nil, err
	}

	return mech.(signature.SigningMechanism), nil, nil
}

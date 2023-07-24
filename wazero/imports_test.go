// Copyright 2023 ChainSafe Systems (ON)
// SPDX-License-Identifier: LGPL-3.0-only

package wazero_runtime

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/ChainSafe/gossamer/lib/crypto/ed25519"
	"github.com/ChainSafe/gossamer/lib/keystore"
	"github.com/ChainSafe/gossamer/lib/runtime"
	"github.com/ChainSafe/gossamer/lib/trie"
	"github.com/ChainSafe/gossamer/pkg/scale"
	"github.com/stretchr/testify/require"
)

// NewTestInstance will create a new runtime instance using the given target runtime
func NewTestInstance(t *testing.T, targetRuntime string) *Instance {
	t.Helper()
	return NewTestInstanceWithTrie(t, targetRuntime, nil)
}

func setupConfig(t *testing.T) Config {
	t.Helper()
	return Config{
		Keystore: keystore.NewGlobalKeystore(),
	}
}

// NewTestInstanceWithTrie returns an instance based on the target runtime string specified,
// which can be a file path or a constant from the constants defined in `lib/runtime/constants.go`.
// The instance uses the trie given as argument for its storage.
func NewTestInstanceWithTrie(t *testing.T, targetRuntime string, tt *trie.Trie) *Instance {
	t.Helper()

	cfg := setupConfig(t)
	targetRuntime, err := runtime.GetRuntime(context.Background(), targetRuntime)
	require.NoError(t, err)

	r, err := NewInstanceFromFile(targetRuntime, cfg)
	require.NoError(t, err)

	return r
}

// NewInstanceFromFile instantiates a runtime from a .wasm file
func NewInstanceFromFile(fp string, cfg Config) (*Instance, error) {
	// Reads the WebAssembly module as bytes.
	// Retrieve WASM binary
	bytes, err := os.ReadFile(fp)
	if err != nil {
		return nil, fmt.Errorf("Failed to read wasm file: %s", err)
	}

	return NewInstance(bytes, cfg)
}

func Test_ext_crypto_ed25519_generate_version_1(t *testing.T) {
	inst := NewTestInstance(t, runtime.HOST_API_TEST_RUNTIME)

	idData := []byte(keystore.AccoName)
	ks, _ := inst.Context.Keystore.GetKeystore(idData)
	require.Equal(t, 0, ks.Size())

	mnemonic := "vessel track notable smile sign cloth problem unfair join orange snack fly"

	mnemonicBytes := []byte(mnemonic)
	var data = &mnemonicBytes
	seedData, err := scale.Marshal(data)
	require.NoError(t, err)

	params := append(idData, seedData...)

	pubKeyBytes, err := inst.Exec("rtm_ext_crypto_ed25519_generate_version_1", params)
	require.NoError(t, err)
	require.Equal(t,
		[]byte{128, 218, 27, 3, 63, 174, 140, 212, 114, 255, 156, 37, 221, 158, 30, 75, 187,
			49, 167, 79, 249, 228, 195, 86, 15, 10, 167, 37, 36, 126, 82, 126, 225},
		pubKeyBytes,
	)

	// this is SCALE encoded, but it should just be a 32 byte buffer. may be due to way test runtime is written.
	pubKey, err := ed25519.NewPublicKey(pubKeyBytes[1:])
	require.NoError(t, err)

	require.Equal(t, 1, ks.Size())
	kp := ks.GetKeypair(pubKey)
	require.NotNil(t, kp)
}

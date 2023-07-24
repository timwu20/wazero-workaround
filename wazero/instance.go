// Copyright 2023 ChainSafe Systems (ON)
// SPDX-License-Identifier: LGPL-3.0-only

package wazero_runtime

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/ChainSafe/gossamer/lib/keystore"
	"github.com/klauspost/compress/zstd"
	"github.com/tetratelabs/wabin/binary"
	"github.com/tetratelabs/wabin/leb128"
	"github.com/tetratelabs/wabin/wasm"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

// Name represents the name of the interpreter
const Name = "wazero"

type contextKey string

const runtimeContextKey = contextKey("runtime.Context")

// Context is the context for the wasm interpreter's imported functions
type Context struct {
	Allocator *FreeingBumpHeapAllocator
	Keystore  *keystore.GlobalKeystore
}

// Instance backed by wazero.Runtime
type Instance struct {
	Runtime  wazero.Runtime
	Module   api.Module
	Context  *Context
	proxyMod api.Module
	hostMod  api.Module
	sync.Mutex
}

// Config is the configuration used to create a Wasmer runtime instance.
type Config struct {
	Keystore *keystore.GlobalKeystore
}

func decompressWasm(code []byte) ([]byte, error) {
	compressionFlag := []byte{82, 188, 83, 118, 70, 219, 142, 5}
	if !bytes.HasPrefix(code, compressionFlag) {
		return code, nil
	}

	decoder, err := zstd.NewReader(nil)
	if err != nil {
		return nil, fmt.Errorf("creating zstd reader: %s", err)
	}
	bytes, err := decoder.DecodeAll(code[len(compressionFlag):], nil)
	if err != nil {
		return nil, err
	}
	return bytes, err
}

// NewInstance instantiates a runtime from raw wasm bytecode
func NewInstance(code []byte, cfg Config) (instance *Instance, err error) {
	ctx := context.Background()
	rt := wazero.NewRuntime(ctx)

	compiledModule, err := rt.NewHostModuleBuilder("host").
		// // values from newer kusama/polkadot runtimes
		// ExportMemory("memory", 23).
		NewFunctionBuilder().
		WithFunc(ext_logging_log_version_1).
		Export("ext_logging_log_version_1").
		NewFunctionBuilder().
		WithFunc(func() int32 {
			return 4
		}).
		Export("ext_logging_max_level_version_1").
		NewFunctionBuilder().
		WithFunc(func(a int32, b int32, c int32) {
			panic("unimplemented")
		}).
		Export("ext_transaction_index_index_version_1").
		NewFunctionBuilder().
		WithFunc(func(a int32, b int32) {
			panic("unimplemented")
		}).
		Export("ext_transaction_index_renew_version_1").
		NewFunctionBuilder().
		WithFunc(func(a int32) {
			panic("unimplemented")
		}).
		Export("ext_sandbox_instance_teardown_version_1").
		NewFunctionBuilder().
		WithFunc(func(a int32, b int64, c int64, d int32) int32 {
			panic("unimplemented")
		}).
		Export("ext_sandbox_instantiate_version_1").
		NewFunctionBuilder().
		WithFunc(func(a int32, b int64, c int64, d int32, e int32, f int32) int32 {
			panic("unimplemented")
		}).
		Export("ext_sandbox_invoke_version_1").
		NewFunctionBuilder().
		WithFunc(func(a int32, b int32, c int32, d int32) int32 {
			panic("unimplemented")
		}).
		Export("ext_sandbox_memory_get_version_1").
		NewFunctionBuilder().
		WithFunc(func(a int32, b int32, c int32, d int32) int32 {
			panic("unimplemented")
		}).
		Export("ext_sandbox_memory_set_version_1").
		NewFunctionBuilder().
		WithFunc(func(a int32) {
			panic("unimplemented")
		}).
		Export("ext_sandbox_memory_teardown_version_1").
		NewFunctionBuilder().
		WithFunc(ext_crypto_ed25519_generate_version_1).
		Export("ext_crypto_ed25519_generate_version_1").
		NewFunctionBuilder().
		WithFunc(func(keyTypeID uint32) uint64 {
			panic("unimplemented")
		}).
		Export("ext_crypto_ed25519_public_keys_version_1").
		NewFunctionBuilder().
		WithFunc(func(keyTypeID, key uint32, msg uint64) uint64 {
			panic("unimplemented")
		}).
		Export("ext_crypto_ed25519_sign_version_1").
		NewFunctionBuilder().
		WithFunc(func(sig uint32, msg uint64, key uint32) uint32 {
			panic("unimplemented")
		}).
		Export("ext_crypto_ed25519_verify_version_1").
		NewFunctionBuilder().
		WithFunc(func(sig, msg uint32) uint64 {
			panic("unimplemented")
		}).
		Export("ext_crypto_secp256k1_ecdsa_recover_version_1").
		NewFunctionBuilder().
		WithFunc(func(sig, msg uint32) uint64 {
			panic("unimplemented")
		}).
		Export("ext_crypto_secp256k1_ecdsa_recover_version_2").
		NewFunctionBuilder().
		WithFunc(func(sig uint32, msg uint64, key uint32) uint32 {
			panic("unimplemented")
		}).
		Export("ext_crypto_ecdsa_verify_version_2").
		NewFunctionBuilder().
		WithFunc(func(sig uint32, msg uint64, key uint32) uint32 {
			panic("unimplemented")
		}).
		Export("ext_crypto_secp256k1_ecdsa_recover_compressed_version_1").
		NewFunctionBuilder().
		WithFunc(func(sig, msg uint32) uint64 {
			panic("unimplemented")
		}).
		Export("ext_crypto_secp256k1_ecdsa_recover_compressed_version_2").
		NewFunctionBuilder().
		WithFunc(func(keyTypeID uint32, seedSpan uint64) uint32 {
			panic("unimplemented")
		}).
		Export("ext_crypto_sr25519_generate_version_1").
		NewFunctionBuilder().
		WithFunc(func(keyTypeID uint32) uint64 {
			panic("unimplemented")
		}).
		Export("ext_crypto_sr25519_public_keys_version_1").
		NewFunctionBuilder().
		WithFunc(func(keyTypeID, key uint32, msg uint64) uint64 {
			panic("unimplemented")
		}).
		Export("ext_crypto_sr25519_sign_version_1").
		NewFunctionBuilder().
		WithFunc(func(sig uint32, msg uint64, key uint32) uint32 {
			panic("unimplemented")
		}).
		Export("ext_crypto_sr25519_verify_version_1").
		NewFunctionBuilder().
		WithFunc(func(sig uint32, msg uint64, key uint32) uint32 {
			panic("unimplemented")
		}).
		Export("ext_crypto_sr25519_verify_version_2").
		NewFunctionBuilder().
		WithFunc(func(sig uint32, msg uint64, key uint32) uint32 {
			panic("unimplemented")
		}).
		Export("ext_crypto_start_batch_verify_version_1").
		NewFunctionBuilder().
		WithFunc(func() uint32 {
			panic("unimplemented")
		}).
		Export("ext_crypto_finish_batch_verify_version_1").
		NewFunctionBuilder().
		WithFunc(func(dataSpan uint64) uint32 {
			panic("unimplemented")
		}).
		Export("ext_trie_blake2_256_root_version_1").
		NewFunctionBuilder().
		WithFunc(func(dataSpan uint64) uint32 {
			panic("unimplemented")
		}).
		Export("ext_trie_blake2_256_ordered_root_version_1").
		NewFunctionBuilder().
		WithFunc(func(dataSpan uint64) uint32 {
			panic("unimplemented")
		}).
		Export("ext_trie_blake2_256_ordered_root_version_2").
		NewFunctionBuilder().
		WithFunc(func(rootSpan uint32, proofSpan, keySpan, valueSpan uint64) uint32 {
			panic("unimplemented")
		}).
		Export("ext_trie_blake2_256_verify_proof_version_1").
		NewFunctionBuilder().
		WithFunc(func(rootSpan uint32, proofSpan, keySpan, valueSpan uint64) uint32 {
			panic("unimplemented")
		}).
		Export("ext_misc_print_hex_version_1").
		NewFunctionBuilder().
		WithFunc(func(dataSpan uint64) uint64 {
			panic("unimplemented")
		}).
		Export("ext_misc_print_num_version_1").
		NewFunctionBuilder().
		WithFunc(func(data uint64) {
			panic("unimplemented")
		}).
		Export("ext_misc_print_utf8_version_1").
		NewFunctionBuilder().
		WithFunc(func(data uint64) {
			panic("unimplemented")
		}).
		Export("ext_misc_runtime_version_version_1").
		NewFunctionBuilder().
		WithFunc(func(childStorageKeySpan, keySpan, valueSpan uint64) {
			panic("unimplemented")
		}).
		Export("ext_default_child_storage_set_version_1").
		NewFunctionBuilder().
		WithFunc(func(childStorageKey, key, valueOut uint64, offset uint32) uint64 {
			panic("unimplemented")
		}).
		Export("ext_default_child_storage_read_version_1").
		NewFunctionBuilder().
		WithFunc(func(childStorageKey, keySpan uint64) {
			panic("unimplemented")
		}).
		Export("ext_default_child_storage_clear_version_1").
		NewFunctionBuilder().
		WithFunc(func(childStorageKey, keySpan uint64) {
			panic("unimplemented")
		}).
		Export("ext_default_child_storage_clear_prefix_version_1").
		NewFunctionBuilder().
		WithFunc(func(childStorageKey, key uint64) uint32 {
			panic("unimplemented")
		}).
		Export("ext_default_child_storage_exists_version_1").
		NewFunctionBuilder().
		WithFunc(func(hildStorageKey, key uint64) uint64 {
			panic("unimplemented")
		}).
		Export("ext_default_child_storage_get_version_1").
		NewFunctionBuilder().
		WithFunc(func(childStorageKey, key uint64) uint64 {
			panic("unimplemented")
		}).
		Export("ext_default_child_storage_next_key_version_1").
		NewFunctionBuilder().
		WithFunc(func(childStorageKey uint64) (ptrSize uint64) {
			panic("unimplemented")
		}).
		Export("ext_default_child_storage_root_version_1").
		NewFunctionBuilder().
		WithFunc(func(childStorageKey uint64) {
			panic("unimplemented")
		}).
		Export("ext_default_child_storage_storage_kill_version_1").
		NewFunctionBuilder().
		WithFunc(func(childStorageKeySpan, lim uint64) (allDeleted uint32) {
			panic("unimplemented")
		}).
		Export("ext_default_child_storage_storage_kill_version_2").
		NewFunctionBuilder().
		WithFunc(func(childStorageKeySpan, lim uint64) (allDeleted uint64) {
			panic("unimplemented")
		}).
		Export("ext_default_child_storage_storage_kill_version_3").
		NewFunctionBuilder().
		WithFunc(ext_allocator_free_version_1).
		Export("ext_allocator_free_version_1").
		NewFunctionBuilder().
		WithFunc(ext_allocator_malloc_version_1).
		Export("ext_allocator_malloc_version_1").
		NewFunctionBuilder().
		WithFunc(func(keyTypeID uint64) uint32 {
			panic("unimplemented")
		}).
		Export("ext_hashing_blake2_128_version_1").
		NewFunctionBuilder().
		WithFunc(func(keyTypeID uint64) uint32 {
			panic("unimplemented")
		}).
		Export("ext_hashing_blake2_256_version_1").
		NewFunctionBuilder().
		WithFunc(func(dataSpan uint64) uint32 {
			panic("unimplemented")
		}).
		Export("ext_hashing_keccak_256_version_1").
		NewFunctionBuilder().
		WithFunc(func(keyTypeID uint64) uint32 {
			panic("unimplemented")
		}).
		Export("ext_hashing_sha2_256_version_1").
		NewFunctionBuilder().
		WithFunc(func(keyTypeID uint64) uint32 {
			panic("unimplemented")
		}).
		Export("ext_hashing_twox_256_version_1").
		NewFunctionBuilder().
		WithFunc(func(keyTypeID uint64) uint32 {
			panic("unimplemented")
		}).
		Export("ext_hashing_twox_128_version_1").
		NewFunctionBuilder().
		WithFunc(func(keyTypeID uint64) uint32 {
			panic("unimplemented")
		}).
		Export("ext_hashing_twox_64_version_1").
		NewFunctionBuilder().
		WithFunc(func(keyTypeID uint32) uint64 {
			panic("unimplemented")
		}).
		Export("ext_offchain_index_set_version_1").
		NewFunctionBuilder().
		WithFunc(func(kind uint32, key uint64) {
			panic("unimplemented")
		}).
		Export("ext_offchain_local_storage_clear_version_1").
		NewFunctionBuilder().
		WithFunc(func(keyTypeID uint32) uint64 {
			panic("unimplemented")
		}).
		Export("ext_offchain_is_validator_version_1").
		NewFunctionBuilder().
		WithFunc(func(keyTypeID uint32) uint64 {
			panic("unimplemented")
		}).
		Export("ext_offchain_local_storage_compare_and_set_version_1").
		NewFunctionBuilder().
		WithFunc(func(keyTypeID uint32) uint64 {
			panic("unimplemented")
		}).
		Export("ext_offchain_local_storage_get_version_1").
		NewFunctionBuilder().
		WithFunc(func(keyTypeID uint32) uint64 {
			panic("unimplemented")
		}).
		Export("ext_offchain_local_storage_set_version_1").
		NewFunctionBuilder().
		WithFunc(func(keyTypeID uint32) uint64 {
			panic("unimplemented")
		}).
		Export("ext_offchain_network_state_version_1").
		NewFunctionBuilder().
		WithFunc(func(keyTypeID uint32) uint64 {
			panic("unimplemented")
		}).
		Export("ext_offchain_random_seed_version_1").
		NewFunctionBuilder().
		WithFunc(func(keyTypeID uint32) uint64 {
			panic("unimplemented")
		}).
		Export("ext_offchain_submit_transaction_version_1").
		NewFunctionBuilder().
		WithFunc(func() uint64 {
			panic("unimplemented")
		}).
		Export("ext_offchain_timestamp_version_1").
		NewFunctionBuilder().
		WithFunc(func(keyTypeID uint64) {
			panic("unimplemented")
		}).
		Export("ext_offchain_sleep_until_version_1").
		NewFunctionBuilder().
		WithFunc(func(methodSpan, uriSpan, metaSpan uint64) (pointerSize uint64) {
			panic("unimplemented")
		}).
		Export("ext_offchain_http_request_start_version_1").
		NewFunctionBuilder().
		WithFunc(func(reqID uint32, nameSpan, valueSpan uint64) (pointerSize uint64) {
			panic("unimplemented")
		}).
		Export("ext_offchain_http_request_add_header_version_1").
		NewFunctionBuilder().
		WithFunc(func(keySpan, valueSpan uint64) {
			panic("unimplemented")
		}).
		Export("ext_storage_append_version_1").
		NewFunctionBuilder().
		WithFunc(func(keyTypeID uint32) uint64 {
			panic("unimplemented")
		}).
		Export("ext_storage_changes_root_version_1").
		NewFunctionBuilder().
		WithFunc(func(keyTypeID uint64) {
			panic("unimplemented")
		}).
		Export("ext_storage_clear_version_1").
		NewFunctionBuilder().
		WithFunc(func(keyTypeID uint64) {
			panic("unimplemented")
		}).
		Export("ext_storage_clear_prefix_version_1").
		NewFunctionBuilder().
		WithFunc(func(prefixSpan, lim uint64) uint64 {
			panic("unimplemented")
		}).
		Export("ext_storage_clear_prefix_version_2").
		NewFunctionBuilder().
		WithFunc(func(keyTypeID uint64) uint32 {
			panic("unimplemented")
		}).
		Export("ext_storage_exists_version_1").
		NewFunctionBuilder().
		WithFunc(func(keyTypeID uint64) uint64 {
			panic("unimplemented")
		}).
		Export("ext_storage_get_version_1").
		NewFunctionBuilder().
		WithFunc(func(keySpan uint64) uint64 {
			panic("unimplemented")
		}).
		Export("ext_storage_next_key_version_1").
		NewFunctionBuilder().
		WithFunc(func(keySpan, valueOut uint64, offset uint32) uint64 {
			panic("unimplemented")
		}).
		Export("ext_storage_read_version_1").
		NewFunctionBuilder().
		WithFunc(func() uint64 {
			panic("unimplemented")
		}).
		Export("ext_storage_root_version_1").
		NewFunctionBuilder().
		WithFunc(func(keyTypeID uint32) uint64 {
			panic("unimplemented")
		}).
		Export("ext_storage_root_version_2").
		NewFunctionBuilder().
		WithFunc(func(keySpan, valueSpan uint64) {
			panic("unimplemented")
		}).
		Export("ext_storage_set_version_1").
		NewFunctionBuilder().
		WithFunc(func(keyTypeID uint32) uint64 {
			panic("unimplemented")
		}).
		Export("ext_storage_start_transaction_version_1").
		NewFunctionBuilder().
		WithFunc(func(keyTypeID uint32) uint64 {
			panic("unimplemented")
		}).
		Export("ext_storage_rollback_transaction_version_1").
		NewFunctionBuilder().
		WithFunc(func(keyTypeID uint32) uint64 {
			panic("unimplemented")
		}).
		Export("ext_storage_commit_transaction_version_1").
		Compile(ctx)

	if err != nil {
		panic(err)
	}

	hostMod, err := rt.InstantiateModule(ctx, compiledModule, wazero.NewModuleConfig())
	if err != nil {
		panic(err)
	}

	proxyBin := NewModuleBinary("host", compiledModule)

	proxyMod, err := rt.Instantiate(ctx, proxyBin)
	if err != nil {
		panic(err)
		return nil, err
	}

	code, err = decompressWasm(code)
	if err != nil {
		return nil, err
	}

	mod, err := rt.Instantiate(ctx, code)
	if err != nil {
		return nil, err
	}

	global := mod.ExportedGlobal("__heap_base")
	if global == nil {
		return nil, fmt.Errorf("wazero error: nil global for __heap_base")
	}

	hb := api.DecodeU32(global.Get())

	fmt.Println("hb", hb)
	// hb := runtime.DefaultHeapBase

	mem := mod.ExportedMemory("memory")
	if mem == nil {
		return nil, fmt.Errorf("wazero error: nil memory for module")
	}

	allocator := NewAllocator(mem, hb)

	fmt.Println("new", mod.String(), hostMod.String(), proxyMod.String())

	return &Instance{
		Runtime: rt,
		Context: &Context{
			Allocator: allocator,
			Keystore:  cfg.Keystore,
		},
		Module:   mod,
		proxyMod: proxyMod,
		hostMod:  hostMod,
	}, nil
}

// NewModuleBinary creates the proxy module to proxy a function call against
// all the exported functions in `proxyTarget`, and returns its encoded binary.
// The resulting module exports the proxy functions whose names are exactly the same
// as the proxy destination.
//
// This is used to test host call implementations. If logging, use
// NewLoggingListenerFactory to avoid messages from the proxying module.
func NewModuleBinary(moduleName string, proxyTarget wazero.CompiledModule) []byte {
	funcDefs := proxyTarget.ExportedFunctions()
	funcNum := uint32(len(funcDefs))
	proxyModule := &wasm.Module{
		MemorySection: &wasm.Memory{Min: 23},
		ExportSection: []*wasm.Export{{Name: "memory", Type: api.ExternTypeMemory}},
		NameSection:   &wasm.NameSection{ModuleName: "env"},
	}
	var cnt wasm.Index
	for _, def := range funcDefs {
		proxyModule.TypeSection = append(proxyModule.TypeSection, &wasm.FunctionType{
			Params: def.ParamTypes(), Results: def.ResultTypes(),
		})

		// Imports the function.
		name := def.ExportNames()[0]
		proxyModule.ImportSection = append(proxyModule.ImportSection, &wasm.Import{
			Module:   moduleName,
			Name:     name,
			DescFunc: cnt,
		})

		// Ensures that type of the proxy function matches the imported function.
		proxyModule.FunctionSection = append(proxyModule.FunctionSection, cnt)

		// Build the function body of the proxy function.
		var body []byte
		for i := range def.ParamTypes() {
			body = append(body, wasm.OpcodeLocalGet)
			body = append(body, leb128.EncodeUint32(uint32(i))...)
		}

		body = append(body, wasm.OpcodeCall)
		body = append(body, leb128.EncodeUint32(cnt)...)
		body = append(body, wasm.OpcodeEnd)
		proxyModule.CodeSection = append(proxyModule.CodeSection, &wasm.Code{Body: body})

		proxyFuncIndex := cnt + funcNum
		// Assigns the same params name as the imported one.
		paramNames := wasm.NameMapAssoc{Index: proxyFuncIndex}
		for i, n := range def.ParamNames() {
			paramNames.NameMap = append(paramNames.NameMap, &wasm.NameAssoc{Index: wasm.Index(i), Name: n})
		}
		proxyModule.NameSection.LocalNames = append(proxyModule.NameSection.LocalNames, &paramNames)

		// Plus, assigns the same function name.
		proxyModule.NameSection.FunctionNames = append(proxyModule.NameSection.FunctionNames,
			&wasm.NameAssoc{Index: proxyFuncIndex, Name: name})

		// Finally, exports the proxy function with the same name as the imported one.
		proxyModule.ExportSection = append(proxyModule.ExportSection, &wasm.Export{
			Type:  wasm.ExternTypeFunc,
			Name:  name,
			Index: proxyFuncIndex,
		})
		cnt++
	}
	return binary.EncodeModule(proxyModule)
}

var ErrExportFunctionNotFound = errors.New("export function not found")

func (i *Instance) Exec(function string, data []byte) (result []byte, err error) {
	i.Lock()
	defer i.Unlock()

	fmt.Println("exec", i.Module.String(), i.proxyMod.String())

	dataLength := uint32(len(data))
	inputPtr, err := i.Context.Allocator.Allocate(dataLength, i.Module.Memory())
	if err != nil {
		return nil, fmt.Errorf("allocating input memory: %w", err)
	}

	// inputPtr1, err := i.Context.Allocator.Allocate(dataLength, i.proxyMod.Memory())
	// if err != nil {
	// 	return nil, fmt.Errorf("allocating input memory: %w", err)
	// }

	defer i.Context.Allocator.Clear()

	// // Store the data into memory
	// mem := i.proxyMod.Memory()
	// if mem == nil {
	// 	panic("nil memory")
	// }
	// fmt.Println("writing proxyMod: inputPtr", inputPtr, "data", data)
	// ok := mem.Write(inputPtr, data)
	// if !ok {
	// 	panic("write overflow")
	// }

	// Store the data into memory
	mem := i.Module.Memory()
	if mem == nil {
		panic("nil memory")
	}
	ok := mem.Write(inputPtr, data)
	if !ok {
		panic("write overflow")
	}
	fmt.Println("writing module: inputPtr", inputPtr, "data", data, "leght", len(data))

	runtimeFunc := i.Module.ExportedFunction(function)
	if runtimeFunc == nil {
		return nil, fmt.Errorf("%w: %s", ErrExportFunctionNotFound, function)
	}

	ctx := context.WithValue(context.Background(), runtimeContextKey, i.Context)

	values, err := runtimeFunc.Call(ctx, api.EncodeU32(uint32(inputPtr)), api.EncodeU32(uint32(dataLength)))
	if err != nil {
		return nil, fmt.Errorf("running runtime function: %w", err)
	}
	if len(values) == 0 {
		return nil, fmt.Errorf("no returned values from runtime function: %s", function)
	}
	wasmValue := values[0]

	outputPtr, outputLength := splitPointerSize(wasmValue)
	result, ok = mem.Read(outputPtr, outputLength)
	if !ok {
		panic("write overflow")
	}
	return result, nil
}

// Copyright 2023 ChainSafe Systems (ON)
// SPDX-License-Identifier: LGPL-3.0-only

package wazero_runtime

import (
	"context"
	"fmt"

	"github.com/ChainSafe/gossamer/lib/crypto/ed25519"
	"github.com/ChainSafe/gossamer/lib/runtime"
	"github.com/ChainSafe/gossamer/pkg/scale"
	"github.com/tetratelabs/wazero/api"
)

// toPointerSize converts an uint32 pointer and uint32 size
// to an int64 pointer size.
func newPointerSize(ptr, size uint32) (pointerSize uint64) {
	return uint64(ptr) | (uint64(size) << 32)
}

// splitPointerSize converts a 64bit pointer size to an
// uint32 pointer and a uint32 size.
func splitPointerSize(pointerSize uint64) (ptr, size uint32) {
	return uint32(pointerSize), uint32(pointerSize >> 32)
}

// read will read from 64 bit pointer size and return a byte slice
func read(m api.Module, pointerSize uint64) (data []byte) {
	ptr, size := splitPointerSize(pointerSize)
	fmt.Println("ptr", ptr, "size", size)
	data, ok := m.Memory().Read(ptr, size)
	if !ok {
		panic("write overflow")
	}
	return data
}

// copies a Go byte slice to wasm memory and returns the corresponding
// 64 bit pointer size.
func write(m api.Module, allocator *FreeingBumpHeapAllocator, data []byte) (pointerSize uint64, err error) {
	size := uint32(len(data))
	pointer, err := allocator.Allocate(size, m.Memory())
	if err != nil {
		return 0, fmt.Errorf("allocating: %w", err)
	}

	ok := m.Memory().Write(pointer, data)
	if !ok {
		return 0, fmt.Errorf("out of range")
	}
	return newPointerSize(pointer, size), nil
}

func ext_logging_log_version_1(ctx context.Context, m api.Module, level int32, targetData, msgData uint64) {
	target := string(read(m, targetData))
	msg := string(read(m, msgData))

	switch int(level) {
	case 0:
		fmt.Println("target=" + target + " message=" + msg)
	case 1:
		fmt.Println("target=" + target + " message=" + msg)
	case 2:
		fmt.Println("target=" + target + " message=" + msg)
	case 3:
		fmt.Println("target=" + target + " message=" + msg)
	case 4:
		fmt.Println("target=" + target + " message=" + msg)
	default:
		fmt.Printf("level=%d target=%s message=%s\n", int(level), target, msg)
	}
}

func ext_crypto_ed25519_generate_version_1(
	ctx context.Context, m api.Module, keyTypeID uint32, seedSpan uint64) uint32 {
	fmt.Println("in import", m.String(), keyTypeID, seedSpan)
	id, ok := m.Memory().Read(keyTypeID, 4)
	if !ok {
		panic("out of range read")
	}

	seedBytes := read(m, seedSpan)
	seedBytes2, ok := m.Memory().Read(1049628, 77)
	if !ok {
		panic("read overflow")
	}
	seedBytes3, ok := m.Memory().Read(1114200, 77)
	if !ok {
		panic("write overflow")
	}

	fmt.Println("seedSpan", seedSpan, "id", id, "seedBytes", seedBytes)
	fmt.Println("seedBytes2", seedBytes2)
	fmt.Println("seedBytes3", seedBytes3)

	var seed *[]byte
	err := scale.Unmarshal(seedBytes2, &seed)
	if err != nil {
		fmt.Printf("cannot generate key: %s\n", err)
		return 0
	}
	fmt.Println("seed", seed)

	var kp *ed25519.Keypair

	if seed != nil {
		kp, err = ed25519.NewKeypairFromMnenomic(string(*seed), "")
	} else {
		kp, err = ed25519.GenerateKeypair()
	}

	if err != nil {
		fmt.Printf("cannot generate key: %s\n", err)
		return 0
	}

	rtCtx := ctx.Value(runtimeContextKey).(*Context)
	if rtCtx == nil {
		panic("nil runtime context")
	}

	ks, err := rtCtx.Keystore.GetKeystore(id)
	if err != nil {
		fmt.Printf("error for id 0x%x: %s\n", id, err)
		return 0
	}

	err = ks.Insert(kp)
	if err != nil {
		fmt.Printf("failed to insert key: %s\n", err)
		return 0
	}

	fmt.Println("writing", kp.Public().Encode())
	ret, err := write(m, rtCtx.Allocator, kp.Public().Encode())
	if err != nil {
		fmt.Printf("failed to allocate memory: %s\n", err)
		return 0
	}

	fmt.Println("generated ed25519 keypair with public key: " + kp.Public().Hex())
	return uint32(ret)
}

func ext_allocator_free_version_1(ctx context.Context, m api.Module, addr uint32) {
	allocator := ctx.Value(runtimeContextKey).(*runtime.Context).Allocator

	// Deallocate memory
	err := allocator.Deallocate(addr)
	if err != nil {
		panic(err)
	}
}

func ext_allocator_malloc_version_1(ctx context.Context, m api.Module, size uint32) uint32 {
	allocator := ctx.Value(runtimeContextKey).(*runtime.Context).Allocator

	// Allocate memory
	res, err := allocator.Allocate(size)
	if err != nil {
		panic(err)
	}

	return res
}

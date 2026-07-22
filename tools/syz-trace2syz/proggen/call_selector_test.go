// Copyright 2019 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package proggen

import (
	"testing"

	"github.com/google/syzkaller/tools/syz-trace2syz/parser"
)

func TestMatchFilename(t *testing.T) {
	sc := selectorCommon{}
	type Test struct {
		file1 string
		file2 string
		devID int
		match bool
	}
	tests := []Test{
		{
			"/dev/zero", "/dev/zero", -1, true,
		}, {
			"/dev/loop#", "/dev/loop1", 1, true,
		}, {
			"", "a", -1, false,
		}, {
			"/dev/loop#/loop", "/dev/loop0/looq", -1, false,
		}, {
			"/dev/i2c-#\x00", "/dev/i2c-1", 1, true,
		}, {
			"/dev/some#/some#", "/dev/some1/some1", 11, true,
		}, {
			"/dev/some/some#", "/dev/some", -1, false,
		}, {
			"/dev/some", "/dev/some/some", -1, false,
		},
	}
	for _, test := range tests {
		match, devID := sc.matchFilename([]byte(test.file1), []byte(test.file2))
		if test.match != match || test.devID != devID {
			t.Errorf("failed to match %s and %s\nexpected: %t, %d\n\ngot: %t, %d\n",
				test.file1, test.file2, test.match, test.devID, match, devID)
		}
	}
}

func TestResourceDependentSelectionBypassesCache(t *testing.T) {
	target := testTarget(t)
	selector := newSelectors(target, newRCache())[0].(*defaultCallSelector)
	resourceDependent := map[string]bool{
		"ioctl": true, "accept": true, "accept4": true, "bind": true, "connect": true,
		"recvfrom": true, "sendto": true, "sendmsg": true, "getsockname": true,
		"openat": true,
	}
	for name, discriminators := range discriminatorArgs {
		if got, want := selector.canCache(name, discriminators), !resourceDependent[name]; got != want {
			t.Errorf("canCache(%q)=%v, want %v", name, got, want)
		}
	}
	call := parser.NewSyscall(1, "ioctl", []parser.IrType{parser.Constant(3), parser.Constant(0)}, 0, false, false)
	key, ok := selector.cacheKey(call, discriminatorArgs[call.CallName])
	if !ok {
		t.Fatal("failed to build cache key")
	}

	// A resource-dependent lookup must ignore even an existing entry: fd mappings can change.
	wrong := target.SyscallMap["getpid"]
	selector.cache[key] = wrong
	if got := selector.Select(call); got == wrong {
		t.Fatal("resource-dependent selection used a stale cache entry")
	}
}

func TestDefaultSelectorCacheMatchesUncached(t *testing.T) {
	target := testTarget(t)
	cached := newSelectors(target, newRCache())[0].(*defaultCallSelector)
	uncached := newSelectors(target, newRCache())[0].(*defaultCallSelector)
	calls := []*parser.Syscall{
		parser.NewSyscall(1, "socket", []parser.IrType{
			parser.Constant(target.ConstMap["AF_INET"]),
			parser.Constant(target.ConstMap["SOCK_STREAM"]),
			parser.Constant(0),
		}, 0, false, false),
		parser.NewSyscall(1, "socket", []parser.IrType{
			parser.Constant(target.ConstMap["AF_INET6"]),
			parser.Constant(target.ConstMap["SOCK_DGRAM"]),
			parser.Constant(0),
		}, 0, false, false),
		parser.NewSyscall(1, "bpf", []parser.IrType{
			parser.Constant(target.ConstMap["BPF_MAP_CREATE"]),
		}, 0, false, false),
		// Unmatched selections are cached too and must remain identical to the original path.
		parser.NewSyscall(1, "socket", []parser.IrType{
			parser.Constant(^uint64(0)), parser.Constant(^uint64(0)), parser.Constant(^uint64(0)),
		}, 0, false, false),
	}
	for _, call := range calls {
		// Force the reference selector down the original uncached path.
		uncached.cacheable[call.CallName] = false
		want := uncached.Select(call)
		if got := cached.Select(call); got != want {
			t.Errorf("first Select(%q)=%v, want %v", call.CallName, got, want)
		}
		if got := cached.Select(call); got != want {
			t.Errorf("cached Select(%q)=%v, want %v", call.CallName, got, want)
		}
	}
	if got, want := len(cached.cache), len(calls); got != want {
		t.Fatalf("cache contains %d entries, want %d distinct argument tuples", got, want)
	}
}

func TestDefaultSelectorDeclinesUnsafeCacheKeys(t *testing.T) {
	selector := newSelectors(testTarget(t), newRCache())[0].(*defaultCallSelector)
	calls := []*parser.Syscall{
		parser.NewSyscall(1, "socket", nil, 0, false, false),
		parser.NewSyscall(1, "socket", []parser.IrType{
			&parser.GroupType{}, parser.Constant(1), parser.Constant(0),
		}, 0, false, false),
	}
	for _, call := range calls {
		selector.Select(call)
	}
	if len(selector.cache) != 0 {
		t.Fatalf("unsafe argument shapes created %d cache entries", len(selector.cache))
	}
}

func TestKeyctlRestrictionSelection(t *testing.T) {
	target := testTarget(t)
	selector := newSelectors(target, newRCache())[0].(*defaultCallSelector)
	args := []parser.IrType{
		parser.Constant(target.ConstMap["KEYCTL_RESTRICT_KEYRING"]), parser.Constant(0),
		&parser.BufferType{Val: "asymmetric"}, &parser.BufferType{Val: "builtin_trusted"},
	}
	if got := selector.Select(parser.NewSyscall(1, "keyctl", args, 0, false, false)); got == nil || got.Name != "keyctl$restrict_keyring" {
		t.Fatalf("generic restriction selected %v", got)
	}
	args[3] = &parser.GroupType{}
	if got := selector.Select(parser.NewSyscall(1, "keyctl", args, 0, false, false)); got == nil || got.Name != "keyctl$KEYCTL_RESTRICT_KEYRING" {
		t.Fatalf("structured restriction selected %v", got)
	}
}

func TestDefaultSelectorCacheKeyIsUnambiguous(t *testing.T) {
	selector := newSelectors(testTarget(t), newRCache())[0].(*defaultCallSelector)
	key := func(args ...parser.IrType) string {
		call := parser.NewSyscall(1, "test", args, 0, false, false)
		key, ok := selector.cacheKey(call, []int{0, 1})
		if !ok {
			t.Fatal("failed to build cache key")
		}
		return key
	}
	// These tuples collide with delimiter-only encoding but not with length-prefixed fields.
	if a, b := key(&parser.BufferType{Val: "x|1=y"}, &parser.BufferType{Val: "z"}),
		key(&parser.BufferType{Val: "x"}, &parser.BufferType{Val: "y|1=z"}); a == b {
		t.Fatalf("different buffer tuples share key %q", a)
	}
	if a, b := key(parser.Constant(0xa), parser.Constant(0)),
		key(&parser.BufferType{Val: "a"}, parser.Constant(0)); a == b {
		t.Fatalf("constant and buffer arguments share key %q", a)
	}
}

// Copyright 2019 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package proggen

import (
	"testing"

	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
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
	target, err := prog.GetTarget(targets.Linux, targets.AMD64)
	if err != nil {
		t.Fatal(err)
	}
	selector := newSelectors(target, newRCache())[0].(*defaultCallSelector)
	for name, want := range map[string]bool{"ioctl": false, "accept": false, "sendmsg": false, "socket": true} {
		if got := selector.canCache(name, discriminatorArgs[name]); got != want {
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

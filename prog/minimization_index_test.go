// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"fmt"
	"strings"
	"testing"

	"github.com/bits-and-blooms/bloom/v3"
)

func testDependencyCache(numCalls int) *Cache {
	return &Cache{
		Uses:    make([]map[any]bool, numCalls),
		Rets:    make([]map[any]bool, numCalls),
		UsesBFs: make([]*bloom.BloomFilter, numCalls),
		RetsBFs: make([]*bloom.BloomFilter, numCalls),
	}
}

func deserializeDependencyProg(t testing.TB, text string) *Prog {
	t.Helper()
	target, err := GetTarget("test", "64")
	if err != nil {
		t.Fatal(err)
	}
	p, err := target.Deserialize([]byte(text), NonStrict)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func trueIndices(mask []bool) []int {
	var indices []int
	for i, set := range mask {
		if set {
			indices = append(indices, i)
		}
	}
	return indices
}

func benchmarkDependencyProg(tb testing.TB, numComponents int) (*Prog, []int) {
	tb.Helper()
	var text strings.Builder
	callIndices := make([]int, 0, numComponents*2)
	for i := 0; i < numComponents; i++ {
		fmt.Fprintf(&text, "<1>r%d = mutate5(&(0x%x)='./file-%d\\x00', 0x0)\n", i, 0x7f0000000000+i*0x80, i)
		fmt.Fprintf(&text, "<1>mutate9(&(0x%x)='./file-%d\\x00')\n", 0x7f0000000040+i*0x80, i)
		callIndices = append(callIndices, i*2, i*2+1)
	}
	return deserializeDependencyProg(tb, text.String()), callIndices
}

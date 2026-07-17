// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"fmt"
	"testing"

	"github.com/google/syzkaller/pkg/testutil"
)

func TestMemAlloc(t *testing.T) {
	t.Parallel()
	type op struct {
		addr      uint64
		size      int // if positive do noteAlloc, otherwise -- alloc
		alignment uint64
	}
	tests := [][]op{
		{
			// Just sequential allocation.
			{0, -1, 1},
			{64, -64, 1},
			{128, -65, 1},
			{256, -16, 1},
			{320, -8, 1},
		},
		{
			// First reserve some memory and then allocate.
			{0, 1, 1},
			{64, 63, 1},
			{128, 64, 1},
			{192, 65, 1},
			{320, -1, 1},
			{448, 1, 1},
			{384, -1, 1},
			{576, 1, 1},
			{640, -128, 1},
		},
		{
			// Aligned memory allocation.
			{0, -1, 1},
			{512, -1, 512},
			{1024, -1, 512},
			{128, -1, 128},
			{64, -1, 1},
			// 128 used, jumps on.
			{192, -1, 1},
			{256, -1, 1},
			{320, -1, 1},
			{384, -1, 1},
			{448, -1, 1},
			// 512 used, jumps on.
			{576, -1, 1},
			// Next 512 available at 1536.
			{1536, -1, 512},
			// Next smallest available.
			{640, -1, 1},
			// Next 64 byte aligned block.
			{1600, -512, 1},
		},
	}
	for ti, test := range tests {
		t.Run(fmt.Sprint(ti), func(t *testing.T) {
			ma := newMemAlloc(16 << 20)
			for i, op := range test {
				if op.size > 0 {
					t.Logf("#%v: noteAlloc(%v, %v)", i, op.addr, op.size)
					ma.noteAlloc(op.addr, uint64(op.size))
					continue
				}
				t.Logf("#%v: alloc(%v) = %v", i, -op.size, op.addr)
				addr := ma.alloc(nil, uint64(-op.size), op.alignment)
				if addr != op.addr {
					t.Fatalf("bad result %v, expecting %v", addr, op.addr)
				}
			}
		})
	}
}

// allocWithoutCursor is the allocation search used before memAlloc.next was added.
func allocWithoutCursor(ma *memAlloc, size0, alignment0 uint64) uint64 {
	if size0 == 0 {
		size0 = 1
	}
	if alignment0 == 0 {
		alignment0 = 1
	}
	size := (size0 + memAllocGranule - 1) / memAllocGranule
	alignment := (alignment0 + memAllocGranule - 1) / memAllocGranule
	for start, end := uint64(0), ma.size-size; start <= end; start += alignment {
		empty := true
		for i := uint64(0); i < size; i++ {
			if ma.get(start + i) {
				empty = false
				break
			}
		}
		if empty {
			addr := start * memAllocGranule
			ma.noteAlloc(addr, size0)
			return addr
		}
	}
	ma.bankruptcy()
	return allocWithoutCursor(ma, size0, alignment0)
}

func TestMemAllocCursorMatchesOriginalSearch(t *testing.T) {
	const memorySize = memAllocL0Mem * 2
	withCursor := newMemAlloc(memorySize)
	withoutCursor := newMemAlloc(memorySize)
	seed := uint64(1)
	for i := 0; i < 10000; i++ {
		// Mix observed allocations with varied sizes and alignments deterministically.
		seed = seed*6364136223846793005 + 1
		if seed%4 == 0 {
			addr := seed % (memorySize - 4*memAllocGranule)
			size := seed%257 + 1
			withCursor.noteAlloc(addr, size)
			withoutCursor.noteAlloc(addr, size)
			continue
		}
		size := seed%257 + 1
		alignments := [...]uint64{0, 1, 63, 64, 65, 128, 512}
		alignment := alignments[seed%uint64(len(alignments))]
		got := withCursor.alloc(nil, size, alignment)
		want := allocWithoutCursor(withoutCursor, size, alignment)
		if got != want {
			t.Fatalf("operation %d: alloc(%d, %d)=%d, original search returned %d (cursor=%d)",
				i, size, alignment, got, want, withCursor.next*memAllocGranule)
		}
	}
}

func TestMemAllocCursorExhaustive(t *testing.T) {
	const window = 8
	sizes := [...]uint64{0, 1, 63, 64, 65, 127, 128, 129, window * memAllocGranule}
	alignments := [...]uint64{0, 1, 63, 64, 65, 128, 192, 512}
	for mask := 0; mask < 1<<window; mask++ {
		base := newMemAlloc(memAllocL0Mem)
		// Enumerate every occupancy pattern in the window; reserve the tail to bound the model.
		for bit := uint64(0); bit < window; bit++ {
			if mask&(1<<bit) != 0 {
				base.noteAlloc(bit*memAllocGranule, 1)
			}
		}
		base.noteAlloc(window*memAllocGranule, memAllocL0Mem-window*memAllocGranule)
		for _, size := range sizes {
			for _, alignment := range alignments {
				withCursor, withoutCursor := cloneMemAlloc(base), cloneMemAlloc(base)
				got := withCursor.alloc(nil, size, alignment)
				want := allocWithoutCursor(withoutCursor, size, alignment)
				if got != want || withCursor.next != withoutCursor.next || withCursor.buf != withoutCursor.buf {
					t.Fatalf("mask=%08b size=%d alignment=%d: cursor=%d original=%d", mask, size, alignment, got, want)
				}
			}
		}
	}
}

func cloneMemAlloc(src *memAlloc) *memAlloc {
	dst := *src
	// The first-level bitmap points into the embedded buffer and must follow the copy.
	dst.mem[0] = &dst.buf
	return &dst
}

func TestMemAllocCursorBehavior(t *testing.T) {
	ma := newMemAlloc(memAllocL0Mem)
	ma.noteAlloc(1, memAllocGranule)
	if want := uint64(2 * memAllocGranule); ma.next != want/memAllocGranule {
		t.Fatalf("cursor=%d, want %d", ma.next*memAllocGranule, want)
	}

	// An aligned allocation can leave the cursor at the earlier free granule.
	if got := ma.alloc(nil, 1, 512); got != 512 {
		t.Fatalf("aligned allocation=%d, want 512", got)
	}
	if want := uint64(2 * memAllocGranule); ma.next != want/memAllocGranule {
		t.Fatalf("cursor skipped free memory: got %d, want %d", ma.next*memAllocGranule, want)
	}

	ma.bankruptcy()
	if ma.next != 0 {
		t.Fatalf("cursor after bankruptcy=%d, want 0", ma.next)
	}
}

func TestVmaAlloc(t *testing.T) {
	t.Parallel()
	target, err := GetTarget("test", "64")
	if err != nil {
		t.Fatal(err)
	}
	r := newRand(target, testutil.RandSource(t))
	va := newVmaAlloc(1000)
	for i := 0; i < 30; i++ {
		size := r.rand(4) + 1
		page := va.alloc(r, size)
		t.Logf("alloc(%v) = %3v-%3v", size, page, page+size)
	}
}

// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package csource

import (
	"bytes"
	"strings"
	"testing"

	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
	"github.com/google/syzkaller/sys/targets"
)

func TestPtrOffsetChecksumAddresses(t *testing.T) {
	target, err := prog.GetTarget(targets.Linux, targets.AMD64)
	if err != nil {
		t.Fatal(err)
	}
	ctx := &context{opts: Options{CSB: true}, target: target,
		sysTarget: targets.Get(target.OS, target.Arch)}
	addr := target.DataOffset
	var out bytes.Buffer
	ctx.generateCsumInet(&out, addr+8, prog.ExecArgCsum{Chunks: []prog.ExecCsumChunk{
		{Kind: prog.ExecArgCsumChunkData, Value: addr, Size: 4},
		{Kind: prog.ExecArgCsumChunkConst, Value: addr, Size: 2},
	}}, 1)
	// Only the data source and checksum destination are addresses; the equal constant is data.
	if got := strings.Count(out.String(), "+PTR_OFFSET"); got != 2 {
		t.Fatalf("got %d offsets, want 2:\n%s", got, out.String())
	}
}

func TestValInMMapRange(t *testing.T) {
	target, err := prog.GetTarget(targets.Linux, targets.AMD64)
	if err != nil {
		t.Fatal(err)
	}
	ctx := &context{target: target, sysTarget: targets.Get(target.OS, target.Arch)}
	min := target.DataOffset
	max := min + target.NumPages*target.PageSize
	tests := []struct {
		value uint64
		want  bool
	}{
		{min - 1, false}, {min, true}, {max - 1, true}, {max, false}, {max + 0x1000, false},
	}
	for _, test := range tests {
		if got := valInMMapRange(ctx, test.value); got != test.want {
			t.Errorf("valInMMapRange(%#x)=%v, want %v", test.value, got, test.want)
		}
	}
}

func TestDataMmapProgOffsetsGuards(t *testing.T) {
	target, err := prog.GetTarget(targets.Linux, targets.AMD64)
	if err != nil {
		t.Fatal(err)
	}
	p := target.DataMmapProg()
	exec, err := p.SerializeForExec()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := target.DeserializeExec(exec, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := &context{p: p, target: target, sysTarget: targets.Get(target.OS, target.Arch), opts: Options{CSB: true}}
	var calls strings.Builder
	for _, call := range decoded.Calls {
		calls.WriteString(ctx.fmtCallBody(call, false, true))
	}
	if got := strings.Count(calls.String(), "+PTR_OFFSET"); got != 3 {
		t.Fatalf("data mmap and guards are not all relocated: %d offsets", got)
	}
}

func TestPtrOffsetBitfieldDestination(t *testing.T) {
	target, err := prog.GetTarget(targets.Linux, targets.AMD64)
	if err != nil {
		t.Fatal(err)
	}
	ctx := &context{opts: Options{CSB: true}, target: target,
		sysTarget: targets.Get(target.OS, target.Arch)}
	var out bytes.Buffer
	ctx.copyin(&out, new(int), prog.ExecCopyin{Addr: target.DataOffset, Arg: prog.ExecArgConst{
		Size: 2, Value: target.DataOffset, BitfieldLength: 4,
	}})
	// The destination is an address; the numerically equal bitfield value is data.
	if got := strings.Count(out.String(), "+PTR_OFFSET"); got != 1 {
		t.Fatalf("got %d offsets, want 1:\n%s", got, out.String())
	}
}

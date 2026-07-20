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

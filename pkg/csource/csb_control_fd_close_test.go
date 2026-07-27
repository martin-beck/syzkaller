// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package csource

import (
	"strings"
	"testing"

	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
	"github.com/google/syzkaller/sys/targets"
)

func TestCSBRequiresControlFDCloseGuards(t *testing.T) {
	target, err := prog.GetTarget(targets.Linux, targets.AMD64)
	if err != nil {
		t.Fatal(err)
	}
	p, err := target.Deserialize([]byte("r0 = openat(0xffffffffffffff9c, 0x0, 0x0, 0x0)\n"+
		"close(r0)\nclose_range(r0, 0xffffffff, 0x0)\n"), prog.NonStrict)
	if err != nil {
		t.Fatal(err)
	}
	src, _, err := Write(p, Options{CSB: true, Slowdown: 1})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"(uint32_t)csb_fd <= 2 ? -1", "(uint32_t)csb_fd <= 2 ? 3"} {
		if !strings.Contains(string(src), want) {
			t.Fatalf("generated C source does not contain %q", want)
		}
	}
}

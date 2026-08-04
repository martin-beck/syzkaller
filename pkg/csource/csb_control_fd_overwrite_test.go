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

func csbSource(t *testing.T, text string, threaded bool) string {
	t.Helper()
	target, err := prog.GetTarget(targets.Linux, targets.AMD64)
	if err != nil {
		t.Fatal(err)
	}
	p, err := target.Deserialize([]byte(text), prog.NonStrict)
	if err != nil {
		t.Fatal(err)
	}
	src, _, err := Write(p, Options{CSB: true, Threaded: threaded, Slowdown: 1})
	if err != nil {
		t.Fatal(err)
	}
	return string(src)
}

func requireCSource(t *testing.T, src, want string) {
	t.Helper()
	if !strings.Contains(src, want) {
		t.Fatalf("generated C source does not contain %q", want)
	}
}

func TestCSBRejectsControlFDOverwrite(t *testing.T) {
	src := csbSource(t, "r0 = openat(0xffffffffffffff9c, 0x0, 0x0, 0x0)\ndup2(r0, 0x2)\n", false)
	requireCSource(t, src, "(uint32_t)csb_dup_dst <= 2")
}

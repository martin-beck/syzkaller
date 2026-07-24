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

func TestUpstreamDialectPreservesResultDeclaration(t *testing.T) {
	got := (&upstreamDialect{}).declareResults([]uint64{1, 2})
	if want := "uint64 UNIQUE_VAR(ctx->r)[2] = {0x1, 0x2};\n"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestUpstreamDialectRewritesPlainExit(t *testing.T) {
	got := string((&upstreamDialect{}).rewriteExit([]byte("UNIQUE_FUNC(doexit)(1); doexit(2);")))
	if !strings.Contains(got, "UNIQUE_FUNC(doexit)") || got != "UNIQUE_FUNC(doexit)(1); exit(2);" {
		t.Fatalf("unexpected exit rewrite: %q", got)
	}
}

func TestSourceDialectBoundary(t *testing.T) {
	target, err := prog.GetTarget(targets.Linux, targets.AMD64)
	if err != nil {
		t.Fatal(err)
	}
	newContext := func(csb bool) *context {
		return &context{opts: Options{CSB: csb}, target: target,
			sysTarget: targets.Get(target.OS, target.Arch)}
	}
	if got := newContext(false).sourceDialect().pseudoCallName("syz_csb_exit"); got != "syz_csb_exit" {
		t.Fatalf("upstream dialect rewrote helper name to %q", got)
	}
	if got := newContext(true).sourceDialect().pseudoCallName("syz_csb_exit"); got != "syz_csb_exit" {
		t.Fatalf("CSB dialect changed an unnamespaced v0.4 helper: %q", got)
	}
	if got := newContext(false).sourceDialect().pointerOffset(target.DataOffset); got != "" {
		t.Fatalf("upstream dialect relocated an address: %q", got)
	}
	if got := newContext(true).sourceDialect().pointerOffset(target.DataOffset); got != "+PTR_OFFSET" {
		t.Fatalf("CSB dialect did not relocate an address: %q", got)
	}
}

func TestSourceDialectSandboxCall(t *testing.T) {
	dialect := &upstreamDialect{}
	for _, test := range []struct {
		name       string
		sandbox    string
		sandboxArg int
		want       string
	}{
		{name: "empty", want: "loop();"},
		{name: "generic", sandbox: "abrakadabra", want: "do_sandbox_abrakadabra();"},
		{name: "with argument", sandbox: "android", sandboxArg: -1234, want: "do_sandbox_android(-1234);"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := dialect.sandboxCall(test.sandbox, test.sandboxArg); got != test.want {
				t.Fatalf("sandboxCall(%q, %d) = %q, want %q",
					test.sandbox, test.sandboxArg, got, test.want)
			}
		})
	}
}

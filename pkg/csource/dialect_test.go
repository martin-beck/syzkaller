// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package csource

import (
	"strings"
	"testing"
)

func TestUpstreamDialectUsesPlainResultArray(t *testing.T) {
	got := (&upstreamDialect{}).declareResults([]uint64{1, 2})
	if want := "uint64 r[2] = {0x1, 0x2};\n"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestUpstreamDialectRewritesNamespacedExit(t *testing.T) {
	got := string((&upstreamDialect{}).rewriteExit([]byte("UNIQUE_FUNC(doexit)(1); doexit(2);")))
	if strings.Contains(got, "doexit") || got != "exit(1); exit(2);" {
		t.Fatalf("unexpected exit rewrite: %q", got)
	}
}

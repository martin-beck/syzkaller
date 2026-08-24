// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

//go:build !codeanalysis

package parser

import "testing"

func TestUnfinishedClonePrecedesChildCalls(t *testing.T) {
	_, trace, err := ParseData([]byte(`1 clone(child_stack=NULL, flags=17, child_tidptr=0x1000 <unfinished ...>
2 close(3) = 0
1 <... clone resumed>) = 2
1 read(3, "", 1) = 0`), false, -1)
	if err != nil {
		t.Fatal(err)
	}
	if len(trace.Calls) != 3 {
		t.Fatalf("got %d calls, want 3", len(trace.Calls))
	}
	if trace.Calls[0].CallName != "clone" || trace.Calls[0].Pid != 1 || trace.Calls[0].Ret != 2 {
		t.Fatalf("task creation not first: %#v", trace.Calls[0])
	}
	if trace.Calls[1].CallName != "close" || trace.Calls[1].Pid != 2 {
		t.Fatalf("child call not second: %#v", trace.Calls[1])
	}
}

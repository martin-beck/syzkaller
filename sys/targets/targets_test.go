// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package targets

import "testing"

func TestCSBSigreturnIsNotProbed(t *testing.T) {
	for _, dep := range Get(Linux, AMD64).PseudoSyscallDeps["syz_csb_rt_sigreturn"] {
		if dep == "rt_sigreturn" {
			t.Fatal("rt_sigreturn cannot be invoked without a kernel signal frame")
		}
	}
}

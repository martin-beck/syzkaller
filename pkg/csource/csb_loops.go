// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package csource

import "fmt"

func loopIdenticalCalls(calls []string, minRun int) []string {
	if minRun <= 1 {
		minRun = 2
	}
	var out []string
	for i := 0; i < len(calls); {
		j := i + 1
		for j < len(calls) && calls[j] == calls[i] {
			j++
		}
		if run := j - i; run >= minRun {
			out = append(out, fmt.Sprintf("\tfor (size_t csb_runtime_loop = 0; csb_runtime_loop < %d; csb_runtime_loop++) {\n%s\t}\n", run, calls[i]))
		} else {
			out = append(out, calls[i:j]...)
		}
		i = j
	}
	return out
}

// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

//go:build !codeanalysis

package parser

func taskCreationCall(name string) bool {
	switch name {
	case "clone", "clone3", "fork", "vfork":
		return true
	default:
		return false
	}
}

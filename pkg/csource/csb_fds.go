// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package csource

import "github.com/google/syzkaller/prog"

var missedFDResources = make(map[uint64]bool)

type csbFDPolicy struct {
	discardedReturn bool
	copyoutFDs      bool
	fixedReturnArg  int
}

var csbFDPolicies = map[string]csbFDPolicy{
	"dup":   {discardedReturn: true, fixedReturnArg: -1},
	"dup3":  {discardedReturn: true, fixedReturnArg: 1},
	"pipe":  {copyoutFDs: true, fixedReturnArg: -1},
	"pipe2": {copyoutFDs: true, fixedReturnArg: -1},
}

type csbDiscardedFDCleanup struct {
	initial bool
	rerun   bool
}

func csbDiscardedFDCleanupFor(call prog.ExecCall, later []prog.ExecCall) csbDiscardedFDCleanup {
	policy, ok := csbFDPolicies[call.Meta.CallName]
	if !ok || !policy.discardedReturn {
		return csbDiscardedFDCleanup{}
	}
	resultStored := call.Index != prog.ExecNoCopyout
	preserveFixed := policy.fixedReturnArg >= 0 && policy.fixedReturnArg < len(call.Args) &&
		(resultStored || execResultUsed(call.Args[policy.fixedReturnArg], later))
	return csbDiscardedFDCleanup{
		initial: !resultStored && !preserveFixed,
		rerun:   call.Props.Rerun > 0 && !preserveFixed,
	}
}

func resetCSBFDResources() {
	missedFDResources = make(map[uint64]bool)
}

func trackCSBFDResources(call prog.ExecCall) {
	if call.Index != prog.ExecNoCopyout {
		missedFDResources[call.Index] = true
	}
	if policy := csbFDPolicies[call.Meta.CallName]; policy.copyoutFDs {
		for _, copyout := range call.Copyout {
			missedFDResources[copyout.Index] = true
		}
	}
}

func markCSBFDResourceClosed(call prog.ExecCall, callName string) {
	if callName != "close" || len(call.Args) == 0 {
		return
	}
	if fdRes, ok := execArgResultIndex(call.Args[0]); ok {
		missedFDResources[fdRes] = false
	}
}

func execResultUsed(arg prog.ExecArg, calls []prog.ExecCall) bool {
	result, ok := arg.(prog.ExecArgResult)
	if !ok {
		return false
	}
	for _, call := range calls {
		for _, arg := range call.Args {
			if other, ok := arg.(prog.ExecArgResult); ok && other.Index == result.Index {
				return true
			}
		}
		for _, copyin := range call.Copyin {
			if other, ok := copyin.Arg.(prog.ExecArgResult); ok && other.Index == result.Index {
				return true
			}
		}
	}
	return false
}

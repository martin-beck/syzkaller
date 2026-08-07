// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package csource

import (
	"fmt"

	"github.com/google/syzkaller/prog"
)

type emitCallOpts struct {
	initCall            bool
	forceNonblockArg    int
	dynamicFcntlCommand bool
	csbFIONBIO          bool
	csbMQAttr           bool
	dataMmap            bool
}

func localIOResources(p prog.ExecProg, target *prog.Target) map[uint64]bool {
	local := make(map[uint64]bool)
	for _, call := range p.Calls {
		switch call.Meta.CallName {
		case "open", "openat", "openat2", "creat", "mq_open", "eventfd", "eventfd2", "timerfd_create", "inotify_init", "inotify_init1", "fanotify_init", "userfaultfd", "signalfd", "signalfd4":
			if call.Index != prog.ExecNoCopyout {
				local[call.Index] = true
			}
		case "pipe", "pipe2", "socketpair":
			for _, copyout := range call.Copyout {
				local[copyout.Index] = true
			}
		case "dup", "dup2", "dup3":
			if call.Index != prog.ExecNoCopyout && localIOArg(call, local) {
				local[call.Index] = true
			}
		case "fcntl":
			duplicate := fcntlCommand(call, target.ConstMap["F_DUPFD"]) ||
				fcntlCommand(call, target.ConstMap["F_DUPFD_CLOEXEC"])
			if _, dynamic := call.Args[1].(prog.ExecArgResult); dynamic {
				// A dynamic command may duplicate a local descriptor at runtime.
				duplicate = true
			}
			if duplicate &&
				call.Index != prog.ExecNoCopyout && localIOArg(call, local) {
				local[call.Index] = true
			}
		}
	}
	return local
}

func fcntlCommand(call prog.ExecCall, command uint64) bool {
	if call.Meta.CallName != "fcntl" || len(call.Args) < 2 {
		return false
	}
	arg, ok := call.Args[1].(prog.ExecArgConst)
	return ok && arg.Value == command
}

func localIOArg(call prog.ExecCall, local map[uint64]bool) bool {
	if len(call.Args) == 0 {
		return false
	}
	arg, ok := call.Args[0].(prog.ExecArgResult)
	return ok && arg.DivOp == 0 && arg.AddOp == 0 && local[arg.Index]
}

func valInMMapRange(ctx *context, val uint64) bool {
	min := ctx.sysTarget.DataOffset
	max := min + ctx.target.NumPages*ctx.target.PageSize

	// The CSB mapping is exactly [min, max); adjacent values are not pointers into it.
	return val >= min && val < max
}

func (ctx *context) openat2How(ci int) ([3]uint64, bool) {
	fallback := [3]uint64{ctx.target.ConstMap["O_PATH"] | ctx.target.ConstMap["O_CLOEXEC"]}
	if ci >= len(ctx.p.Calls) || len(ctx.p.Calls[ci].Args) < 3 {
		return fallback, false
	}
	ptr, ok := ctx.p.Calls[ci].Args[2].(*prog.PointerArg)
	if !ok || ptr.Res == nil {
		return fallback, false
	}
	how, ok := ptr.Res.(*prog.GroupArg)
	if !ok || len(how.Inner) < 3 {
		return fallback, false
	}
	values := [3]uint64{}
	for i := range values {
		field, ok := how.Inner[i].(*prog.ConstArg)
		if !ok {
			return fallback, false
		}
		values[i] = field.Val
	}
	return values, true
}

func (ctx *context) rewriteCSBOpenat2Arg(call prog.ExecCall, argIndex, callIndex int, value string) string {
	if !ctx.opts.CSB || call.Meta.CallName != "openat2" {
		return value
	}
	switch argIndex {
	case 2:
		return fmt.Sprintf("(intptr_t)&csb_open_how_%d", callIndex)
	case 3:
		return fmt.Sprintf("sizeof(csb_open_how_%d)", callIndex)
	default:
		return value
	}
}

func (ctx *context) protectCSBControlFD(callName string, arg int, val string) string {
	if !ctx.opts.CSB {
		return val
	}
	// CSB uses stdin/stdout/stderr to control and report benchmark operations.
	if callName == "close" && arg == 0 {
		return fmt.Sprintf("({ intptr_t csb_fd = (%s); (uint32)csb_fd <= 2 ? -1 : csb_fd; })", val)
	}
	if callName == "close_range" && arg == 0 {
		return fmt.Sprintf("({ intptr_t csb_fd = (%s); (uint32)csb_fd <= 2 ? 3 : csb_fd; })", val)
	}
	return val
}

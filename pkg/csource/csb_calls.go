// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package csource

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
)

type emitCallOpts struct {
	initCall            bool
	forceNonblockArg    int
	dynamicFcntlCommand bool
	csbFIONBIO          bool
	csbMQAttr           bool
	dataMmap            bool
	localIO             map[uint64]bool
	closeUnusedDup      bool
}

func csbMessageSizes(p *prog.Prog) []uint64 {
	sizes := make([]uint64, len(p.Calls))
	for i, call := range p.Calls {
		if call.Meta.CallName != "recvmsg" && call.Meta.CallName != "sendmsg" || len(call.Args) <= 1 {
			continue
		}
		msgPtr, ok := call.Args[1].(*prog.PointerArg)
		if !ok {
			continue
		}
		msgHeader, ok := msgPtr.Res.(*prog.GroupArg)
		if !ok || len(msgHeader.Inner) <= 3 {
			continue
		}
		iovPtr, ok := msgHeader.Inner[3].(*prog.PointerArg)
		if !ok {
			continue
		}
		iovGroup, ok := iovPtr.Res.(*prog.GroupArg)
		if !ok {
			continue
		}
		for _, msg := range iovGroup.Inner {
			iov, ok := msg.(*prog.GroupArg)
			if !ok || len(iov.Inner) <= 1 {
				continue
			}
			if length, ok := iov.Inner[1].(*prog.ConstArg); ok {
				sizes[i] += length.Val
			}
		}
	}
	return sizes
}

func (ctx *context) prepareEmitCall(w *bytes.Buffer, call *prog.ExecCall, ci int,
	opts emitCallOpts, initCall, dataMmap, resCopyout bool) emitCallOpts {
	opts.initCall = initCall
	opts.forceNonblockArg = -1
	opts.dataMmap = dataMmap
	if !ctx.opts.CSB {
		return opts
	}
	opts.closeUnusedDup = !resCopyout && (call.Meta.CallName == "dup" || call.Meta.CallName == "dup3")
	ctx.prepareFIONBIO(w, *call, ci, &opts)
	ctx.prepareOpenat2(w, *call, ci)
	ctx.prepareFcntl(call, ci, w, &opts)
	ctx.prepareMQAttr(w, *call, ci, &opts)
	ctx.prepareNonblockingOpen(call, &opts)
	return opts
}

func (ctx *context) copyoutMultiple(call prog.ExecCall, resCopyout bool, opts emitCallOpts) bool {
	return len(call.Copyout) > 1 || resCopyout && len(call.Copyout) > 0 ||
		resCopyout && ctx.opts.CSB && ctx.target.OS == targets.Linux && opts.localIO[call.Index]
}

func (ctx *context) prepareFIONBIO(w *bytes.Buffer, call prog.ExecCall, ci int, opts *emitCallOpts) {
	if call.Meta.CallName != "ioctl" || len(call.Args) <= 2 || !localIOArg(call, opts.localIO) {
		return
	}
	cmd, cmdOK := call.Args[1].(prog.ExecArgConst)
	value, valueOK := call.Args[2].(prog.ExecArgConst)
	if cmdOK && valueOK && cmd.Value == ctx.target.ConstMap["FIONBIO"] && valInMMapRange(ctx, value.Value) {
		opts.csbFIONBIO = true
		fmt.Fprintf(w, "\tuint32 csb_fionbio_%d = 1;\n", ci)
	}
}

func (ctx *context) prepareOpenat2(w *bytes.Buffer, call prog.ExecCall, ci int) {
	if call.Meta.CallName != "openat2" {
		return
	}
	how, known := ctx.openat2How(ci)
	if known && how[0]&ctx.target.ConstMap["O_PATH"] == 0 {
		how[0] |= ctx.target.ConstMap["O_NONBLOCK"]
	}
	fmt.Fprintf(w, "\t{\n\tstruct { uint64 flags; uint64 mode; uint64 resolve; } "+
		"csb_open_how_%[1]d = {%[2]d, %[3]d, %[4]d};\n", ci, how[0], how[1], how[2])
}

func (ctx *context) prepareFcntl(call *prog.ExecCall, ci int, w *bytes.Buffer, opts *emitCallOpts) {
	if fcntlCommand(*call, ctx.target.ConstMap["F_SETFL"]) && localIOArg(*call, opts.localIO) {
		args := append([]prog.ExecArg(nil), call.Args...)
		if flags, ok := args[2].(prog.ExecArgConst); ok {
			flags.Value |= ctx.target.ConstMap["O_NONBLOCK"]
			args[2] = flags
			call.Args = args
		} else if _, ok := args[2].(prog.ExecArgResult); ok {
			opts.forceNonblockArg = 2
		}
	}
	if call.Meta.CallName != "fcntl" || len(call.Args) <= 1 || !localIOArg(*call, opts.localIO) {
		return
	}
	command, dynamic := call.Args[1].(prog.ExecArgResult)
	if dynamic {
		opts.dynamicFcntlCommand = true
		fmt.Fprintf(w, "\tintptr_t csb_fcntl_cmd_%d = %s;\n", ci, ctx.resultArgToStr(command))
	}
}

func (ctx *context) prepareMQAttr(w *bytes.Buffer, call prog.ExecCall, ci int, opts *emitCallOpts) {
	if call.Meta.CallName != "mq_getsetattr" || !localIOArg(call, opts.localIO) {
		return
	}
	attr, ok := call.Args[1].(prog.ExecArgConst)
	if !ok || !valInMMapRange(ctx, attr.Value) {
		return
	}
	opts.csbMQAttr = true
	fmt.Fprintf(w, "\tstruct { intptr_t flags; intptr_t maxmsg; intptr_t msgsize; intptr_t curmsgs; "+
		"intptr_t reserved[4]; } csb_mq_attr_%[1]d = {%[2]d, 0, 0, 0};\n",
		ci, ctx.target.ConstMap["O_NONBLOCK"])
}

func (ctx *context) prepareNonblockingOpen(call *prog.ExecCall, opts *emitCallOpts) {
	if ctx.target.OS != targets.Linux {
		return
	}
	flagArg := -1
	switch call.Meta.CallName {
	case "open":
		flagArg = 1
	case "openat":
		flagArg = 2
	case "mq_open":
		flagArg = 1
	case "creat":
		var flags prog.ExecArgConst
		switch mode := call.Args[1].(type) {
		case prog.ExecArgConst:
			flags.Size, flags.Format = mode.Size, mode.Format
		case prog.ExecArgResult:
			flags.Size, flags.Format = mode.Size, mode.Format
		}
		flags.Value = ctx.target.ConstMap["O_WRONLY"] | ctx.target.ConstMap["O_CREAT"] |
			ctx.target.ConstMap["O_TRUNC"] | ctx.target.ConstMap["O_NONBLOCK"]
		call.Meta = ctx.target.SyscallMap["open"]
		call.Args = []prog.ExecArg{call.Args[0], flags, call.Args[1]}
	}
	if flagArg == -1 {
		return
	}
	args := append([]prog.ExecArg(nil), call.Args...)
	if flags, ok := args[flagArg].(prog.ExecArgConst); ok {
		flags.Value |= ctx.target.ConstMap["O_NONBLOCK"]
		args[flagArg] = flags
		call.Args = args
	} else if _, ok := args[flagArg].(prog.ExecArgResult); ok {
		opts.forceNonblockArg = flagArg
	}
}

func (ctx *context) finishEmitCall(w *bytes.Buffer, call prog.ExecCall) {
	if ctx.opts.CSB && call.Meta.CallName == "openat2" {
		fmt.Fprintf(w, "\t}\n")
	}
}

func finishCSBCalls() {
	// Remove resources from network operations which are not created by a connect.
	connectOps := make(map[uint64][]NetOpSize)
	for res := range connectFDs {
		connectOps[res] = netOpsOrHandshake(res)
	}
	NetOpsFDsConnect = connectOps

	acceptOps := make(map[uint64][]NetOpSize)
	for _, res := range sortedUint64AnyKeys(acceptFDs) {
		acceptOps[res] = netOpsOrHandshake(res)
	}
	NetOpsFDsAccept = acceptOps
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

func (ctx *context) formatCSBConstArg(call prog.ExecCall, arg prog.ExecArgConst, i, ci int,
	opts emitCallOpts, value string) string {
	// DataMmapProg includes adjacent guard pages that move with the mapping.
	if ctx.opts.CSB && ((opts.dataMmap && i == 0) ||
		(call.Meta.Name == "ioctl$auto_FIONBIO" && i == 2 && valInMMapRange(ctx, arg.Value)) ||
		(arg.IsPointer && valInMMapRange(ctx, arg.Value))) {
		value += "+PTR_OFFSET"
	}
	value = ctx.rewriteCSBOpenat2Arg(call, i, ci, value)
	if opts.csbFIONBIO && i == 2 {
		value = fmt.Sprintf("(intptr_t)&csb_fionbio_%d", ci)
	}
	if opts.csbMQAttr && i == 1 {
		value = fmt.Sprintf("(intptr_t)&csb_mq_attr_%d", ci)
	}
	if opts.dynamicFcntlCommand && i == 2 {
		value = fmt.Sprintf("(csb_fcntl_cmd_%d == F_SETFL ? (%s | O_NONBLOCK) : %s)", ci, value, value)
	}
	return value
}

func (ctx *context) formatCSBResultArg(call prog.ExecCall, i, ci int, opts emitCallOpts, value string) string {
	if opts.dynamicFcntlCommand && i == 1 {
		value = fmt.Sprintf("csb_fcntl_cmd_%d", ci)
	}
	if opts.dynamicFcntlCommand && i == 2 {
		value = fmt.Sprintf("(csb_fcntl_cmd_%d == F_SETFL ? (%s | O_NONBLOCK) : %s)", ci, value, value)
	}
	if opts.forceNonblockArg == i {
		value = fmt.Sprintf("(%s | O_NONBLOCK)", value)
	}
	return ctx.rewriteCSBOpenat2Arg(call, i, ci, value)
}

func (ctx *context) formatCSBCallBody(callName, funcName string, args []string, native bool) (string, bool) {
	if !ctx.opts.CSB || callName != "dup2" && callName != "dup3" {
		return "", false
	}
	argOffset := 0
	if native {
		argOffset = 1
	}
	src, dst := args[argOffset], args[argOffset+1]
	args[argOffset] = "csb_dup_src"
	args[argOffset+1] = "((uint32)csb_dup_dst <= 2 && (uint32)csb_dup_src != (uint32)csb_dup_dst ? -1 : csb_dup_dst)"
	return fmt.Sprintf("({ intptr_t csb_dup_src = (%s); intptr_t csb_dup_dst = (%s); %v(%v); })",
		src, dst, funcName, strings.Join(args, ", ")), true
}

func (ctx *context) copyoutCSBResult(w *bytes.Buffer, call prog.ExecCall, ci int, opts emitCallOpts) {
	initFDs[call.Index] = true
	if ctx.opts.CSB && ctx.target.OS == targets.Linux && opts.localIO[call.Index] {
		// Set nonblocking mode before publishing the descriptor to concurrent calls.
		if opts.dynamicFcntlCommand {
			fmt.Fprintf(w, "\t\tif (csb_fcntl_cmd_%[1]d == F_DUPFD || "+
				"csb_fcntl_cmd_%[1]d == F_DUPFD_CLOEXEC) "+
				"{ int flags = fcntl(res, F_GETFL); if (flags != -1) "+
				"fcntl(res, F_SETFL, flags | O_NONBLOCK); }\n", ci)
		} else {
			fmt.Fprintf(w, "\t\t{ int flags = fcntl(res, F_GETFL); "+
				"if (flags != -1) fcntl(res, F_SETFL, flags | O_NONBLOCK); }\n")
		}
	}
	if opts.dynamicFcntlCommand && opts.localIO[call.Index] {
		fmt.Fprintf(w, "\t\t%[1]v[%[2]v] = "+
			"(csb_fcntl_cmd_%[3]d == F_DUPFD || csb_fcntl_cmd_%[3]d == F_DUPFD_CLOEXEC) ? res : -1;\n",
			ctx.resultArrayName(), call.Index, ci)
	} else {
		fmt.Fprintf(w, "\t\t%v[%v] = res;\n", ctx.resultArrayName(), call.Index)
	}
}

func (ctx *context) copyoutCSBArg(w *bytes.Buffer, copyout prog.ExecCopyout, value string,
	opts emitCallOpts) bool {
	if !ctx.opts.CSB || ctx.target.OS != targets.Linux || !opts.localIO[copyout.Index] {
		return false
	}
	fmt.Fprintf(w, "\t\tNONFAILING({ int fd = %[1]s; int flags = fcntl(fd, F_GETFL); "+
		"if (flags != -1) fcntl(fd, F_SETFL, flags | O_NONBLOCK); %[2]v[%[3]v] = fd; });\n",
		value, ctx.resultArrayName(), copyout.Index)
	return true
}

func (ctx *context) recordCSBCall(call prog.ExecCall, resCopyout bool, msgSize uint64) {
	if resCopyout {
		missedFDResources[call.Index] = true
	}
	callName := call.Meta.CallName
	if trampoline, ok := ctx.sysTarget.SyscallTrampolines[callName]; ok {
		callName = trampoline
	}
	if callName == "close" {
		if fdRes, ok := execArgResultIndex(call.Args[0]); ok {
			missedFDResources[fdRes] = false
		}
	}
	if callName == "pipe" || callName == "pipe2" {
		for _, copyout := range call.Copyout {
			missedFDResources[copyout.Index] = true
		}
	}
	if fdRes, ok := firstResultIndex(call); ok {
		switch callName {
		case "read", "pread", "pread64", "recv", "recvfrom":
			AddToNetOps(fdRes, NetRead, call.Args[2].(prog.ExecArgConst).Value)
		case "recvmsg":
			AddToNetOps(fdRes, NetRead, msgSize)
		case "write", "pwrite", "pwrite64", "send", "sendto":
			AddToNetOps(fdRes, NetWrite, call.Args[2].(prog.ExecArgConst).Value)
		case "sendmsg":
			AddToNetOps(fdRes, NetWrite, msgSize)
		case "connect":
			if call.Meta.Name == "connect$inet" || call.Meta.Name == "connect$inet6" {
				connectFDs[fdRes] = true
			}
		case "listen":
			listenFDs[fdRes] = true
		}
	}
	if (callName == "accept" || callName == "accept4") &&
		(call.Meta.Name == "accept$inet" || call.Meta.Name == "accept4$inet" ||
			call.Meta.Name == "accept$inet6" || call.Meta.Name == "accept4$inet6") {
		acceptCalls++
		acceptFDs[call.Index] = true
	}
}

func firstResultIndex(call prog.ExecCall) (uint64, bool) {
	if len(call.Args) == 0 {
		return 0, false
	}
	return execArgResultIndex(call.Args[0])
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

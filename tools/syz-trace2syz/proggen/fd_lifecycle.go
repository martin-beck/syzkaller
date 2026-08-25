// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

//go:build !codeanalysis

package proggen

import (
	"fmt"
	"strings"

	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/tools/syz-trace2syz/parser"
)

// fdBinding is a descriptor-table entry. Different tables may contain copies
// of the binding and still refer to the same syzkaller resource producer.
type fdBinding struct {
	arg         prog.Arg
	closeOnExec bool
}

type fdTable struct {
	entries map[uint64]fdBinding
}

func newFDTable() *fdTable {
	return &fdTable{entries: make(map[uint64]fdBinding)}
}

func (table *fdTable) clone() *fdTable {
	copy := newFDTable()
	for fd, binding := range table.entries {
		copy.entries[fd] = binding
	}
	return copy
}

// fdNamespace models only the descriptor identity needed while translating a
// multi-process trace. It does not attempt to replay the process tree.
type fdNamespace struct {
	tables       map[int64]*fdTable
	current      *fdTable
	currentPID   int64
	dup2SameFile *fdBinding
}

func newFDNamespace() *fdNamespace {
	return &fdNamespace{tables: make(map[int64]*fdTable)}
}

func (ns *fdNamespace) activate(pid int64) {
	table := ns.tables[pid]
	if table == nil {
		table = newFDTable()
		ns.tables[pid] = table
	}
	ns.current = table
	ns.currentPID = pid
}

func (ns *fdNamespace) ensureCurrent() *fdTable {
	if ns.current == nil {
		ns.activate(0)
	}
	return ns.current
}

func isFDResource(syzType prog.Type) bool {
	resource, ok := syzType.(*prog.ResourceType)
	return ok && len(resource.Desc.Kind) != 0 && resource.Desc.Kind[0] == "fd"
}

func traceFD(traceType parser.IrType) (uint64, bool) {
	switch value := traceType.(type) {
	case parser.Constant:
		return value.Val(), true
	case *parser.GroupType:
		if len(value.Elems) == 1 {
			return traceFD(value.Elems[0])
		}
	}
	return 0, false
}

func (ctx *context) matchCommand(command uint64, name string) bool {
	nameVal, hasVal := ctx.target.ConstMap[name]
	return hasVal && command == nameVal
}

func (ctx *context) matchFlag(flags uint64, name string) bool {
	nameVal, hasVal := ctx.target.ConstMap[name]
	return hasVal && flags&nameVal != 0
}

func (ctx *context) traceHasFlag(arg parser.IrType, name string) bool {
	value, ok := ctx.target.ConstMap[name]
	return ok && irHasFlag(arg, value)
}

func (ctx *context) traceHasCloneFlag(call *parser.Syscall, name string) bool {
	if len(call.Args) == 0 {
		return false
	}
	for _, arg := range call.Args {
		if strings.Contains(fmt.Sprint(arg), name) {
			return true
		}
	}
	flags := call.Args[0]
	// strace prints clone as clone(child_stack=..., flags=..., ...), while
	// clone3 keeps flags in the first field of struct clone_args.
	if call.CallName == "clone" && len(call.Args) > 1 {
		flags = call.Args[1]
	}
	return ctx.traceHasFlag(flags, name)
}

func (ns *fdNamespace) cache(syzType prog.Type, traceType parser.IrType, arg prog.Arg) bool {
	if !isFDResource(syzType) {
		return false
	}
	fd, ok := traceFD(traceType)
	if !ok {
		return false
	}
	ns.ensureCurrent().entries[fd] = fdBinding{arg: arg}
	return true
}

func (ns *fdNamespace) get(syzType prog.Type, traceType parser.IrType) (prog.Arg, bool) {
	if !isFDResource(syzType) {
		return nil, false
	}
	fd, ok := traceFD(traceType)
	if !ok {
		return nil, false
	}
	return ns.ensureCurrent().entries[fd].arg, true
}

// beginFDCall chooses the descriptor table used to resolve this call's
// resources. dup2(oldfd, oldfd) needs its original binding restored after the
// generic result handling, because the real syscall is a no-op.
func (ctx *context) beginFDCall(call *parser.Syscall) {
	ns := ctx.returnCache.fds
	ns.activate(call.Pid)
	ns.dup2SameFile = nil
	if call.CallName != "dup2" || len(call.Args) < 2 {
		return
	}
	oldFD, oldOK := traceFD(call.Args[0])
	newFD, newOK := traceFD(call.Args[1])
	if !oldOK || !newOK || oldFD != newFD {
		return
	}
	if binding, ok := ns.current.entries[oldFD]; ok {
		copy := binding
		ns.dup2SameFile = &copy
	}
}

// completeFDCall applies successful descriptor-table mutations after argument
// and result resources for the syscall have been generated.
func (ctx *context) completeFDCall(call *parser.Syscall) {
	ctx.returnCache.fds.complete(ctx, call)
}

func (ns *fdNamespace) complete(ctx *context, call *parser.Syscall) {
	if call.Paused || call.Ret < 0 {
		return
	}
	table := ns.ensureCurrent()
	switch call.CallName {
	case "fork", "vfork":
		ns.tables[call.Ret] = table.clone()
	case "clone", "clone3":
		if ctx.traceHasCloneFlag(call, "CLONE_FILES") {
			ns.tables[call.Ret] = table
		} else {
			ns.tables[call.Ret] = table.clone()
		}
	case "execve", "execveat":
		// unshare the table after exec, closing the O_CLOEXEC fds.
		copy := table.clone()
		for fd, binding := range copy.entries {
			if binding.closeOnExec {
				delete(copy.entries, fd)
			}
		}
		// replace the fd table, `ns.currentPid = call.Pid` holds after beginFDCall()
		ns.tables[call.Pid] = copy
		ns.current = copy
	case "unshare":
		if len(call.Args) != 0 && ctx.traceHasFlag(call.Args[0], "CLONE_FILES") {
			ns.replaceCurrent(table.clone())
		}
	case "close":
		if len(call.Args) != 0 {
			if fd, ok := traceFD(call.Args[0]); ok {
				delete(table.entries, fd)
			}
		}
	case "close_range":
		ns.completeCloseRange(ctx, call)
	case "fcntl":
		ns.completeFcntl(ctx, call)
	case "ioctl":
		ns.completeIoctl(ctx, call)
	case "dup2":
		if ns.dup2SameFile != nil {
			if fd, ok := traceFD(call.Args[1]); ok {
				table.entries[fd] = *ns.dup2SameFile
			}
		}
	}
	ns.markCreatedCloexec(ctx, call)
}

func (ns *fdNamespace) replaceCurrent(table *fdTable) {
	ns.tables[ns.currentPID] = table
	ns.current = table
}

func (ns *fdNamespace) completeCloseRange(ctx *context, call *parser.Syscall) {
	if len(call.Args) < 3 {
		return
	}
	first, firstOK := traceFD(call.Args[0])
	last, lastOK := traceFD(call.Args[1])
	flags, flagsOK := traceFD(call.Args[2])
	if !firstOK || !lastOK || !flagsOK {
		return
	}
	if ctx.matchFlag(flags, "CLOSE_RANGE_UNSHARE") {
		ns.replaceCurrent(ns.current.clone())
	}
	for fd, binding := range ns.current.entries {
		if fd < first || fd > last {
			continue
		}
		if ctx.matchFlag(flags, "CLOSE_RANGE_CLOEXEC") {
			binding.closeOnExec = true
			ns.current.entries[fd] = binding
		} else {
			delete(ns.current.entries, fd)
		}
	}
}

func (ns *fdNamespace) completeFcntl(ctx *context, call *parser.Syscall) {
	if len(call.Args) < 2 {
		return
	}
	fd, fdOK := traceFD(call.Args[0])
	command, commandOK := traceFD(call.Args[1])
	if !fdOK || !commandOK {
		return
	}
	binding, found := ns.current.entries[fd]
	switch {
	case ctx.matchCommand(command, "F_GETFD"): // Use the observed result to repair incomplete creator knowledge.
		if found {
			binding.closeOnExec = ctx.matchFlag(uint64(call.Ret), "FD_CLOEXEC")
			ns.current.entries[fd] = binding
		}
	case ctx.matchCommand(command, "F_SETFD"):
		if found && len(call.Args) >= 3 {
			if flags, ok := traceFD(call.Args[2]); ok {
				binding.closeOnExec = ctx.matchFlag(flags, "FD_CLOEXEC")
				ns.current.entries[fd] = binding
			}
		}
	}
}

func (ns *fdNamespace) completeIoctl(ctx *context, call *parser.Syscall) {
	if len(call.Args) < 2 {
		return
	}
	fd, fdOK := traceFD(call.Args[0])
	command, commandOK := traceFD(call.Args[1])
	binding, found := ns.current.entries[fd]
	if !fdOK || !commandOK || !found {
		return
	}
	switch {
	case ctx.matchCommand(command, "FIOCLEX"):
		binding.closeOnExec = true
	case ctx.matchCommand(command, "FIONCLEX"):
		binding.closeOnExec = false
	default:
		return
	}
	ns.current.entries[fd] = binding
}

func (ns *fdNamespace) markCreatedCloexec(ctx *context, call *parser.Syscall) {
	setReturn := func(enabled bool) {
		if !enabled || call.Ret < 0 {
			return
		}
		ns.setCloexec(uint64(call.Ret), true)
	}
	flag := func(index int, name string) bool {
		return index < len(call.Args) && ctx.traceHasFlag(call.Args[index], name)
	}
	switch call.CallName {
	case "open":
		setReturn(flag(1, "O_CLOEXEC"))
	case "openat", "open_by_handle_at":
		setReturn(flag(2, "O_CLOEXEC"))
	case "openat2":
		setReturn(flag(2, "O_CLOEXEC"))
	case "socket":
		setReturn(flag(1, "SOCK_CLOEXEC"))
	case "accept4":
		setReturn(flag(3, "SOCK_CLOEXEC"))
	case "dup3":
		setReturn(flag(2, "O_CLOEXEC"))
	case "fcntl":
		if len(call.Args) >= 2 {
			command, ok := traceFD(call.Args[1])
			setReturn(ok && ctx.matchCommand(command, "F_DUPFD_CLOEXEC"))
		}
	case "epoll_create1":
		setReturn(flag(0, "EPOLL_CLOEXEC"))
	case "inotify_init1":
		setReturn(flag(0, "IN_CLOEXEC"))
	case "userfaultfd":
		setReturn(flag(0, "O_CLOEXEC"))
	case "eventfd2":
		setReturn(flag(1, "EFD_CLOEXEC"))
	case "timerfd_create":
		setReturn(flag(1, "TFD_CLOEXEC"))
	case "signalfd4":
		setReturn(flag(3, "SFD_CLOEXEC"))
	case "memfd_create":
		setReturn(flag(1, "MFD_CLOEXEC"))
	case "fanotify_init":
		setReturn(flag(0, "FAN_CLOEXEC"))
	case "pidfd_open", "pidfd_getfd":
		setReturn(true) // These interfaces always create close-on-exec descriptors.
	case "pipe2":
		ns.setGroupCloexec(call, 0, flag(1, "O_CLOEXEC"))
	case "socketpair":
		ns.setGroupCloexec(call, 3, flag(1, "SOCK_CLOEXEC"))
	}
}

func (ns *fdNamespace) setGroupCloexec(call *parser.Syscall, index int, enabled bool) {
	if !enabled || index >= len(call.Args) {
		return
	}
	for _, fd := range traceFDs(call.Args[index]) {
		ns.setCloexec(fd, true)
	}
}

func traceFDs(arg parser.IrType) []uint64 {
	switch value := arg.(type) {
	case parser.Constant:
		return []uint64{value.Val()}
	case *parser.GroupType:
		var result []uint64
		for _, elem := range value.Elems {
			result = append(result, traceFDs(elem)...)
		}
		return result
	default:
		return nil
	}
}

func (ns *fdNamespace) setCloexec(fd uint64, enabled bool) {
	binding, ok := ns.current.entries[fd]
	if !ok {
		return
	}
	binding.closeOnExec = enabled
	ns.current.entries[fd] = binding
}

// fdArgumentOverride keeps numeric descriptor-selection arguments from being
// mistaken for dependencies on an existing descriptor with the same number.
func (ctx *context) fdArgumentOverride(index int, syzType prog.Type,
	traceArg parser.IrType) (prog.Arg, bool) {
	name := ctx.currentStraceCall.CallName
	literal := (name == "dup2" || name == "dup3") && index == 1 ||
		name == "close_range" && (index == 0 || index == 1)
	resource, ok := syzType.(*prog.ResourceType)
	fd, fdOK := traceFD(traceArg)
	if !literal || !ok || !isFDResource(resource) || !fdOK {
		return nil, false
	}
	return prog.MakeResultArg(resource, prog.DirIn, nil, fd), true
}

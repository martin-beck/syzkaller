// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

//go:build !codeanalysis

package proggen

import (
	"slices"
	"strings"
	"testing"

	"github.com/google/syzkaller/prog"
)

func TestFDLifecycleTargetConstants(t *testing.T) {
	target := testTarget(t)
	for _, name := range []string{
		"CLONE_FILES", "CLOSE_RANGE_CLOEXEC", "CLOSE_RANGE_UNSHARE",
		"EFD_CLOEXEC", "EPOLL_CLOEXEC", "FAN_CLOEXEC", "FD_CLOEXEC",
		"FIOCLEX", "FIONCLEX", "F_DUPFD_CLOEXEC", "F_GETFD", "F_SETFD",
		"IN_CLOEXEC", "MFD_CLOEXEC", "O_CLOEXEC", "SFD_CLOEXEC",
		"SOCK_CLOEXEC", "TFD_CLOEXEC",
	} {
		if _, ok := target.ConstMap[name]; !ok {
			t.Errorf("target is missing %s", name)
		}
	}
}

func TestFDForkCopyKeepsProcessLocalReuseSeparate(t *testing.T) {
	p := parseMergedFDTrace(t, `
1 openat(-100, "/dev/null", 0) = 3
1 dup2(3, 9) = 9
1 close(3) = 0
1 clone(child_stack=NULL, flags=0x1200000|17, child_tidptr=0x1000) = 2
2 openat(-100, "/etc/hostname", 0) = 3
2 dup2(3, 9) = 9
2 close(3) = 0
2 read(9, "host", 4) = 4
1 wait4(-1, 0x1000, 0, 0) = 2
1 read(9, "", 1) = 0
`)
	serialized := string(p.Serialize())
	for _, want := range []string{
		"<2>r3 = dup2(r2, 0x9)",
		"<2>read(r3,",
		"<1>read(r1,",
	} {
		if !strings.Contains(serialized, want) {
			t.Fatalf("missing %q:\n%s", want, serialized)
		}
	}
	if strings.Contains(serialized, "<1>read(r3,") {
		t.Fatalf("parent read was connected to the child's fd reuse:\n%s", serialized)
	}
}

func TestFDCloneFilesSharesReuse(t *testing.T) {
	p := parseMergedFDTrace(t, `
1 openat(-100, "/dev/null", 0) = 3
1 clone(child_stack=NULL, flags=0x400|17, child_tidptr=0x1000) = 2
2 openat(-100, "/etc/hostname", 0) = 4
2 dup2(4, 3) = 3
1 read(3, "host", 4) = 4
`)
	serialized := string(p.Serialize())
	if !strings.Contains(serialized, "<1>read(r1,") {
		t.Fatalf("CLONE_FILES reuse was not visible in the parent:\n%s", serialized)
	}
}

func TestFDExecDropsOnlyCloseOnExecBindings(t *testing.T) {
	p := parseMergedFDTrace(t, `
1 execve("/usr/bin/app", ["app"], 0x0) = 0
1 openat(-100, "/dev/null", 0) = 3
1 dup3(3, 200, 0x80000) = 200
1 dup2(3, 201) = 201
1 execve("/usr/bin/app", ["app"], 0x0) = 0
1 read(200, 0x1000, 1) = -1 EBADF (Bad file descriptor)
1 read(201, "", 1) = 0
`)
	serialized := string(p.Serialize())
	if !strings.Contains(serialized, "<1>read(0xc8,") {
		t.Fatalf("close-on-exec fd still refers to its pre-exec producer:\n%s", serialized)
	}
	if !strings.Contains(serialized, "<1>read(r1,") {
		t.Fatalf("ordinary fd did not retain its pre-exec producer:\n%s", serialized)
	}
	var closedComponent prog.RelatedCallComponent
	prog.ForEachRelatedCallComponentForThread(p, 1, []int{4}, new(prog.Cache),
		func(component prog.RelatedCallComponent) {
			closedComponent = component
		})
	if !slices.Equal(closedComponent.KeepCalls, []int{4}) {
		t.Fatalf("post-exec closed fd retained pre-exec dependencies: %v", closedComponent.KeepCalls)
	}
}

func TestFDExecUnsharesCloneFilesTable(t *testing.T) {
	p := parseMergedFDTrace(t, `
1 openat(-100, "/dev/null", 0x80000) = 3
1 clone(child_stack=NULL, flags=0x400|17, child_tidptr=0x1000) = 2
2 execve("/usr/bin/app", ["app"], 0x0) = 0
2 read(3, 0x1000, 1) = -1 EBADF (Bad file descriptor)
1 read(3, "", 1) = 0
`)
	serialized := string(p.Serialize())
	if !strings.Contains(serialized, "<2>read(0x3,") || !strings.Contains(serialized, "<1>read(r0,") {
		t.Fatalf("exec did not unshare before applying close-on-exec:\n%s", serialized)
	}
}

func TestFDFcntlControlsCloseOnExec(t *testing.T) {
	tests := []struct {
		name  string
		trace string
		want  string
	}{
		{
			name: "set",
			trace: `1 openat(-100, "/dev/null", 0) = 3
1 fcntl(3, 2, 1) = 0
1 execve("/usr/bin/app", ["app"], 0x0) = 0
1 read(3, 0x1000, 1) = -1 EBADF (Bad file descriptor)`,
			want: "<1>read(0x3,",
		},
		{
			name: "clear",
			trace: `1 openat(-100, "/dev/null", 0x80000) = 3
1 fcntl(3, 2, 0) = 0
1 execve("/usr/bin/app", ["app"], 0x0) = 0
1 read(3, "", 1) = 0`,
			want: "<1>read(r0,",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			serialized := string(parseMergedFDTrace(t, test.trace).Serialize())
			if !strings.Contains(serialized, test.want) {
				t.Fatalf("missing %q:\n%s", test.want, serialized)
			}
		})
	}
}

func TestFDIoctlUsesTargetConstants(t *testing.T) {
	target := testTarget(t)
	target.ConstMap["FIOCLEX"] = 0xdead
	target.ConstMap["FIONCLEX"] = 0xbeef
	p := parseMergedFDTraceForTarget(t, target, `
1 openat(-100, "/dev/null", 0) = 3
1 ioctl(3, 0xdead) = 0
1 execve("/usr/bin/app", ["app"], 0x0) = 0
1 read(3, 0x1000, 1) = -1 EBADF (Bad file descriptor)
`)
	serialized := string(p.Serialize())
	if !strings.Contains(serialized, "<1>read(0x3,") {
		t.Fatalf("FIOCLEX was not resolved through target constants:\n%s", serialized)
	}
}

func TestFDCloseRangeUnsharesCloneFilesTable(t *testing.T) {
	p := parseMergedFDTrace(t, `
1 openat(-100, "/dev/null", 0) = 3
1 clone(child_stack=NULL, flags=0x400|17, child_tidptr=0x1000) = 2
2 close_range(3, 3, 2) = 0
2 read(3, 0x1000, 1) = -1 EBADF (Bad file descriptor)
1 read(3, "", 1) = 0
`)
	serialized := string(p.Serialize())
	if !strings.Contains(serialized, "<2>read(0x3,") || !strings.Contains(serialized, "<1>read(r0,") {
		t.Fatalf("close_range did not unshare before closing:\n%s", serialized)
	}
}

func TestFDCloseRangeUsesTargetConstants(t *testing.T) {
	target := testTarget(t)
	target.ConstMap["CLOSE_RANGE_CLOEXEC"] = 0x8000
	p := parseMergedFDTraceForTarget(t, target, `
1 openat(-100, "/dev/null", 0) = 3
1 close_range(3, 3, 0x8000) = 0
1 execve("/usr/bin/app", ["app"], 0x0) = 0
1 read(3, 0x1000, 1) = -1 EBADF (Bad file descriptor)
`)
	serialized := string(p.Serialize())
	if !strings.Contains(serialized, "<1>read(0x3,") {
		t.Fatalf("CLOSE_RANGE_CLOEXEC was not resolved through target constants:\n%s", serialized)
	}
}

func TestFDZeroIsTracked(t *testing.T) {
	p := parseMergedFDTrace(t, `
1 close(0) = 0
1 openat(-100, "/dev/null", 0) = 0
1 fcntl(0, 1) = 0
`)
	serialized := string(p.Serialize())
	if !strings.Contains(serialized, "r0 = openat$null") || !strings.Contains(serialized, "fcntl$getflags(r0,") {
		t.Fatalf("fd zero was not linked to its producer:\n%s", serialized)
	}
}

func TestFDReuseDoesNotPolluteExtractedParentDependencies(t *testing.T) {
	p := parseMergedFDTrace(t, `
1 openat(-100, "/dev/null", 0) = 3
1 dup2(3, 9) = 9
1 clone(child_stack=NULL, flags=17, child_tidptr=0x1000) = 2
2 openat(-100, "/etc/hostname", 0) = 3
2 dup2(3, 9) = 9
2 read(9, "host", 4) = 4
1 read(9, "", 1) = 0
`)
	var got prog.RelatedCallComponent
	cache := new(prog.Cache)
	prog.ForEachRelatedCallComponentForThread(p, 1, []int{6}, cache, func(component prog.RelatedCallComponent) {
		got = component
	})
	for _, index := range []int{0, 1, 6} {
		if !slices.Contains(got.KeepCalls, index) {
			t.Fatalf("parent dependency %d missing from %v", index, got.KeepCalls)
		}
	}
	for _, index := range []int{3, 4, 5} {
		if slices.Contains(got.KeepCalls, index) {
			t.Fatalf("child call %d leaked into parent dependencies %v", index, got.KeepCalls)
		}
	}
}

func parseMergedFDTrace(t *testing.T, input string) *prog.Prog {
	t.Helper()
	return parseMergedFDTraceForTarget(t, testTarget(t), input)
}

func parseMergedFDTraceForTarget(t *testing.T, target *prog.Target, input string) *prog.Prog {
	t.Helper()
	progs, err := ParseData([]byte(strings.TrimSpace(input)), target, false, false, false,
		strings.Count(input, "\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(progs) != 1 || progs[0] == nil {
		t.Fatalf("got %d programs, want one", len(progs))
	}
	return progs[0]
}

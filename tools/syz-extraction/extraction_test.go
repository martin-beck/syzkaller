// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"path/filepath"
	"reflect"
	"testing"

	"github.com/google/syzkaller/prog"
)

type testCall struct {
	name string
	tid  int64
}

func makeTestProg(calls ...testCall) *prog.Prog {
	p := &prog.Prog{}
	for _, call := range calls {
		p.Calls = append(p.Calls, &prog.Call{
			Meta: &prog.Syscall{
				Name:     call.name,
				CallName: call.name,
			},
			StraceTid: call.tid,
		})
	}
	return p
}

func callNames(p *prog.Prog) []string {
	var names []string
	for _, call := range p.Calls {
		names = append(names, call.Meta.Name)
	}
	return names
}

func TestIsPollLike(t *testing.T) {
	for _, name := range []string{"epoll_pwait", "epoll_wait", "poll", "ppoll", "select"} {
		if !isPollLike(name) {
			t.Fatalf("%s should be poll-like", name)
		}
	}
	for _, name := range []string{"read", "write", "openat"} {
		if isPollLike(name) {
			t.Fatalf("%s should not be poll-like", name)
		}
	}
}

func TestFilterOutPollsKeepsOnlyPollBeforeNonPoll(t *testing.T) {
	p := makeTestProg(
		testCall{"poll", 1},
		testCall{"ppoll", 1},
		testCall{"read", 1},
		testCall{"epoll_wait", 2},
		testCall{"write", 2},
		testCall{"select", 3},
	)

	got := callNames(filterOutPolls(p))
	want := []string{"ppoll", "read", "epoll_wait", "write"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestGetOutPrefix(t *testing.T) {
	oldProg := *flagProg
	t.Cleanup(func() {
		*flagProg = oldProg
	})

	tests := []struct {
		path string
		want string
	}{
		{filepath.Join("some", "program_trace_openat_write_0.prog"), "trace"},
		{filepath.Join("some", "thread_trace_openat_write_0.prog"), "trace"},
		{filepath.Join("some", "trace_openat_write_0.prog"), "trace_openat"},
		{filepath.Join("some", "trace.prog"), "trace.prog"},
	}
	for _, test := range tests {
		*flagProg = test.path
		if got := getOutPrefix(); got != test.want {
			t.Fatalf("getOutPrefix(%q) = %q, want %q", test.path, got, test.want)
		}
	}
}

func TestGenSyscallHist(t *testing.T) {
	p := makeTestProg(
		testCall{"openat", 1},
		testCall{"write", 1},
		testCall{"openat", 2},
	)

	got := genSyscallHist(p)
	want := map[string]int{"openat": 2, "write": 1}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestBuildThreadListSortsDescendingAndIndexesCalls(t *testing.T) {
	syscallIDxPerTid = make(map[int64][]int)
	p := makeTestProg(
		testCall{"read", 3},
		testCall{"write", 1},
		testCall{"openat", 3},
		testCall{"close", 2},
	)

	gotThreads := buildThreadList(p)
	wantThreads := []int64{3, 2, 1}
	if !reflect.DeepEqual(gotThreads, wantThreads) {
		t.Fatalf("threads %v, want %v", gotThreads, wantThreads)
	}

	wantIndices := map[int64][]int{
		1: {1},
		2: {3},
		3: {0, 2},
	}
	if !reflect.DeepEqual(syscallIDxPerTid, wantIndices) {
		t.Fatalf("indices %v, want %v", syscallIDxPerTid, wantIndices)
	}
}

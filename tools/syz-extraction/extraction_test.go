// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/google/syzkaller/pkg/stat"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
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

func TestReadProgAllowsAbsoluteFilenames(t *testing.T) {
	oldOS, oldArch, oldProg, oldStrict := *flagOS, *flagArch, *flagProg, *flagStrict
	defer func() {
		*flagOS = oldOS
		*flagArch = oldArch
		*flagProg = oldProg
		*flagStrict = oldStrict
	}()

	progFile := filepath.Join(t.TempDir(), "abs.prog")
	data := []byte("openat(0xffffffffffffff9c, &(0x7f0000000000)='/etc/ld.so.cache\\x00', 0x0, 0x0)\n")
	if err := os.WriteFile(progFile, data, 0600); err != nil {
		t.Fatal(err)
	}

	*flagOS = "linux"
	*flagArch = "amd64"
	*flagProg = progFile
	*flagStrict = false

	p := readProg()
	if len(p.Calls) != 1 {
		t.Fatalf("got %d calls, want 1", len(p.Calls))
	}
}

func TestSanitizeFilename(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
		want []byte
	}{
		{
			name: "absolute",
			in:   []byte("/etc/ld.so.cache\x00"),
			want: []byte("./etc/ld.so.cache\x00"),
		},
		{
			name: "parent",
			in:   []byte("../file\x00"),
			want: []byte("a/../file\x00"),
		},
		{
			name: "double-parent",
			in:   []byte("../../file\x00"),
			want: []byte("a/a/../../file\x00"),
		},
		{
			name: "parent-in-between-escape",
			in:   []byte("foo/../../bar/../../file\x00"),
			want: []byte("a/a/foo/../../bar/../../file\x00"),
		},
		{
			name: "parent-in-between-no-escape",
			in:   []byte("foo/../bar/../file\x00"),
			want: []byte("foo/../bar/../file\x00"),
		},
		{
			name: "bare parent",
			in:   []byte("..\x00"),
			want: []byte("a/..\x00"),
		},
		{
			name: "dot prefixed file",
			in:   []byte("..file\x00"),
			want: []byte("a/..file\x00"),
		},
		{
			name: "all zeros",
			in:   []byte("\x00\x00"),
			want: []byte("\x00\x00"),
		},
	}
	for _, test := range tests {
		got := sanitizeFilename(test.in)
		if !reflect.DeepEqual(got, test.want) {
			t.Fatalf("%s: got %q, want %q", test.name, got, test.want)
		}
	}
}

func TestProcessComponentsMatchesSerialExtraction(t *testing.T) {
	oldMinCalls, oldJobs := *flagMinCalls, *flagJobs
	defer func() {
		*flagMinCalls = oldMinCalls
		*flagJobs = oldJobs
	}()
	*flagMinCalls = 1
	*flagJobs = 4

	target, err := prog.GetTarget("test", "64")
	if err != nil {
		t.Fatal(err)
	}
	p, err := target.Deserialize([]byte(""+
		"<2>r0 = socket(0x111, 0x1000, 0x10000)\n"+
		"<2>ioctl(r0, 0x333, 0x0)\n"+
		"<1>listen(r0)\n"+
		"<1>test$res1(0xffff)\n"+
		"<1>r1 = mutate5(&(0x7f0000000000)='./same-file\\x00', 0x0)\n"+
		"<1>mutate9(&(0x7f0000000040)='./same-file\\x00')\n"+
		"<1>mutate9(&(0x7f0000000100)='./other-file\\x00')\n"+
		"<1>mutate6(r1, &(0x7f0000000140)=\"abcd\", 0x4)\n"), prog.NonStrict)
	if err != nil {
		t.Fatal(err)
	}

	callIndices := []int{2, 3, 4, 5, 6, 7}
	components := prog.RelatedCallComponentsForThread(p, 1, callIndices, newCache(len(p.Calls)))
	got := processComponents(p, components, 0)
	want := serialExtractComponents(p, 1, callIndices)

	if len(got) != len(want) {
		t.Fatalf("got %d results, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].order != want[i].order {
			t.Fatalf("result %d order = %d, want %d", i, got[i].order, want[i].order)
		}
		if !reflect.DeepEqual(got[i].names, want[i].names) {
			t.Fatalf("result %d names = %v, want %v", i, got[i].names, want[i].names)
		}
		gotProg, wantProg := "", ""
		if got[i].prog != nil {
			gotProg = string(got[i].prog.Serialize())
		}
		if want[i].prog != nil {
			wantProg = string(want[i].prog.Serialize())
		}
		if gotProg != wantProg {
			t.Fatalf("result %d program differs\ngot:\n%s\nwant:\n%s", i, gotProg, wantProg)
		}
	}
}

func serialExtractComponents(p *prog.Prog, tid int64, callIndices []int) []extractedComponent {
	cache := newCache(len(p.Calls))
	processedCalls := make([]bool, len(p.Calls))
	nonStartCalls := make([]bool, len(p.Calls))
	var results []extractedComponent

	for _, callIndex := range callIndices {
		if nonStartCalls[callIndex] || p.Calls[callIndex].StraceTid != tid {
			continue
		}
		pF, pCallsOut, keepCalls := generateMinimizedProg(p, callIndex, processedCalls, cache)
		nonStartCalls = prog.Sliceor(prog.Sliceor(pCallsOut, keepCalls), nonStartCalls)
		processedCalls = pCallsOut

		pF = filterOutPolls(pF)
		result := extractedComponent{order: len(results)}
		if len(pF.Calls) >= *flagMinCalls {
			result.prog = pF
			result.names = stat.TopKNames(genSyscallHist(pF), *flagTopCalls)
		}
		results = append(results, result)
	}
	return results
}

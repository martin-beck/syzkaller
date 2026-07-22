// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

//go:build !codeanalysis

package parser

import (
	"fmt"
	"reflect"
	"testing"

	_ "github.com/google/syzkaller/sys"
)

func parseTestData(t *testing.T, data []byte) *TraceTree {
	t.Helper()
	tree, _, err := ParseData(data, true, -1)
	if err != nil {
		t.Fatal(err)
	}
	return tree
}

func TestParseLoopBasic(t *testing.T) {
	tests := []string{
		`open() = 3
		fstat() = 0`,
		`open() = 0x73ffddabc
		fstat() = 0`,
		`open() = -1 ENOSPEC (something)
		fstat() = 0`,
		`open( ,  <unfinished ...>
		<... open resumed>) = 3
		fstat() = 0`,
		`open( ,  <unfinished ...>
		<... open resumed> , 2) = 3
		fstat() = 0`,
		`open( <unfinished ...>
		<... open resumed>) = 3
		fstat() = 0`,
		`open( <unfinished ...>
		<... open resumed>) = 0x44277ffff
		fstat() = 0`,
		`open( <unfinished ...>
		<... open resumed>) = ?
		fstat() = 0`,
		`open( <unfinished ...>
		<... open resumed>) = -1 FLAG (sdfjfjfjf)
		fstat() = 0`,
		`open(1,  <unfinished ...>
		<... open resumed> , 0x1|0x2) = -1 FLAG (sdfjfjfjf)
		fstat() = 0`,
		`open([0x1, 0x2], NULL, {tv_sec=5, tv_nsec=0}, 8 <unfinished ...>
		<... rt_sigtimedwait resumed> )   = 10 (SIGUSR1)
		fstat() = 0`,
		`open(0, 536892418, {c_cc[VMIN]=1, c_cc[VTIME]=0} <unfinished ...>
		<... open resumed> , 0x1|0x2) = -1 FLAG (sdfjfjfjf)
		fstat() = 0`,
		`open(-19) = 0
		 fstat() = 0`,
		`open(1 + 2) = 0
		 fstat() = 0`,
		`open(3 - 1) = 0
		 fstat() = 0`,
		`open(1075599392, 0x20000000) = -1 EBADF (Bad file descriptor)
		 fstat() = 0`,
		`open() = -1 EIO (Input/output error)
		 fstat() = 0`,
		`open(113->114) = -1 EIO (Input/output error)
		 fstat() = 0`,
	}

	for _, test := range tests {
		tree := parseTestData(t, []byte(test))
		if tree.RootPid != -1 {
			t.Fatalf("Incorrect Root Pid: %d", tree.RootPid)
		}

		calls := tree.TraceMap[tree.RootPid].Calls
		if len(calls) != 2 {
			t.Fatalf("expected 2 calls. Got %d instead", len(calls))
		}
		if calls[0].CallName != "open" || calls[1].CallName != "fstat" {
			t.Fatalf("call list should be open->fstat. Got %s->%s", calls[0].CallName, calls[1].CallName)
		}
	}
}

func TestParseSplitFieldValue(t *testing.T) {
	data := []byte(`1 bpf(0x10, {query={target_fd=14, attach_type=0x6, query_flags=0, attach_flags=0, prog_ids= <unfinished ...>
2 close(3) = 0
1 <... bpf resumed>[], prog_cnt=64 => 0}}, 32) = 0`)
	for _, splitThreads := range []bool{false, true} {
		t.Run(fmt.Sprint(splitThreads), func(t *testing.T) {
			tree, trace, err := ParseData(data, splitThreads, -1)
			if err != nil {
				t.Fatal(err)
			}
			callIndex := 1
			if splitThreads {
				trace = tree.TraceMap[1]
				callIndex = 0
			} else if got := []string{trace.Calls[0].CallName, trace.Calls[1].CallName}; !reflect.DeepEqual(got, []string{"close", "bpf"}) {
				t.Fatalf("calls: got %v, want [close bpf]", got)
			}
			call := trace.Calls[callIndex]
			query := call.Args[1].(*GroupType).Elems[0].(*GroupType)
			if call.CallName != "bpf" || len(query.Elems) != 6 {
				t.Fatalf("split query parsed as %#v", call)
			}
		})
	}
}

func TestEvaluateExpressions(t *testing.T) {
	type ExprTest struct {
		line         string
		expectedEval uint64
	}
	tests := []ExprTest{
		{"open(0x1) = 0", 1},
		{"open(1) = 0", 1},
		{"open(0x1|0x2) = 0", 3},
		{"open(0x1|2) = 0", 3},
		{"open(1 << 5) = 0", 32},
		{"open(1 << 5|1) = 0", 33},
		{"open(1 & 0) = 0", 0},
		{"open(1 + 2) = 0", 3},
		{"open(1-2) = 0", ^uint64(0)},
		{"open(4 >> 1) = 0", 2},
		{"open(0700) = 0", 448},
		{"open(0) = 0", 0},
	}
	for i, test := range tests {
		tree := parseTestData(t, []byte(test.line))
		if tree.RootPid != -1 {
			t.Fatalf("failed test: %d. Incorrect Root Pid: %d", i, tree.RootPid)
		}
		calls := tree.TraceMap[tree.RootPid].Calls
		if len(calls) != 1 {
			t.Fatalf("failed test: %d. Expected 1 call. Got %d instead", i, len(calls))
		}
		arg, ok := calls[0].Args[0].(Constant)
		if !ok {
			t.Fatalf("first argument expected to be constant. Got: %s", arg.String())
		}
		if arg.Val() != test.expectedEval {
			t.Fatalf("expected %v != %v", test.expectedEval, arg.Val())
		}
	}
}

func TestParseEmptyStatxFlags(t *testing.T) {
	tree := parseTestData(t, []byte(`1 statx(3, ".", , 0x1101, {}) = 0`))
	call := tree.TraceMap[tree.RootPid].Calls[0]
	arg, ok := call.Args[2].(Constant)
	if !ok || arg.Val() != 0 {
		t.Fatalf("empty statx flags parsed as %#v, want constant zero", call.Args[2])
	}
}

func TestParseTruncatedSchedAffinity(t *testing.T) {
	data := []byte(`901717 sched_setaffinity(901734, 8192, [0, 1, 2, ...] <unfinished ...>
901717 <... sched_setaffinity resumed>) = 0
901717 close(3) = 0`)
	tests := []struct {
		name         string
		splitThreads bool
	}{
		{"merged", false},
		{"split", true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tree, trace, err := ParseData(data, test.splitThreads, -1)
			if err != nil {
				t.Fatal(err)
			}
			if test.splitThreads {
				trace = tree.TraceMap[901717]
			}
			if len(trace.Calls) != 2 {
				t.Fatalf("got %d calls, want resumed affinity and following call", len(trace.Calls))
			}
			call := trace.Calls[0]
			if call.CallName != "sched_setaffinity" || call.Paused || call.Ret != 0 {
				t.Fatalf("unexpected resumed call: %#v", call)
			}
			cpus, ok := call.Args[2].(*GroupType)
			if !ok || len(cpus.Elems) != 3 {
				t.Fatalf("CPU list parsed as %#v, want three known CPUs", call.Args[2])
			}
		})
	}
}

func TestParseLoopPid(t *testing.T) {
	data := `1  open() = 3
			 1  fstat() = 0`

	tree := parseTestData(t, []byte(data))
	if tree.RootPid != 1 {
		t.Fatalf("Incorrect Root Pid: %d", tree.RootPid)
	}

	calls := tree.TraceMap[tree.RootPid].Calls
	if len(calls) != 2 {
		t.Fatalf("Expect 2 calls. Got %d instead", len(calls))
	}
	if calls[0].CallName != "open" || calls[1].CallName != "fstat" {
		t.Fatalf("call list should be open->fstat. Got %s->%s", calls[0].CallName, calls[1].CallName)
	}
}

func TestParseLoop1Child(t *testing.T) {
	data1Child := `1 open() = 3
				   1 clone() = 2
                   2 read() = 16`

	tree := parseTestData(t, []byte(data1Child))
	if len(tree.TraceMap) != 2 {
		t.Fatalf("Incorrect Root Pid. Expected: 2, Got %d", tree.RootPid)
	}
	if tree.RootPid != 1 {
		t.Fatalf("Incorrect Root Pid. Expected: 1, Got %d", tree.RootPid)
	}
	if tree.Ptree[tree.RootPid][0] != 2 {
		t.Fatalf("Expected child to have pid: 2. Got %d", tree.Ptree[tree.RootPid][0])
	} else {
		if len(tree.TraceMap[2].Calls) != 1 {
			t.Fatalf("Child trace should have only 1 call. Got %d", len(tree.TraceMap[2].Calls))
		}
	}
}

func TestParseForkChildren(t *testing.T) {
	data := `1 fork() = 2
2 read() = 1
1 vfork() = 3
3 write() = 1
1 fork() = -1`
	tree := parseTestData(t, []byte(data))
	children := tree.Ptree[tree.RootPid]
	if !reflect.DeepEqual(children, []int64{2, 3}) {
		t.Fatalf("got children %v, want [2 3]", children)
	}
}

func TestParseLoop2Childs(t *testing.T) {
	data2Childs := `1 open() = 3
                    1 clone() = 2
                    2 read() = 16
                    1 clone() = 3
                    3 open() = 3`
	tree := parseTestData(t, []byte(data2Childs))
	if len(tree.TraceMap) != 3 {
		t.Fatalf("Incorrect Root Pid. Expected: 3, Got %d", tree.RootPid)
	}
	if len(tree.Ptree[tree.RootPid]) != 2 {
		t.Fatalf("Expected Pid 1 to have 2 children: Got %d", len(tree.Ptree[tree.RootPid]))
	}
}

func TestParseLoop1Grandchild(t *testing.T) {
	data1Grandchild := `1 open() = 3
						1 clone() = 2
						2 clone() = 3
						3 open() = 4`
	tree := parseTestData(t, []byte(data1Grandchild))
	if len(tree.Ptree[tree.RootPid]) != 1 {
		t.Fatalf("Expect RootPid to have 1 child. Got %d", tree.RootPid)
	}
	if len(tree.Ptree[2]) != 1 {
		t.Fatalf("Incorrect Root Pid. Expected: 3, Got %d", tree.RootPid)

	}
}

func TestParseGroupType(t *testing.T) {
	type irTest struct {
		test string
	}
	tests := []irTest{
		{`open({1, 2, 3}) = 0`},
		{`open([1, 2, 3]) = 0`},
		{`open([1 2 3]) = 0`},
	}
	for _, test := range tests {
		tree := parseTestData(t, []byte(test.test))
		call := tree.TraceMap[tree.RootPid].Calls[0]
		_, ok := call.Args[0].(*GroupType)
		if !ok {
			t.Fatalf("Expected Group type. Got: %#v", call.Args[0])
		}
	}
}

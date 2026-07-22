// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

//go:build !codeanalysis

package parser

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"strings"

	"github.com/google/syzkaller/pkg/log"
)

func parseSyscall(scanner *bufio.Scanner) (int, *Syscall) {
	lex := newStraceLexer(scanner.Bytes())
	ret := StraceParse(lex)
	return ret, lex.result
}

func shouldSkip(line string) bool {
	return strings.Contains(line, "ERESTART") ||
		strings.Contains(line, "+++") ||
		strings.Contains(line, "---") ||
		strings.Contains(line, "<ptrace(SYSCALL):No such process>")
}

func joinSplitValues(data []byte) []byte {
	// A value split immediately after '=' cannot be parsed as two partial trees.
	// Rejoin only matching PID/syscall pairs before parsing either line.
	type pendingCall struct {
		line int
		name string
	}
	lines := strings.Split(string(data), "\n")
	pending := make(map[string]pendingCall)
	removed := make(map[int]bool)
	for i, line := range lines {
		if strings.HasSuffix(line, "= <unfinished ...>") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				if paren := strings.IndexByte(fields[1], '('); paren > 0 {
					pending[fields[0]] = pendingCall{i, fields[1][:paren]}
				}
			}
			continue
		}
		start := strings.Index(line, "<... ")
		end := strings.Index(line, " resumed>")
		if start < 0 || end < start {
			continue
		}
		pid := strings.TrimSpace(line[:start])
		call, ok := pending[pid]
		if !ok || line[start+5:end] != call.name {
			continue
		}
		lines[call.line] = strings.TrimSuffix(lines[call.line], "<unfinished ...>") + line[end+9:]
		removed[i] = true
		delete(pending, pid)
	}
	joined := lines[:0]
	for i, line := range lines {
		if !removed[i] {
			joined = append(joined, line)
		}
	}
	return []byte(strings.Join(joined, "\n"))
}

// ParseData parses each line of a strace file in a loop.
func ParseData(data []byte, splitThreads bool, numLines int) (*TraceTree, *Trace, error) {
	var status string
	tree := NewTraceTree()
	trace := new(Trace)
	lastCalls := make(map[int64](*Syscall))
	// Creating the process tree
	scanner := bufio.NewScanner(bytes.NewReader(joinSplitValues(data)))
	scanner.Buffer(nil, 64<<20)
	curLine := 0
	for scanner.Scan() {
		if curLine%1000 == 0 && numLines > 0 {
			status = fmt.Sprintf("-- Progress [%03.1f/100%%] --", (100.0 * float32(curLine) / float32(numLines)))
			fmt.Fprintf(os.Stderr, "%s\r", status)
		}
		line := scanner.Text()
		curLine++
		if shouldSkip(line) {
			continue
		}
		log.Logf(4, "scanning call: %s", line)
		ret, call := parseSyscall(scanner)
		if call == nil || ret != 0 {
			fmt.Fprintf(os.Stderr, "%s\r", strings.Repeat(" ", len(status)))
			return nil, nil, fmt.Errorf("failed to parse line: %v", line)
		}
		if splitThreads {
			tree.add(call)
		} else {
			if !call.Resumed {
				lastCalls[call.Pid] = call
			} else {
				lastCall := lastCalls[call.Pid]
				if lastCall == nil {
					fmt.Fprintf(os.Stderr, "%s\r", strings.Repeat(" ", len(status)))
					fmt.Fprintf(os.Stderr, "Problem line: %s\n", line)
					fmt.Fprintf(os.Stderr, "Problem call: %#v\n", call)
					panic("Cannot find call to resume!\n")
				}
				lastCall.Args = append(lastCall.Args, call.Args...)
				lastCall.Paused = false
				lastCall.Ret = call.Ret
				call = lastCall
			}

			if !call.Paused {
				trace.Calls = append(trace.Calls, call)
			}
		}
	}
	fmt.Fprintf(os.Stderr, "%s\r", strings.Repeat(" ", len(status)))
	if err := scanner.Err(); err != nil {
		return nil, nil, err
	}
	if splitThreads && len(tree.TraceMap) == 0 {
		return nil, nil, nil
	}
	if splitThreads {
		return tree, nil, nil
	}

	return nil, trace, nil
}

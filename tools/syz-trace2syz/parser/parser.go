// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

//go:build !codeanalysis

package parser

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/google/syzkaller/pkg/log"
)

func parseSyscall(data []byte) (int, *Syscall) {
	lex := newStraceLexer(data)
	ret := StraceParse(lex)
	return ret, lex.result
}

func normalizeStraceLine(line string) string {
	// Large CPU sets are truncated with a trailing ellipsis.
	if strings.Contains(line, "sched_setaffinity(") {
		line = strings.Replace(line, ", ...]", "]", 1)
	}
	// strace 6.8 can render a zero statx flags argument as an empty field.
	// Normalize only that known form so malformed arguments in other calls
	// continue to fail parsing instead of being silently rewritten.
	if strings.Contains(line, " statx(") || strings.HasPrefix(line, "statx(") {
		return strings.Replace(line, ", ,", ", 0,", 1)
	}
	return line
}

func shouldSkip(line string) bool {
	return strings.Contains(line, "ERESTART") ||
		strings.Contains(line, "+++") ||
		strings.Contains(line, "---") ||
		strings.Contains(line, "<ptrace(SYSCALL):No such process>")
}

func joinSplitValues(data []byte) ([]byte, int64) {
	// A value split immediately after '=' cannot be parsed as two partial trees.
	// Rejoin only matching PID/syscall pairs before parsing either line.
	type pendingCall struct {
		line int
		name string
	}
	lines := strings.Split(string(data), "\n")
	pending := make(map[string]pendingCall)
	removed := make(map[int]bool)
	var rootPid int64
	for i, line := range lines {
		fields := strings.Fields(line)
		if rootPid == 0 && len(fields) != 0 && !shouldSkip(line) {
			rootPid = -1
			if pid, err := strconv.ParseInt(fields[0], 10, 64); err == nil {
				rootPid = pid
			}
		}
		start := strings.Index(line, "<... ")
		end := strings.Index(line, " resumed>")
		if start >= 0 && end >= start {
			pid := strings.TrimSpace(line[:start])
			if call, ok := pending[pid]; ok && line[start+5:end] == call.name {
				lines[i] = strings.TrimSuffix(lines[call.line], "<unfinished ...>") + line[end+9:]
				removed[call.line] = true
				delete(pending, pid)
				line = lines[i]
			}
		}
		if paren := strings.IndexByte(line, '('); strings.HasSuffix(line, "= <unfinished ...>") && paren > 0 {
			prefix := strings.TrimSpace(line[:paren])
			parts := strings.Fields(prefix)
			name := parts[len(parts)-1]
			pending[strings.TrimSpace(strings.TrimSuffix(prefix, name))] = pendingCall{i, name}
		}
	}
	joined := lines[:0]
	for i, line := range lines {
		if !removed[i] {
			joined = append(joined, line)
		}
	}
	return []byte(strings.Join(joined, "\n")), rootPid
}

// ParseData parses each line of a strace file in a loop.
func ParseData(data []byte, splitThreads bool, numLines int) (*TraceTree, *Trace, error) {
	var status string
	data, rootPid := joinSplitValues(data)
	tree := NewTraceTree()
	if splitThreads {
		tree.RootPid = rootPid
	}
	trace := new(Trace)
	lastCalls := make(map[int64](*Syscall))
	// Creating the process tree
	scanner := bufio.NewScanner(bytes.NewReader(data))
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
		ret, call := parseSyscall([]byte(normalizeStraceLine(line)))
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

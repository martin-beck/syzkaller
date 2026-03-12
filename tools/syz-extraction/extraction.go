// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"cmp"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"

	"github.com/bits-and-blooms/bloom/v3"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/stat"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
)

type TIDIndices struct {
	Tid     int64
	Indices []int
}

var (
	flagOS   = flag.String("os", runtime.GOOS, "target os")
	flagArch = flag.String("arch", runtime.GOARCH, "target arch")
	flagProg = flag.String("prog", "", "file with program to convert (required)")

	flagStrict      = flag.Bool("strict", false, "parse input program in strict mode")
	flagDeserialize = flag.String("deserialize", "", "(Optional) directory to store deserialized programs")
	flagMinCalls    = flag.Int("minCalls", 5, "minimum number of remaining syscalls after minimization")
	flagTopCalls    = flag.Int("topCalls", 2, "number of most used usyscalls to be used for file name generation")

	syscallIDxPerTid = make(map[int64][]int)
)

func help() {
	flag.Usage = func() {
		flag.PrintDefaults()
	}
	flag.Parse()
	if *flagProg == "" {
		flag.Usage()
		os.Exit(1)
	}
}

func readProg() (p *prog.Prog) {
	target, err := prog.GetTarget(*flagOS, *flagArch)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	data, err := os.ReadFile(*flagProg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to read prog file: %v\n", err)
		os.Exit(1)
	}
	mode := prog.NonStrict
	if *flagStrict {
		mode = prog.Strict
	}
	p, err = target.Deserialize(data, mode)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to deserialize the program: %v\n", err)
		os.Exit(1)
	}
	return
}

func generateMinimizedProg(p *prog.Prog, callIndex0 int, processedCallsIn []bool, c *prog.Cache) (pOut *prog.Prog, processedCalls []bool, keepCalls []bool) {
	pOut, processedCalls, keepCalls = prog.RemoveUnrelatedCallsFast(p, callIndex0, processedCallsIn, c)
	return
}

func isPollLike(syscallName string) bool {
	pollLikes := []string{
		"epoll_pwait",
		"epoll_wait",
		"poll",
		"ppoll",
		"select",
	}
	for _, v := range pollLikes {
		if syscallName == v {
			return true
		}
	}
	return false
}

func filterOutPolls(p *prog.Prog) *prog.Prog {
	notPolls := make([]bool, len(p.Calls))
	prevPoll := make(map[int64]int)
	for idx, c := range p.Calls {
		if isPollLike(c.Meta.Name) {
			prevPoll[c.StraceTid] = idx
		} else if oldIdx, ok := prevPoll[c.StraceTid]; ok {
			notPolls[oldIdx] = true // Keep the last poll in the sequence.
			delete(prevPoll, c.StraceTid)
			notPolls[idx] = true
		} else {
			notPolls[idx] = true
		}
	}
	px := p.CloneFilter(notPolls)
	return px
}

func getOutPrefix() string {
	prefixLen := 2
	progBase := filepath.Base(*flagProg)
	splitBase := strings.Split(progBase, "_")
	if len(splitBase) > 1 && (splitBase[0] == "thread" || splitBase[0] == "program") {
		progBase = strings.Join(splitBase[1:], "_")
		prefixLen = 1
	}
	splitBase = strings.Split(progBase, "_")
	if len(splitBase) < prefixLen {
		prefixLen = len(splitBase)
	}
	outPrefix := strings.Join(splitBase[:prefixLen], "_")
	return outPrefix
}

func newCache(numCalls int) *prog.Cache {
	c := new(prog.Cache)
	c.Uses = make([]map[any]bool, numCalls)
	c.Rets = make([]map[any]bool, numCalls)
	c.UsesBFs = make([]*bloom.BloomFilter, numCalls)
	c.RetsBFs = make([]*bloom.BloomFilter, numCalls)
	return c
}

func generateAllProgs(p *prog.Prog, threadList []int64) {
	numCalls := len(p.Calls)
	outPrefixesIdx := make(map[string]int)
	outPrefix := getOutPrefix()

	fmt.Fprintf(os.Stderr, "Total number of syscalls: %d\n", numCalls)

	c := newCache(numCalls)

	totalStartSyscalls := 0
	usedStartSyscalls := 0
	for _, tid := range threadList {
		totalStartSyscalls += len(syscallIDxPerTid[tid])
	}
	var status string

	// go over all thread IDs in decreasing depth starting with the highest depth
	for idx, tid := range threadList {
		processedCalls := make([]bool, numCalls)
		nonStartCalls := make([]bool, numCalls)

		numCallsTid := len(syscallIDxPerTid[tid])
		fmt.Printf("[%d/%d] Working on TID %d - %d syscalls\n", idx+1, len(threadList), tid, numCallsTid)

		for subIdx, i := range syscallIDxPerTid[tid] {
			usedStartSyscalls++
			if !nonStartCalls[i] && p.Calls[i].StraceTid == tid {
				if usedStartSyscalls%100 == 0 {
					status = fmt.Sprintf("-- Progress TID [%03.1f/100%%] -- Progress overall [%03.1f/100%%] --", (100.0 * float32(subIdx) / float32(numCallsTid)), (100 * float32(usedStartSyscalls) / float32(totalStartSyscalls)))
					fmt.Fprintf(os.Stderr, "%s\r", status)
				}
				pF, pCallsOut, keepCalls := generateMinimizedProg(p, i, processedCalls, c)
				nonStartCalls = prog.Sliceor(prog.Sliceor(pCallsOut, keepCalls), nonStartCalls)
				processedCalls = pCallsOut

				if len(pF.Calls) >= *flagMinCalls {
					pF = filterOutPolls(pF)

					scallHist := genSyscallHist(pF)
					topNames := stat.TopKNames(scallHist, *flagTopCalls)
					prefix := outPrefix + "_" + strings.Join(topNames, "_")

					_, ok := outPrefixesIdx[prefix]
					if !ok {
						outPrefixesIdx[prefix] = 0
					} else {
						outPrefixesIdx[prefix]++
					}

					fmt.Fprintf(os.Stderr, "%s\r", strings.Repeat(" ", len(status)))
					fmt.Fprintf(os.Stderr, "    Extracted %d syscalls into %s_%d\n", len(pF.Calls), prefix, outPrefixesIdx[prefix])
					saveProg2File(pF, prefix, outPrefixesIdx[prefix])
				}
			}
			i--
		}
		fmt.Fprintf(os.Stderr, "%s\r", strings.Repeat(" ", len(status)))
	}
}

func genSyscallHist(p *prog.Prog) map[string]int {
	hist := make(map[string]int)

	for _, call := range p.Calls {
		_, ok := hist[call.Meta.CallName]
		if !ok {
			hist[call.Meta.CallName] = 1
		} else {
			hist[call.Meta.CallName]++
		}
	}

	return hist
}

func saveProg2File(p *prog.Prog, prefix string, index int) {
	outName := filepath.Join(*flagDeserialize, "min_"+prefix+"_"+strconv.Itoa(index)+".prog")
	if err := osutil.WriteFile(outName, p.Serialize()); err != nil {
		log.Fatalf("failed to output file: %v", err)
	}
}

// a map from TID to clone depth
type ThreadSet map[int64]bool

func buildThreadList(p *prog.Prog) []int64 {
	tt := make(ThreadSet)
	tl := make([]int64, 0)

	for idx, c := range p.Calls {
		tt[c.StraceTid] = true
		tid := c.StraceTid
		syscallIDxPerTid[tid] = append(syscallIDxPerTid[tid], idx)
	}
	for t := range tt {
		tl = append(tl, t)
	}

	slices.SortStableFunc(tl, func(a, b int64) int {
		return cmp.Compare(a, b)
	})
	slices.Reverse(tl)

	return tl
}

func main() {
	help()

	p := readProg()

	threads := buildThreadList(p)

	for ci, c := range p.Calls {
		switch c.Meta.Name {
		case "io_setup":
			fmt.Fprintf(os.Stderr, "  Idx %d io_setup\n", ci)
			fmt.Fprintf(os.Stderr, "    Arg 1 io_context_t: %#v\n", c.Args[1])
		case "io_getevents":
			fmt.Fprintf(os.Stderr, "  Idx %d io_getevents\n", ci)
			fmt.Fprintf(os.Stderr, "    Arg 0 io_context_t: %#v\n", c.Args[0])
			return
		}
	}

	return

	generateAllProgs(p, threads)
}

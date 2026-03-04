// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/bits-and-blooms/bloom/v3"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/stat"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
)

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

func countSyscalls(p *prog.Prog, tid int64) int64 {
	num := int64(0)
	for _, c := range p.Calls {
		if c.StraceTid == tid {
			num++
		}
	}
	return num
}

func generateAllProgs(p *prog.Prog, threadList []int64) (pF *prog.Prog) {
	numCalls := len(p.Calls)
	processedCalls := make([]bool, numCalls)
	processedCalls[numCalls-1] = false
	keepCalls := make([]bool, numCalls)
	nonStartCalls := make([]bool, numCalls)
	outPrefixesIdx := make(map[string]int)
	prefixLen := 2
	c := new(prog.Cache)
	c.Uses = make([]map[any]bool, numCalls)
	c.Rets = make([]map[any]bool, numCalls)
	c.UsesBFs = make([]*bloom.BloomFilter, numCalls)
	c.RetsBFs = make([]*bloom.BloomFilter, numCalls)
	fmt.Fprintf(os.Stderr, "Total number of syscalls: %d\n", numCalls)

	totalStartSyscalls := 0
	usedStartSyscalls := 0
	for _, tid := range threadList {
		totalStartSyscalls += len(syscallIDxPerTid[tid])
	}
	var status string

	// go over all thread IDs in decreasing depth starting with the highest depth
	for idx, tid := range threadList {
		numCallsTid := len(syscallIDxPerTid[tid])
		if len(syscallIDxPerTid[tid]) < *flagMinCalls {
			fmt.Printf("[%d/%d] Skipping TID %d - not enough syscalls %d\n", idx+1, len(threadList), tid, numCallsTid)
			usedStartSyscalls += numCallsTid
			continue
		}
		fmt.Printf("[%d/%d] Working on TID %d - %d syscalls\n", idx+1, len(threadList), tid, numCallsTid)

		for subIdx, i := range syscallIDxPerTid[tid] {
			usedStartSyscalls++
			if !nonStartCalls[i] && p.Calls[i].StraceTid == tid {
				if usedStartSyscalls%100 == 0 {
					status = fmt.Sprintf("-- Progress TID [%03.1f/100%%] -- Progress overall [%03.1f/100%%] --", (100.0 * float32(subIdx) / float32(numCallsTid)), (100 * float32(usedStartSyscalls) / float32(totalStartSyscalls)))
					fmt.Fprintf(os.Stderr, "%s\r", status)
				}
				pF, processedCalls, keepCalls = generateMinimizedProg(p, i, processedCalls, c)
				nonStartCalls = prog.Sliceor(prog.Sliceor(processedCalls, keepCalls), nonStartCalls)

				if len(pF.Calls) >= *flagMinCalls {
					prefixLen = 2
					progBase := filepath.Base(*flagProg)
					splitBase := strings.Split(progBase, "_")
					if len(splitBase) > 1 && (splitBase[0] == "thread" || splitBase[0] == "program") {
						progBase = strings.Join(splitBase[1:], "_")
						prefixLen = 1
					}

					scallHist := genSyscallHist(pF)
					topNames := stat.TopKNames(scallHist, *flagTopCalls)
					outPrefix := strings.Join(strings.Split(progBase, "_")[:prefixLen], "_") + "_" + strings.Join(topNames, "_")
					_, ok := outPrefixesIdx[outPrefix]
					if !ok {
						outPrefixesIdx[outPrefix] = 0
					} else {
						outPrefixesIdx[outPrefix]++
					}

					pF = filterOutPolls(pF)

					fmt.Fprintf(os.Stderr, "%s\r", strings.Repeat(" ", len(status)))
					fmt.Fprintf(os.Stderr, "    Extracted %d syscalls into %s_%d\n", len(pF.Calls), outPrefix, outPrefixesIdx[outPrefix])
					saveProg2File(pF, outPrefix, outPrefixesIdx[outPrefix])
				}
			}
			i--
		}
		fmt.Fprintf(os.Stderr, "%s\r", strings.Repeat(" ", len(status)))
	}

	return
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
	// log.Logf(0, "Stored program %s", outName)
}

// a map from TID to clone depth
type ThreadSet map[int64]bool

func buildThreadList(p *prog.Prog) []int64 {
	tt := make(ThreadSet)
	tl := make([]int64, 0)

	for _, c := range p.Calls {
		tt[c.StraceTid] = true
	}
	for t := range tt {
		tl = append(tl, t)
	}
	return tl
}

func populateSyscallIdx(p *prog.Prog) {
	for idx, c := range p.Calls {
		tid := c.StraceTid
		syscallIDxPerTid[tid] = append(syscallIDxPerTid[tid], idx)
	}
}

func main() {
	help()

	p := readProg()

	threads := buildThreadList(p)

	populateSyscallIdx(p)

	generateAllProgs(p, threads)
}

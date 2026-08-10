// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package csource

import (
	"errors"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/google/syzkaller/prog"
)

type NetOp int

var ErrUnsupportedCSBNetwork = errors.New("unsupported CSB network topology")

const (
	NetRead NetOp = iota
	NetWrite
)

type NetOpSize struct {
	Op   NetOp
	Num  uint64
	Size uint64
}

var (
	missedFDResources = make(map[uint64](bool))
	connectFDs        = make(map[uint64](bool))
	acceptFDs         = make(map[uint64](bool))
	acceptCalls       int
	readFDSizes       = make(map[uint64](uint64))
	NetOpsFDs         = make(map[uint64]([]NetOpSize))
	NetOpsFDsConnect  = make(map[uint64]([]NetOpSize))
	NetOpsFDsAccept   = make(map[uint64]([]NetOpSize))
	listenFDs         = make(map[uint64](bool))
	initFDs           = make(map[uint64](bool))
)

func AddToNetOps(res uint64, op NetOp, size uint64) {
	netops, ok := NetOpsFDs[res]

	// no operation for this file descriptor recorded yet, initialize
	if !ok {
		NetOpsFDs[res] = make([]NetOpSize, 0)
		netops = NetOpsFDs[res]
	}

	// empty list of operations, or current operation is write -> append
	if len(netops) == 0 || op == NetWrite {
		nosNew := NetOpSize{op, 1, size}
		netops = append(netops, nosNew)
		NetOpsFDs[res] = netops
		return
	}

	// op is Read
	nosLast := netops[len(netops)-1]
	if nosLast.Op == NetWrite {
		nosNew := NetOpSize{op, 1, size}
		netops = append(netops, nosNew)
		NetOpsFDs[res] = netops
		return
	}

	// Last op was also Read, combine into total
	nosNew := NetOpSize{op, nosLast.Num + 1, nosLast.Size + size}
	netops[len(netops)-1] = nosNew
	NetOpsFDs[res] = netops
}

var netOpName = map[NetOp]string{
	NetRead:  "r",
	NetWrite: "w",
}

func (no NetOp) String() string {
	return netOpName[no]
}

func (nos NetOpSize) String() string {
	return strconv.FormatUint(nos.Num, 10) + netOpName[nos.Op] + strconv.FormatUint(nos.Size, 10)
}

func NetOpsString(res uint64, ops map[uint64][]NetOpSize) string {
	netops, ok := ops[res]
	var netopstring string
	// no operation for this file descriptor recorded yet, initialize
	if !ok {
		return ""
	}

	for idx, nos := range netops {
		if idx != 0 {
			netopstring += "-"
		}
		netopstring += nos.String()
	}
	return netopstring
}

func netOpsOrHandshake(res uint64) []NetOpSize {
	if ops := NetOpsFDs[res]; len(ops) != 0 {
		return ops
	}
	return []NetOpSize{{Op: NetRead, Num: 1, Size: 1}}
}

func resetGenerationState() {
	missedFDResources = make(map[uint64]bool)
	connectFDs = make(map[uint64]bool)
	acceptFDs = make(map[uint64]bool)
	acceptCalls = 0
	readFDSizes = make(map[uint64]uint64)
	NetOpsFDs = make(map[uint64][]NetOpSize)
	NetOpsFDsConnect = make(map[uint64][]NetOpSize)
	NetOpsFDsAccept = make(map[uint64][]NetOpSize)
	listenFDs = make(map[uint64]bool)
	initFDs = make(map[uint64]bool)
}

func validateCSBNetwork() error {
	if len(NetOpsFDsConnect) != 0 && len(NetOpsFDsAccept) != 0 {
		return fmt.Errorf("%w: both client and server sequences", ErrUnsupportedCSBNetwork)
	}
	if acceptCalls > 1 {
		return fmt.Errorf("%w: multiple server sequences", ErrUnsupportedCSBNetwork)
	}
	var first []NetOpSize
	for _, fd := range sortedUint64AnyKeys(NetOpsFDsConnect) {
		if first == nil {
			first = NetOpsFDsConnect[fd]
		} else if !slices.Equal(first, NetOpsFDsConnect[fd]) {
			return fmt.Errorf("%w: different client sequences", ErrUnsupportedCSBNetwork)
		}
	}
	return nil
}

func (ctx *context) mapToArrayStringBool(inMap map[string]bool) string {
	keys := make([]string, 0, len(inMap))
	for key := range inMap {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	values := make([]string, 0, len(keys))
	for _, key := range keys {
		values = append(values, fmt.Sprintf("\"%s\"", key))
	}
	return strings.Join(values, ",")
}

func sortedUint64AnyKeys[V bool | uint64 | string | []NetOpSize](inMap map[uint64]V) []uint64 {
	keys := make([]uint64, 0, len(inMap))
	for key := range inMap {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		return keys[i] < keys[j]
	})
	return keys
}

func toStringArray[V uint64 | string | []NetOpSize](opMap map[uint64]V) (string, error) {
	opsSeq := make([]string, 0, len(opMap))
	for _, res := range sortedUint64AnyKeys(opMap) {

		v_string := ""
		switch val := any(opMap).(type) {
		case map[uint64]uint64:
			v_string = fmt.Sprint(val[res])

		case map[uint64]string:
			v_string = fmt.Sprintf("\"%s\"", val[res])

		case map[uint64][]NetOpSize:
			v_string = "\"" + NetOpsString(res, val) + "\""

		default:
			return "", fmt.Errorf("Unknown type for array to string conversion! %T\n", opMap)
		}

		opsSeq = append(opsSeq, v_string)
	}
	return strings.Join(opsSeq, ", "), nil
}

func execArgResultIndex(arg prog.ExecArg) (uint64, bool) {
	result, ok := arg.(prog.ExecArgResult)
	return result.Index, ok
}

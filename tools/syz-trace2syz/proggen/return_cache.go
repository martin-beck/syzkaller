// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package proggen

import (
	"strconv"

	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/tools/syz-trace2syz/parser"
)

type returnCache struct {
	resources map[string]prog.Arg
	fds       *fdNamespace
}

func newRCache() *returnCache {
	return &returnCache{
		resources: make(map[string]prog.Arg),
		fds:       newFDNamespace(),
	}
}

func returnCacheKey(syzType prog.Type, traceType parser.IrType) string {
	a, ok := syzType.(*prog.ResourceType)
	if !ok {
		log.Fatalf("caching non resource type")
	}
	switch t := traceType.(type) {
	case parser.Constant:
		return a.Desc.Kind[0] + "-" + strconv.FormatUint(t.Val(), 16)
	default:
		return a.Desc.Kind[0] + "-" + traceType.String()
	}
}

func (r *returnCache) cache(syzType prog.Type, traceType parser.IrType, arg prog.Arg) {
	log.Logf(2, "caching resource: %v", returnCacheKey(syzType, traceType))
	if r.fds.cache(syzType, traceType, arg) {
		return
	}
	r.resources[returnCacheKey(syzType, traceType)] = arg
}

func (r *returnCache) get(syzType prog.Type, traceType parser.IrType) prog.Arg {
	if result, handled := r.fds.get(syzType, traceType); handled {
		return result
	}
	result := r.resources[returnCacheKey(syzType, traceType)]
	log.Logf(2, "fetching resource: %s, val: %s", returnCacheKey(syzType, traceType), result)
	return result
}

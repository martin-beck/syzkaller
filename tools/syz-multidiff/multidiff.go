package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"sort"
	"strings"

	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
)

var (
	flagOS         = flag.String("os", runtime.GOOS, "target os")
	flagArch       = flag.String("arch", runtime.GOARCH, "target arch")
	flagStrict     = flag.Bool("strict", false, "parse input programs in strict mode")
	flagGraphviz   = flag.Bool("graphviz", false, "write all file relations as Graphviz DOT instead of text")
	flagListFiles  = flag.Bool("listfiles", false, "write file names after folding, one per line")
	flagStdin      = flag.Bool("stdin", false, "read additional input file names from stdin, one per line")
	flagFold       = flag.Int("fold", 0, fmt.Sprintf("fold relation clusters up to level 0-%d", maxFold))
	flagTransitive = flag.Bool("transitive", true,
		"merge relation clusters transitively (use -transitive=false for pair/signature clusters)")
)

type relation int

const (
	// Keep these ordered from strongest to weakest. Fold N folds precisely the
	// relations whose numeric value is below N.
	relationSame relation = iota
	relationSimilar
	relationSignificantlyDifferent
	relationCompletelyDifferent
	maxFold = int(relationCompletelyDifferent)
)

// `fold` is the user input for the folding level. The function returns true when the relation should be folded.
func foldsRelation(fold int, rel relation) bool {
	return fold > int(rel)
}

func (rel relation) String() string {
	switch rel {
	case relationSame:
		return "completely same"
	case relationSimilar:
		return "similar up to a constant"
	case relationSignificantlyDifferent:
		return "significantly different"
	case relationCompletelyDifferent:
		return "completely different"
	default:
		panic("unknown relation")
	}
}

type signedOffset struct {
	negative  bool
	magnitude uint64
}

func makeOffset(from, to uint64) signedOffset {
	if to >= from {
		return signedOffset{magnitude: to - from}
	}
	return signedOffset{negative: true, magnitude: from - to}
}

func (off signedOffset) String() string {
	if off.negative {
		return fmt.Sprintf("-0x%x", off.magnitude)
	}
	return fmt.Sprintf("+0x%x", off.magnitude)
}

type replacement struct {
	location string
	from     string
	to       string
}

type comparison struct {
	relation      relation
	arguments     []string
	pointerOffset *signedOffset
	replacements  []replacement
}

func (cmp comparison) signature() string {
	return strings.Join(cmp.arguments, "\x00")
}

type inputProgram struct {
	name string
	prog *prog.Prog
}

type exactCluster struct {
	representative int
	members        []int
}

type representativeRelation struct {
	left       int
	right      int
	comparison comparison
}

type analysis struct {
	files     []inputProgram
	clusters  []exactCluster
	relations []representativeRelation
}

type reportSelection struct {
	similar             []relationCluster
	significant         []relationCluster
	relations           []representativeRelation
	completelyDifferent []int
}

type relationTier struct {
	kind     relation
	clusters []relationCluster
}

func (selection reportSelection) weakerTiers() []relationTier {
	return []relationTier{
		{relationSimilar, selection.similar},
		{relationSignificantlyDifferent, selection.significant},
	}
}

func main() {
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "usage: syz-multidiff [flags] [file.prog ...]\n")
		flag.PrintDefaults()
	}
	flag.Parse()
	if err := validateOutputModes(*flagGraphviz, *flagListFiles); err != nil {
		fatalf("%v", err)
	}
	if *flagFold < 0 || *flagFold > maxFold {
		fatalf("-fold must be between 0 and %d, got %d", maxFold, *flagFold)
	}
	inputNames := append([]string{}, flag.Args()...)
	if *flagStdin {
		stdinNames, err := readInputNames(os.Stdin)
		if err != nil {
			fatalf("failed to read input file list from stdin: %v", err)
		}
		inputNames = append(inputNames, stdinNames...)
	}
	if len(inputNames) == 0 {
		flag.Usage()
		os.Exit(1)
	}

	target, err := prog.GetTarget(*flagOS, *flagArch)
	if err != nil {
		fatalf("failed to get target: %v", err)
	}
	mode := prog.NonStrictUnsafe
	if *flagStrict {
		mode = prog.StrictUnsafe
	}
	files := make([]inputProgram, 0, len(inputNames))
	for _, name := range inputNames {
		data, err := os.ReadFile(name)
		if err != nil {
			fatalf("failed to read %q: %v", name, err)
		}
		p, err := target.Deserialize(data, mode)
		if err != nil {
			fatalf("failed to deserialize %q: %v", name, err)
		}
		files = append(files, inputProgram{name: filepath.Clean(name), prog: p})
	}
	slices.SortFunc(files, func(a, b inputProgram) int {
		return strings.Compare(a.name, b.name)
	})

	result := analyze(files)
	switch {
	case *flagGraphviz:
		writeGraphviz(os.Stdout, result, *flagTransitive, *flagFold)
	case *flagListFiles:
		writeFileList(os.Stdout, result, *flagTransitive, *flagFold)
	default:
		writeText(os.Stdout, result, log.V(1), *flagTransitive, *flagFold)
	}
}

func validateOutputModes(graphviz, listFiles bool) error {
	if graphviz && listFiles {
		return fmt.Errorf("-graphviz and -listfiles are mutually exclusive")
	}
	return nil
}

func readInputNames(r io.Reader) ([]string, error) {
	var names []string
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		if name := strings.TrimSpace(scanner.Text()); name != "" {
			names = append(names, name)
		}
	}
	return names, scanner.Err()
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "syz-multidiff: "+format+"\n", args...)
	os.Exit(1)
}

func analyze(files []inputProgram) analysis {
	result := analysis{files: files}
	for fileIdx := range files {
		found := false
		for clusterIdx := range result.clusters {
			rep := result.clusters[clusterIdx].representative
			if comparePrograms(files[rep].prog, files[fileIdx].prog).relation == relationSame {
				result.clusters[clusterIdx].members = append(result.clusters[clusterIdx].members, fileIdx)
				found = true
				break
			}
		}
		if !found {
			result.clusters = append(result.clusters, exactCluster{
				representative: fileIdx,
				members:        []int{fileIdx},
			})
		}
	}
	for left := range result.clusters {
		for right := left + 1; right < len(result.clusters); right++ {
			leftRep := result.clusters[left].representative
			rightRep := result.clusters[right].representative
			result.relations = append(result.relations, representativeRelation{
				left:       left,
				right:      right,
				comparison: comparePrograms(files[leftRep].prog, files[rightRep].prog),
			})
		}
	}
	return result
}

func selectReportRelations(result analysis, transitive bool) reportSelection {
	var selection reportSelection
	var similarRelations []representativeRelation
	for _, rel := range result.relations {
		if rel.comparison.relation == relationSimilar {
			similarRelations = append(similarRelations, rel)
		}
	}
	selection.similar = findRelationClusters(similarRelations, relationSimilar, transitive)
	selection.relations = append(selection.relations, similarRelations...)

	// Only a similarity cluster's representative is considered for weaker
	// relations. Exact clusters outside similarity clusters contribute their
	// own representatives directly.
	similarMembers := make(map[int]bool)
	diffCandidates := make(map[int]bool)
	for _, cluster := range selection.similar {
		diffCandidates[cluster.representative] = true
		for _, member := range cluster.members {
			similarMembers[member] = true
		}
	}
	for clusterIdx := range result.clusters {
		if !similarMembers[clusterIdx] {
			diffCandidates[clusterIdx] = true
		}
	}
	var significantRelations []representativeRelation
	for _, rel := range result.relations {
		if rel.comparison.relation == relationSignificantlyDifferent &&
			diffCandidates[rel.left] && diffCandidates[rel.right] {
			significantRelations = append(significantRelations, rel)
		}
	}
	selection.significant = findRelationClusters(
		significantRelations, relationSignificantlyDifferent, transitive)
	selection.relations = append(selection.relations, significantRelations...)

	// Duplicate programs have a completely-same peer, so only singleton exact
	// clusters can be completely different from every other input program.
	for clusterIdx, cluster := range result.clusters {
		if len(cluster.members) != 1 {
			continue
		}
		allDifferent := true
		for _, rel := range result.relations {
			if rel.left != clusterIdx && rel.right != clusterIdx {
				continue
			}
			if rel.comparison.relation != relationCompletelyDifferent {
				allDifferent = false
				break
			}
		}
		if allDifferent {
			selection.completelyDifferent = append(selection.completelyDifferent, cluster.members...)
		}
	}
	return selection
}

type argContainer struct {
	owner  prog.Arg
	parent *argContainer
	args   []prog.Arg
	fields []prog.Field
}

type programIndex struct {
	root          map[*prog.Call]*argContainer
	parents       map[prog.Arg]*argContainer
	groups        map[*prog.GroupArg]*argContainer
	resultOrigins map[*prog.ResultArg]string
}

func indexProgram(p *prog.Prog) *programIndex {
	index := &programIndex{
		root:          make(map[*prog.Call]*argContainer),
		parents:       make(map[prog.Arg]*argContainer),
		groups:        make(map[*prog.GroupArg]*argContainer),
		resultOrigins: make(map[*prog.ResultArg]string),
	}
	for callIdx, call := range p.Calls {
		root := &argContainer{args: call.Args, fields: call.Meta.Args}
		index.root[call] = root
		if call.Ret != nil {
			index.resultOrigins[call.Ret] = fmt.Sprintf("call[%d].ret", callIdx)
		}
		for argIdx, arg := range call.Args {
			name := fieldName(call.Meta.Args, argIdx)
			index.walk(arg, root, fmt.Sprintf("call[%d].%s", callIdx, name))
		}
	}
	return index
}

func (index *programIndex) walk(arg prog.Arg, parent *argContainer, path string) {
	if arg == nil {
		return
	}
	index.parents[arg] = parent
	if result, ok := arg.(*prog.ResultArg); ok {
		index.resultOrigins[result] = path
	}
	switch arg := arg.(type) {
	case *prog.PointerArg:
		index.walk(arg.Res, parent, path+".pointee")
	case *prog.GroupArg:
		container := &argContainer{owner: arg, parent: parent, args: arg.Inner}
		if typ, ok := arg.Type().(*prog.StructType); ok {
			container.fields = typ.Fields
		}
		index.groups[arg] = container
		for idx, inner := range arg.Inner {
			name := fmt.Sprintf("element[%d]", idx)
			if len(container.fields) != 0 {
				name = fieldName(container.fields, idx)
			}
			index.walk(inner, container, path+"."+name)
		}
	case *prog.UnionArg:
		index.walk(arg.Option, parent, fmt.Sprintf("%s.option[%d]", path, arg.Index))
	}
}

func fieldName(fields []prog.Field, idx int) string {
	if idx < len(fields) && fields[idx].Name != "" {
		return fields[idx].Name
	}
	return fmt.Sprintf("arg%d", idx)
}

func (index *programIndex) resolveLen(call *prog.Call, arg *prog.ConstArg) prog.Arg {
	typ, ok := arg.Type().(*prog.LenType)
	if !ok || len(typ.Path) == 0 || typ.Offset {
		return nil
	}
	path := typ.Path
	container := index.parents[arg]
	if path[0] == prog.SyscallRef {
		container = index.root[call]
		path = path[1:]
	}
	if container == nil || len(path) == 0 {
		return nil
	}
	return index.resolvePath(container, path)
}

func (index *programIndex) resolvePath(container *argContainer, path []string) prog.Arg {
	name := path[0]
	var found prog.Arg
	if name == prog.ParentRef {
		found = container.owner
	} else {
		for idx, field := range container.fields {
			if field.Name == name && idx < len(container.args) {
				found = container.args[idx]
				break
			}
		}
		if found == nil {
			for current := container; current != nil; current = current.parent {
				if current.owner != nil && current.owner.Type().TemplateName() == name {
					found = current.owner
					break
				}
			}
		}
	}
	if found == nil {
		return nil
	}
	found = prog.InnerArg(found)
	if len(path) == 1 || found == nil {
		return found
	}
	return index.resolveArgPath(found, path[1:])
}

func (index *programIndex) resolveArgPath(arg prog.Arg, path []string) prog.Arg {
	if len(path) == 0 {
		return prog.InnerArg(arg)
	}
	arg = prog.InnerArg(arg)
	switch arg := arg.(type) {
	case *prog.GroupArg:
		container := index.groups[arg]
		if container == nil {
			return nil
		}
		return index.resolvePath(container, path)
	case *prog.UnionArg:
		typ := arg.Type().(*prog.UnionType)
		if arg.Index >= len(typ.Fields) || typ.Fields[arg.Index].Name != path[0] {
			return nil
		}
		return index.resolveArgPath(arg.Option, path[1:])
	default:
		return nil
	}
}

type lengthPair struct {
	callA *prog.Call
	callB *prog.Call
	argA  *prog.ConstArg
	argB  *prog.ConstArg
}

type compareContext struct {
	indexA         *programIndex
	indexB         *programIndex
	arguments      map[string]struct{}
	pointerOffset  *signedOffset
	replacementMap map[string]map[string]string
	replacementRev map[string]map[string]string
	replacements   []replacement
	changedStrings map[prog.Arg]prog.Arg
	lengthPairs    []lengthPair
	anyDifference  bool
	allowed        bool
}

func comparePrograms(a, b *prog.Prog) comparison {
	if len(a.Calls) != len(b.Calls) {
		return comparison{relation: relationCompletelyDifferent}
	}
	propsDiffer := false
	for idx := range a.Calls {
		if a.Calls[idx].Meta.Name != b.Calls[idx].Meta.Name {
			return comparison{relation: relationCompletelyDifferent}
		}
		propsDiffer = propsDiffer || (a.Calls[idx].Props != b.Calls[idx].Props)
	}
	if propsDiffer {
		return comparison{relation: relationSignificantlyDifferent}
	}
	ctx := &compareContext{
		indexA:         indexProgram(a),
		indexB:         indexProgram(b),
		arguments:      make(map[string]struct{}),
		replacementMap: make(map[string]map[string]string),
		replacementRev: make(map[string]map[string]string),
		changedStrings: make(map[prog.Arg]prog.Arg),
		allowed:        true,
	}
	for callIdx := range a.Calls {
		callA, callB := a.Calls[callIdx], b.Calls[callIdx]
		if len(callA.Args) != len(callB.Args) {
			ctx.allowed = false
			ctx.anyDifference = true
			continue
		}
		for argIdx := range callA.Args {
			name := fieldName(callA.Meta.Args, argIdx)
			instance := fmt.Sprintf("call[%d] %s.%s", callIdx, callA.Meta.Name, name)
			semantic := callA.Meta.Name + "." + name
			ctx.compareArg(callA, callB, callA.Args[argIdx], callB.Args[argIdx], instance, semantic)
		}
	}
	ctx.validateLengths()
	if !ctx.anyDifference {
		return comparison{relation: relationSame}
	}
	arguments := make([]string, 0, len(ctx.arguments))
	for argument := range ctx.arguments {
		arguments = append(arguments, argument)
	}
	sort.Strings(arguments)
	if !ctx.allowed {
		return comparison{relation: relationSignificantlyDifferent, arguments: arguments}
	}
	sort.Slice(ctx.replacements, func(i, j int) bool {
		left, right := ctx.replacements[i], ctx.replacements[j]
		if left.location != right.location {
			return left.location < right.location
		}
		if left.from != right.from {
			return left.from < right.from
		}
		return left.to < right.to
	})
	return comparison{
		relation:      relationSimilar,
		arguments:     arguments,
		pointerOffset: ctx.pointerOffset,
		replacements:  ctx.replacements,
	}
}

func (ctx *compareContext) compareArg(callA, callB *prog.Call, a, b prog.Arg, instance, semantic string) {
	if a == nil || b == nil {
		if a != nil || b != nil {
			ctx.disallow(instance)
		}
		return
	}
	if reflect.TypeOf(a) != reflect.TypeOf(b) || a.Type().Name() != b.Type().Name() || a.Dir() != b.Dir() {
		ctx.disallow(instance)
		return
	}
	switch a := a.(type) {
	case *prog.ConstArg:
		b := b.(*prog.ConstArg)
		_, isLength := a.Type().(*prog.LenType)
		if isLength {
			ctx.lengthPairs = append(ctx.lengthPairs, lengthPair{callA, callB, a, b})
		}
		if a.Val == b.Val {
			return
		}
		ctx.difference(instance + ".value")
		if !isLength {
			ctx.allowed = false
		}
	case *prog.PointerArg:
		b := b.(*prog.PointerArg)
		if a.Address != b.Address {
			ctx.difference(instance + ".address")
			if a.IsSpecial() || b.IsSpecial() {
				ctx.allowed = false
			}
		}
		if !a.IsSpecial() && !b.IsSpecial() {
			offset := makeOffset(a.Address, b.Address)
			if ctx.pointerOffset == nil {
				ctx.pointerOffset = &offset
			} else if *ctx.pointerOffset != offset {
				ctx.allowed = false
			}
		}
		if a.VmaSize != b.VmaSize {
			ctx.disallow(instance + ".vma_size")
		}
		ctx.compareArg(callA, callB, a.Res, b.Res, instance+".pointee", semantic+".pointee")
	case *prog.DataArg:
		b := b.(*prog.DataArg)
		if a.Dir() == prog.DirOut {
			if a.Size() != b.Size() {
				ctx.disallow(instance + ".size")
			}
			return
		}
		same := bytes.Equal(a.Data(), b.Data())
		if same && !isString(a.Type()) {
			return
		}
		if !same {
			ctx.difference(instance + ".data")
			if !isString(a.Type()) {
				ctx.allowed = false
				return
			}
		}
		from, to := string(a.Data()), string(b.Data())
		byValue := ctx.replacementMap[semantic]
		byReplacement := ctx.replacementRev[semantic]
		if byValue == nil {
			byValue = make(map[string]string)
			ctx.replacementMap[semantic] = byValue
			byReplacement = make(map[string]string)
			ctx.replacementRev[semantic] = byReplacement
		}
		previousTo, seenFrom := byValue[from]
		previousFrom, seenTo := byReplacement[to]
		if (seenFrom && previousTo != to) || (seenTo && previousFrom != from) {
			ctx.allowed = false
		} else if !seenFrom {
			byValue[from] = to
			byReplacement[to] = from
			if to != from {
				ctx.replacements = append(ctx.replacements, replacement{semantic, from, to})
			}
		}
		if !same {
			ctx.changedStrings[a] = b
		}
	case *prog.GroupArg:
		b := b.(*prog.GroupArg)
		if len(a.Inner) != len(b.Inner) {
			ctx.disallow(instance + ".elements")
			return
		}
		fields, _ := a.Type().(*prog.StructType)
		for idx := range a.Inner {
			name := fmt.Sprintf("element[%d]", idx)
			if fields != nil {
				name = fieldName(fields.Fields, idx)
			}
			ctx.compareArg(callA, callB, a.Inner[idx], b.Inner[idx],
				instance+"."+name, semantic+"."+name)
		}
	case *prog.UnionArg:
		b := b.(*prog.UnionArg)
		if a.Index != b.Index {
			ctx.disallow(instance + ".option")
			return
		}
		name := fmt.Sprintf("option[%d]", a.Index)
		if typ := a.Type().(*prog.UnionType); a.Index < len(typ.Fields) {
			name = typ.Fields[a.Index].Name
		}
		ctx.compareArg(callA, callB, a.Option, b.Option, instance+"."+name, semantic+"."+name)
	case *prog.ResultArg:
		b := b.(*prog.ResultArg)
		if a.OpDiv != b.OpDiv || a.OpAdd != b.OpAdd || (a.Res == nil) != (b.Res == nil) {
			ctx.disallow(instance)
			return
		}
		if a.Res == nil {
			if a.Val != b.Val {
				ctx.disallow(instance + ".value")
			}
			return
		}
		if ctx.indexA.resultOrigins[a.Res] != ctx.indexB.resultOrigins[b.Res] {
			ctx.disallow(instance + ".resource")
		}
	default:
		ctx.disallow(instance)
	}
}

func isString(typ prog.Type) bool {
	buffer, ok := typ.(*prog.BufferType)
	if !ok {
		return false
	}
	return buffer.Kind == prog.BufferString || buffer.Kind == prog.BufferFilename || buffer.Kind == prog.BufferGlob
}

func (ctx *compareContext) difference(path string) {
	ctx.anyDifference = true
	ctx.arguments[path] = struct{}{}
}

func (ctx *compareContext) disallow(path string) {
	ctx.difference(path)
	ctx.allowed = false
}

func (ctx *compareContext) validateLengths() {
	for _, pair := range ctx.lengthPairs {
		targetA := ctx.indexA.resolveLen(pair.callA, pair.argA)
		targetB := ctx.indexB.resolveLen(pair.callB, pair.argB)
		changedTarget, targetChanged := ctx.changedStrings[targetA]
		if !targetChanged {
			if pair.argA.Val != pair.argB.Val {
				ctx.allowed = false
			}
			continue
		}
		if targetA == nil || changedTarget != targetB {
			ctx.allowed = false
			continue
		}
		typ := pair.argA.Type().(*prog.LenType)
		bitSize := typ.BitSize
		if bitSize == 0 {
			bitSize = 8
		}
		if pair.argA.Val != targetA.Size()*8/bitSize || pair.argB.Val != targetB.Size()*8/bitSize {
			ctx.allowed = false
		}
	}
}

func writeText(w io.Writer, result analysis, verbose, transitive bool, fold int) {
	selection := selectReportRelations(result, transitive)
	hidden := foldedOutputNodes(result, selection, fold)
	var sameClusters []exactCluster
	for _, cluster := range result.clusters {
		if len(cluster.members) > 1 && !hidden[cluster.representative] {
			sameClusters = append(sameClusters, cluster)
		}
	}
	fmt.Fprintf(w, "Completely same clusters (%d):\n", len(sameClusters))
	if len(sameClusters) == 0 {
		fmt.Fprintln(w, "  (none)")
	}
	for idx, cluster := range sameClusters {
		fmt.Fprintf(w, "  Cluster %d:\n", idx+1)
		fmt.Fprintf(w, "    representative: %s\n", result.files[cluster.representative].name)
		if !foldsRelation(fold, relationSame) {
			fmt.Fprintf(w, "    files: %s\n", joinFileNames(result.files, cluster.members))
		}
	}

	similar := visibleRelationClusters(result, selection.similar, hidden)
	fmt.Fprintf(w, "\nSimilar up to a constant clusters (%d):\n", len(similar))
	if len(similar) == 0 {
		fmt.Fprintln(w, "  (none)")
	}
	writeRelationClusters(w, result, similar, verbose, foldsRelation(fold, relationSimilar))
	significant := visibleRelationClusters(result, selection.significant, hidden)
	fmt.Fprintf(w, "\nSignificantly different clusters (%d):\n", len(significant))
	if len(significant) == 0 {
		fmt.Fprintln(w, "  (none)")
	}
	writeRelationClusters(w, result, significant, verbose,
		foldsRelation(fold, relationSignificantlyDifferent))
	fmt.Fprintf(w, "\nCompletely different from all other programs (%d):\n",
		len(selection.completelyDifferent))
	if len(selection.completelyDifferent) == 0 {
		fmt.Fprintln(w, "  (none)")
	}
	for _, fileIdx := range selection.completelyDifferent {
		fmt.Fprintf(w, "  %s\n", result.files[fileIdx].name)
	}
}

func visibleRelationClusters(result analysis, clusters []relationCluster, hidden map[int]bool) []relationCluster {
	visible := make([]relationCluster, 0, len(clusters))
	for _, cluster := range clusters {
		representative := result.clusters[cluster.representative].representative
		if !hidden[representative] {
			visible = append(visible, cluster)
		}
	}
	return visible
}

type relationCluster struct {
	representative int
	members        []int
	arguments      []string
	edges          []representativeRelation
}

func findRelationClusters(relations []representativeRelation, kind relation, transitive bool) []relationCluster {
	bySignature := make(map[string][]representativeRelation)
	for edgeIdx, rel := range relations {
		if rel.comparison.relation != kind {
			continue
		}
		key := "transitive"
		if !transitive {
			if kind == relationSimilar {
				key = rel.comparison.signature()
			} else {
				key = fmt.Sprintf("edge-%09d", edgeIdx)
			}
		}
		bySignature[key] = append(bySignature[key], rel)
	}
	keys := make([]string, 0, len(bySignature))
	for key := range bySignature {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var clusters []relationCluster
	for _, key := range keys {
		edges := bySignature[key]
		adjacent := make(map[int][]int)
		for edgeIdx, edge := range edges {
			adjacent[edge.left] = append(adjacent[edge.left], edgeIdx)
			adjacent[edge.right] = append(adjacent[edge.right], edgeIdx)
		}
		nodes := make([]int, 0, len(adjacent))
		for node := range adjacent {
			nodes = append(nodes, node)
		}
		sort.Ints(nodes)
		visitedNodes := make(map[int]bool)
		for _, start := range nodes {
			if visitedNodes[start] {
				continue
			}
			visitedNodes[start] = true
			queue := []int{start}
			edgeSet := make(map[int]bool)
			componentNodes := map[int]bool{start: true}
			for len(queue) != 0 {
				node := queue[0]
				queue = queue[1:]
				for _, edgeIdx := range adjacent[node] {
					edgeSet[edgeIdx] = true
					edge := edges[edgeIdx]
					other := edge.left
					if other == node {
						other = edge.right
					}
					if !visitedNodes[other] {
						visitedNodes[other] = true
						componentNodes[other] = true
						queue = append(queue, other)
					}
				}
			}
			componentEdges := make([]representativeRelation, 0, len(edgeSet))
			componentMembers := make([]int, 0, len(componentNodes))
			for node := range componentNodes {
				componentMembers = append(componentMembers, node)
			}
			sort.Ints(componentMembers)
			for edgeIdx := range edges {
				if edgeSet[edgeIdx] {
					componentEdges = append(componentEdges, edges[edgeIdx])
				}
			}
			argumentSet := make(map[string]struct{})
			for _, edge := range componentEdges {
				for _, argument := range edge.comparison.arguments {
					argumentSet[argument] = struct{}{}
				}
			}
			arguments := make([]string, 0, len(argumentSet))
			for argument := range argumentSet {
				arguments = append(arguments, argument)
			}
			sort.Strings(arguments)
			clusters = append(clusters, relationCluster{
				representative: componentMembers[0],
				members:        componentMembers,
				arguments:      arguments,
				edges:          componentEdges,
			})
		}
	}
	return clusters
}

func writeRelationClusters(w io.Writer, result analysis, clusters []relationCluster, verbose, folded bool) {
	for idx, cluster := range clusters {
		fmt.Fprintf(w, "  Cluster %d:\n", idx+1)
		representative := result.clusters[cluster.representative].representative
		fmt.Fprintf(w, "    representative: %s\n", result.files[representative].name)
		if folded {
			continue
		}
		fileIndices := make([]int, 0, len(cluster.members))
		for _, clusterIdx := range cluster.members {
			fileIndices = append(fileIndices, result.clusters[clusterIdx].representative)
		}
		sort.Ints(fileIndices)
		fmt.Fprintf(w, "    files: %s\n", joinFileNames(result.files, fileIndices))
		if !verbose {
			continue
		}
		if len(cluster.arguments) != 0 {
			fmt.Fprintf(w, "    differing arguments: %s\n", strings.Join(cluster.arguments, ", "))
		}
		for _, edge := range cluster.edges {
			left := result.files[result.clusters[edge.left].representative].name
			right := result.files[result.clusters[edge.right].representative].name
			fmt.Fprintf(w, "    %s <-> %s", left, right)
			var details []string
			if edge.comparison.pointerOffset != nil {
				details = append(details, "pointer offset "+edge.comparison.pointerOffset.String())
			}
			for _, replacement := range edge.comparison.replacements {
				details = append(details, fmt.Sprintf("%s: %q -> %q",
					replacement.location, replacement.from, replacement.to))
			}
			if len(details) != 0 {
				fmt.Fprintf(w, " (%s)", strings.Join(details, "; "))
			}
			fmt.Fprintln(w)
		}
	}
}

func joinFileNames(files []inputProgram, indices []int) string {
	names := make([]string, len(indices))
	for idx, fileIdx := range indices {
		names[idx] = files[fileIdx].name
	}
	return strings.Join(names, ", ")
}

func writeFileList(w io.Writer, result analysis, transitive bool, fold int) {
	selection := selectReportRelations(result, transitive)
	hidden := foldedOutputNodes(result, selection, fold)
	names := make([]string, 0, len(result.files)-len(hidden))
	for fileIdx, file := range result.files {
		if !hidden[fileIdx] {
			names = append(names, file.name)
		}
	}
	sort.Strings(names)
	for _, name := range names {
		fmt.Fprintln(w, name)
	}
}

func writeGraphviz(w io.Writer, result analysis, transitive bool, fold int) {
	selection := selectReportRelations(result, transitive)
	representatives := make(map[int]bool)
	for _, cluster := range result.clusters {
		if len(cluster.members) > 1 {
			representatives[cluster.representative] = true
		}
	}
	for _, cluster := range selection.similar {
		representatives[result.clusters[cluster.representative].representative] = true
	}
	for _, cluster := range selection.significant {
		representatives[result.clusters[cluster.representative].representative] = true
	}
	hidden := foldedOutputNodes(result, selection, fold)
	fmt.Fprintln(w, "graph syz_multidiff {")
	fmt.Fprintln(w, `  graph [overlap=false, rankdir=LR, pack=true, packmode="array_c1"];`)
	fmt.Fprintln(w, "  node [shape=box];")
	for idx, file := range result.files {
		if hidden[idx] {
			continue
		}
		attributes := fmt.Sprintf("label=%q", file.name)
		var styles []string
		if representatives[idx] {
			attributes += `, fillcolor="lightgoldenrod1"`
			styles = append(styles, "filled")
		}
		if slices.Contains(selection.completelyDifferent, idx) {
			attributes += `, color="gray40"`
			styles = append(styles, "dashed")
		}
		if len(styles) != 0 {
			attributes += fmt.Sprintf(", style=%q", strings.Join(styles, ","))
		}
		fmt.Fprintf(w, "  file%d [%s];\n", idx, attributes)
	}
	written := make(map[graphvizEdge]bool)
	if !foldsRelation(fold, relationSame) {
		for _, cluster := range result.clusters {
			for _, member := range cluster.members {
				writeGraphvizEdgeOnce(w, written, cluster.representative, member, relationSame)
			}
		}
	}
	for _, tier := range selection.weakerTiers() {
		if !foldsRelation(fold, tier.kind) {
			writeGraphvizRelationClusters(w, written, result, tier.clusters, tier.kind)
		}
	}
	fmt.Fprintln(w, "}")
}

func foldedOutputNodes(result analysis, selection reportSelection, fold int) map[int]bool {
	hidden := make(map[int]bool)
	if foldsRelation(fold, relationSame) {
		for _, cluster := range result.clusters {
			for _, member := range cluster.members {
				if member != cluster.representative {
					hidden[member] = true
				}
			}
		}
	}
	for _, tier := range selection.weakerTiers() {
		if foldsRelation(fold, tier.kind) {
			foldRelationMembers(hidden, result, tier.clusters)
		}
	}
	return hidden
}

func foldRelationMembers(hidden map[int]bool, result analysis, clusters []relationCluster) {
	leaders := make(map[int]bool)
	var members []int
	for _, cluster := range clusters {
		leaders[result.clusters[cluster.representative].representative] = true
		for _, memberCluster := range cluster.members {
			members = append(members, result.clusters[memberCluster].representative)
		}
	}
	for _, member := range members {
		if !leaders[member] {
			hidden[member] = true
		}
	}
}

type graphvizEdge struct {
	left     int
	right    int
	relation relation
}

func writeGraphvizRelationClusters(w io.Writer, written map[graphvizEdge]bool, result analysis,
	clusters []relationCluster, kind relation) {
	for _, cluster := range clusters {
		representative := result.clusters[cluster.representative].representative
		for _, memberCluster := range cluster.members {
			member := result.clusters[memberCluster].representative
			writeGraphvizEdgeOnce(w, written, representative, member, kind)
		}
	}
}

func writeGraphvizEdgeOnce(w io.Writer, written map[graphvizEdge]bool, left, right int, kind relation) {
	if left == right {
		return
	}
	if left > right {
		left, right = right, left
	}
	edge := graphvizEdge{left: left, right: right, relation: kind}
	if written[edge] {
		return
	}
	written[edge] = true
	writeGraphvizEdge(w, left, right, comparison{relation: kind})
}

func writeGraphvizEdge(w io.Writer, left, right int, cmp comparison) {
	color, style := "black", "solid"
	switch cmp.relation {
	case relationSame:
		color, style = "forestgreen", "bold"
	case relationSimilar:
		color = "royalblue"
	case relationCompletelyDifferent:
		color, style = "gray40", "dashed"
	case relationSignificantlyDifferent:
		color = "firebrick"
	}
	fmt.Fprintf(w, "  file%d -- file%d [color=%q, style=%q];\n",
		left, right, color, style)
}

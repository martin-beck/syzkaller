package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/google/syzkaller/prog"
	"github.com/stretchr/testify/require"
)

func parseTestProgram(t *testing.T, source string) *prog.Prog {
	t.Helper()
	target, err := prog.GetTarget("test", "64")
	require.NoError(t, err)
	p, err := target.Deserialize([]byte(source), prog.StrictUnsafe)
	require.NoError(t, err)
	return p
}

func TestComparePrograms(t *testing.T) {
	tests := []struct {
		name  string
		left  string
		right string
		want  relation
	}{
		{
			name:  "same",
			left:  `mutate7(&(0x7f0000000000)='foo', 0x3)`,
			right: `mutate7(&(0x7f0000000000)='foo', 0x3)`,
			want:  relationSame,
		},
		{
			name:  "pointer string and length",
			left:  `mutate7(&(0x7f0000000000)='foo', 0x3)`,
			right: `mutate7(&(0x7f0000000100)='longer', 0x6)`,
			want:  relationSimilar,
		},
		{
			name:  "ordinary integer",
			left:  `test$int(0x1, 0x2, 0x3, 0x4, 0x5)`,
			right: `test$int(0x2, 0x2, 0x3, 0x4, 0x5)`,
			want:  relationSignificantlyDifferent,
		},
		{
			name:  "stale string length",
			left:  `mutate7(&(0x7f0000000000)='foo', 0x3)`,
			right: `mutate7(&(0x7f0000000000)='longer', 0x3)`,
			want:  relationSignificantlyDifferent,
		},
		{
			name:  "different calls",
			left:  `test$str0(&(0x7f0000000000)='foo')`,
			right: `test$str1(&(0x7f0000000000)='foo')`,
			want:  relationCompletelyDifferent,
		},
		{
			name:  "different async property",
			left:  `test$int(0x1, 0x2, 0x3, 0x4, 0x5)`,
			right: `test$int(0x1, 0x2, 0x3, 0x4, 0x5) (async)`,
			want:  relationSignificantlyDifferent,
		},
		{
			name:  "different rerun property",
			left:  `test$int(0x1, 0x2, 0x3, 0x4, 0x5)`,
			right: `test$int(0x1, 0x2, 0x3, 0x4, 0x5) (rerun: 2)`,
			want:  relationSignificantlyDifferent,
		},
		{
			name:  "different fail-nth property",
			left:  `test$int(0x1, 0x2, 0x3, 0x4, 0x5)`,
			right: `test$int(0x1, 0x2, 0x3, 0x4, 0x5) (fail_nth: 3)`,
			want:  relationSignificantlyDifferent,
		},
		{
			name: "inconsistent pointer offsets",
			left: "test$str0(&(0x7f0000000000)='foo')\n" +
				"test$str0(&(0x7f0000001000)='foo')",
			right: "test$str0(&(0x7f0000000100)='foo')\n" +
				"test$str0(&(0x7f0000001300)='foo')",
			want: relationSignificantlyDifferent,
		},
		{
			name: "mixed changed and unchanged pointer offsets",
			left: "test$str0(&(0x7f0000000000)='foo')\n" +
				"test$str0(&(0x7f0000001000)='foo')",
			right: "test$str0(&(0x7f0000000100)='foo')\n" +
				"test$str0(&(0x7f0000001000)='foo')",
			want: relationSignificantlyDifferent,
		},
		{
			name: "inconsistent repeated replacement",
			left: "mutate7(&(0x7f0000000000)='foo', 0x3)\n" +
				"mutate7(&(0x7f0000001000)='foo', 0x3)",
			right: "mutate7(&(0x7f0000000000)='bar', 0x3)\n" +
				"mutate7(&(0x7f0000001000)='baz', 0x3)",
			want: relationSignificantlyDifferent,
		},
		{
			name: "inconsistent repeated replacement reverse",
			left: "mutate7(&(0x7f0000000000)='bar', 0x3)\n" +
				"mutate7(&(0x7f0000001000)='baz', 0x3)",
			right: "mutate7(&(0x7f0000000000)='foo', 0x3)\n" +
				"mutate7(&(0x7f0000001000)='foo', 0x3)",
			want: relationSignificantlyDifferent,
		},
		{
			name: "changed and unchanged repeated replacement",
			left: "mutate7(&(0x7f0000000000)='foo', 0x3)\n" +
				"mutate7(&(0x7f0000001000)='foo', 0x3)",
			right: "mutate7(&(0x7f0000000000)='bar', 0x3)\n" +
				"mutate7(&(0x7f0000001000)='foo', 0x3)",
			want: relationSignificantlyDifferent,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			left := parseTestProgram(t, test.left)
			right := parseTestProgram(t, test.right)
			cmp := comparePrograms(left, right)
			require.Equal(t, test.want, cmp.relation)
			reverse := comparePrograms(right, left)
			require.Equal(t, test.want, reverse.relation)
		})
	}
}

func TestAnalyzeAndOutput(t *testing.T) {
	files := []inputProgram{
		{name: "a.prog", prog: parseTestProgram(t, `mutate7(&(0x7f0000000000)='foo', 0x3)`)},
		{name: "a-copy.prog", prog: parseTestProgram(t, `mutate7(&(0x7f0000000000)='foo', 0x3)`)},
		{name: "b.prog", prog: parseTestProgram(t, `mutate7(&(0x7f0000000100)='longer', 0x6)`)},
	}
	result := analyze(files)
	require.Len(t, result.clusters, 2)
	require.Len(t, result.relations, 1)
	require.Equal(t, relationSimilar, result.relations[0].comparison.relation)
	selection := selectReportRelations(result, true)
	require.Len(t, selection.relations, 1)
	require.Empty(t, selection.completelyDifferent)

	var text bytes.Buffer
	writeText(&text, result, false, true, 0)
	require.Contains(t, text.String(), "representative: a.prog")
	require.Contains(t, text.String(), "Similar up to a constant clusters (1)")
	require.Contains(t, text.String(), "files: a.prog, b.prog")
	require.NotContains(t, text.String(), "files: a.prog, a-copy.prog, b.prog")
	require.NotContains(t, text.String(), "a.prog <-> b.prog")
	require.NotContains(t, text.String(), "differing arguments")
	require.NotContains(t, text.String(), "pointer offset +0x100")

	var verboseText bytes.Buffer
	writeText(&verboseText, result, true, true, 0)
	require.Contains(t, verboseText.String(), "differing arguments")
	require.Contains(t, verboseText.String(), "pointer offset +0x100")

	var dot bytes.Buffer
	writeGraphviz(&dot, result, true, 0)
	require.True(t, strings.HasPrefix(dot.String(), "graph syz_multidiff {"))
	require.Contains(t, dot.String(), `rankdir=LR, pack=true, packmode="array_c1"`)
	require.Contains(t, dot.String(), `file0 [label="a.prog", fillcolor="lightgoldenrod1", style="filled"]`)
	require.Contains(t, dot.String(), `file1 [label="a-copy.prog"]`)
	require.Contains(t, dot.String(), `file2 [label="b.prog"]`)
	require.Contains(t, dot.String(), `color="forestgreen"`)
	require.Contains(t, dot.String(), `color="royalblue"`)
}

func TestFindSimilarClustersDoesNotJoinDisconnectedRelations(t *testing.T) {
	cmp := comparison{relation: relationSimilar, arguments: []string{"call[0] mutate7.a0.data"}}
	clusters := findRelationClusters([]representativeRelation{
		{left: 0, right: 1, comparison: cmp},
		{left: 2, right: 3, comparison: cmp},
	}, relationSimilar, true)
	require.Len(t, clusters, 2)
	require.Len(t, clusters[0].edges, 1)
	require.Len(t, clusters[1].edges, 1)
	require.Equal(t, 0, clusters[0].representative)
	require.Equal(t, []int{0, 1}, clusters[0].members)
	require.Equal(t, 2, clusters[1].representative)
	require.Equal(t, []int{2, 3}, clusters[1].members)
}

func TestReadInputNames(t *testing.T) {
	names, err := readInputNames(strings.NewReader(" first.prog \n\nsecond.prog\r\n"))
	require.NoError(t, err)
	require.Equal(t, []string{"first.prog", "second.prog"}, names)
}

func TestValidateOutputModes(t *testing.T) {
	require.NoError(t, validateOutputModes(false, false))
	require.NoError(t, validateOutputModes(true, false))
	require.NoError(t, validateOutputModes(false, true))
	require.EqualError(t, validateOutputModes(true, true),
		"-graphviz and -listfiles are mutually exclusive")
}

func TestFoldsRelation(t *testing.T) {
	for fold := 0; fold <= maxFold; fold++ {
		for rel := relationSame; rel <= relationCompletelyDifferent; rel++ {
			require.Equal(t, int(rel) < fold, foldsRelation(fold, rel),
				"fold=%d relation=%s", fold, rel)
		}
	}
}

func TestSelectReportRelations(t *testing.T) {
	result := analysis{
		files: []inputProgram{
			{name: "a.prog"}, {name: "b.prog"}, {name: "c.prog"},
			{name: "d.prog"}, {name: "e.prog"}, {name: "f.prog"},
		},
		clusters: []exactCluster{
			{representative: 0, members: []int{0}},
			{representative: 1, members: []int{1}},
			{representative: 2, members: []int{2}},
			{representative: 3, members: []int{3}},
			{representative: 4, members: []int{4}},
			{representative: 5, members: []int{5}},
		},
		relations: []representativeRelation{
			{left: 0, right: 1, comparison: comparison{relation: relationSimilar}},
			{left: 2, right: 3, comparison: comparison{relation: relationSimilar}},
			// This is weaker than the strongest relation of either endpoint.
			{left: 0, right: 2, comparison: comparison{relation: relationSignificantlyDifferent}},
			// This is f.prog's strongest relation, even though a.prog has a stronger one.
			{left: 0, right: 5, comparison: comparison{
				relation:  relationSignificantlyDifferent,
				arguments: []string{"call[0] test$int.a0.value"},
			}},
			{left: 0, right: 4, comparison: comparison{relation: relationCompletelyDifferent}},
			{left: 1, right: 4, comparison: comparison{relation: relationCompletelyDifferent}},
			{left: 2, right: 4, comparison: comparison{relation: relationCompletelyDifferent}},
			{left: 3, right: 4, comparison: comparison{relation: relationCompletelyDifferent}},
			{left: 4, right: 5, comparison: comparison{relation: relationCompletelyDifferent}},
		},
	}
	selection := selectReportRelations(result, true)
	require.Len(t, selection.similar, 2)
	require.Len(t, selection.significant, 1)
	require.Equal(t, []int{0, 2, 5}, selection.significant[0].members)
	require.Len(t, selection.relations, 4)
	require.Equal(t, []int{4}, selection.completelyDifferent)

	var output bytes.Buffer
	writeText(&output, result, false, true, 0)
	require.Contains(t, output.String(), "files: a.prog, c.prog, f.prog")
	require.NotContains(t, output.String(), "call[0] test$int.a0.value")
	require.Contains(t, output.String(), "Completely different from all other programs (1):\n  e.prog")
	require.NotContains(t, output.String(), "Completely different relations")

	var verboseOutput bytes.Buffer
	writeText(&verboseOutput, result, true, true, 0)
	require.Contains(t, verboseOutput.String(), "call[0] test$int.a0.value")
}

func TestClusterRepresentativesKeepWeakerRelations(t *testing.T) {
	result := analysis{
		files: []inputProgram{
			{name: "x.prog"}, {name: "x-copy.prog"},
			{name: "y.prog"}, {name: "y-copy.prog"},
			{name: "z.prog"},
		},
		clusters: []exactCluster{
			{representative: 0, members: []int{0, 1}},
			{representative: 2, members: []int{2, 3}},
			{representative: 4, members: []int{4}},
		},
		relations: []representativeRelation{
			{left: 0, right: 1, comparison: comparison{relation: relationSimilar}},
			{left: 0, right: 2, comparison: comparison{relation: relationSignificantlyDifferent}},
			{left: 1, right: 2, comparison: comparison{relation: relationCompletelyDifferent}},
		},
	}
	selection := selectReportRelations(result, true)
	require.Len(t, selection.similar, 1)
	require.Equal(t, []int{0, 1}, selection.similar[0].members)
	require.Len(t, selection.significant, 1)
	require.Equal(t, []int{0, 2}, selection.significant[0].members)
	require.Len(t, selection.relations, 2)

	var output bytes.Buffer
	writeText(&output, result, false, true, 0)
	require.Contains(t, output.String(), "files: x.prog, y.prog")
	require.Contains(t, output.String(), "files: x.prog, z.prog")
	require.NotContains(t, output.String(), "files: x.prog, x-copy.prog, y.prog")
	require.NotContains(t, output.String(), "files: x.prog, x-copy.prog, z.prog")
	require.NotContains(t, output.String(), "completely different relation")

	var verbose bytes.Buffer
	writeText(&verbose, result, true, true, 0)
	require.NotContains(t, verbose.String(), "y.prog <-> z.prog")

	var dot bytes.Buffer
	writeGraphviz(&dot, result, true, 0)
	require.NotContains(t, dot.String(), "completely different")
	require.Contains(t, dot.String(), "file0 -- file2")
	require.NotContains(t, dot.String(), "file1 -- file2")

	var fold1Text bytes.Buffer
	writeText(&fold1Text, result, false, true, 1)
	require.NotContains(t, fold1Text.String(), "x-copy.prog")
	require.NotContains(t, fold1Text.String(), "y-copy.prog")
	require.Contains(t, fold1Text.String(), "y.prog")
	require.Contains(t, fold1Text.String(), "z.prog")

	var fold2Text bytes.Buffer
	writeText(&fold2Text, result, false, true, 2)
	require.NotContains(t, fold2Text.String(), "x-copy.prog")
	require.NotContains(t, fold2Text.String(), "y.prog")
	require.Contains(t, fold2Text.String(), "z.prog")

	var fold3Text bytes.Buffer
	writeText(&fold3Text, result, false, true, 3)
	require.NotContains(t, fold3Text.String(), "x-copy.prog")
	require.NotContains(t, fold3Text.String(), "y.prog")
	require.NotContains(t, fold3Text.String(), "z.prog")
	require.Contains(t, fold3Text.String(), "representative: x.prog")

	var fold1Dot bytes.Buffer
	writeGraphviz(&fold1Dot, result, true, 1)
	require.NotContains(t, fold1Dot.String(), "file1 [")
	require.NotContains(t, fold1Dot.String(), "file3 [")
	require.Contains(t, fold1Dot.String(), "file2 [")
	require.Contains(t, fold1Dot.String(), "file4 [")
	require.NotContains(t, fold1Dot.String(), `color="forestgreen"`)

	var fold2Dot bytes.Buffer
	writeGraphviz(&fold2Dot, result, true, 2)
	require.NotContains(t, fold2Dot.String(), "file2 [")
	require.Contains(t, fold2Dot.String(), "file4 [")
	require.NotContains(t, fold2Dot.String(), `color="royalblue"`)
	require.Contains(t, fold2Dot.String(), `color="firebrick"`)

	var fold3Dot bytes.Buffer
	writeGraphviz(&fold3Dot, result, true, 3)
	require.NotContains(t, fold3Dot.String(), "file4 [")
	require.NotContains(t, fold3Dot.String(), `color="firebrick"`)
	require.Contains(t, fold3Dot.String(), "file0 [")

	wantLists := []string{
		"x-copy.prog\nx.prog\ny-copy.prog\ny.prog\nz.prog\n",
		"x.prog\ny.prog\nz.prog\n",
		"x.prog\nz.prog\n",
		"x.prog\n",
	}
	for fold, want := range wantLists {
		var list bytes.Buffer
		writeFileList(&list, result, true, fold)
		require.Equal(t, want, list.String(), "fold=%d", fold)
	}
}

func TestGraphvizHighlightsSignificantRepresentative(t *testing.T) {
	result := analysis{
		files: []inputProgram{{name: "a.prog"}, {name: "b.prog"}},
		clusters: []exactCluster{
			{representative: 0, members: []int{0}},
			{representative: 1, members: []int{1}},
		},
		relations: []representativeRelation{
			{left: 0, right: 1, comparison: comparison{relation: relationSignificantlyDifferent}},
		},
	}
	var dot bytes.Buffer
	writeGraphviz(&dot, result, true, 0)
	require.Contains(t, dot.String(),
		`file0 [label="a.prog", fillcolor="lightgoldenrod1", style="filled"]`)
	require.Contains(t, dot.String(), `file1 [label="b.prog"]`)
}

func TestGraphvizUsesRepresentativeStarEdges(t *testing.T) {
	t.Run("completely same", func(t *testing.T) {
		result := analysis{
			files: []inputProgram{{name: "a"}, {name: "b"}, {name: "c"}},
			clusters: []exactCluster{
				{representative: 0, members: []int{0, 1, 2}},
			},
		}
		var dot bytes.Buffer
		writeGraphviz(&dot, result, true, 0)
		require.Contains(t, dot.String(), "file0 -- file1")
		require.Contains(t, dot.String(), "file0 -- file2")
		require.NotContains(t, dot.String(), "file1 -- file2")
	})

	for _, kind := range []relation{relationSimilar, relationSignificantlyDifferent} {
		t.Run(kind.String(), func(t *testing.T) {
			result := analysis{
				files: []inputProgram{{name: "a"}, {name: "b"}, {name: "c"}},
				clusters: []exactCluster{
					{representative: 0, members: []int{0}},
					{representative: 1, members: []int{1}},
					{representative: 2, members: []int{2}},
				},
				relations: []representativeRelation{
					{left: 0, right: 1, comparison: comparison{relation: kind}},
					{left: 1, right: 2, comparison: comparison{relation: kind}},
				},
			}
			var dot bytes.Buffer
			writeGraphviz(&dot, result, true, 0)
			require.Contains(t, dot.String(), "file0 -- file1")
			require.Contains(t, dot.String(), "file0 -- file2")
			require.NotContains(t, dot.String(), "file1 -- file2")
		})
	}
}

func TestTransitiveRelationClusters(t *testing.T) {
	similarRelations := []representativeRelation{
		{left: 0, right: 1, comparison: comparison{
			relation:  relationSimilar,
			arguments: []string{"call[0].a"},
		}},
		{left: 1, right: 2, comparison: comparison{
			relation:  relationSimilar,
			arguments: []string{"call[1].b"},
		}},
	}
	transitive := findRelationClusters(similarRelations, relationSimilar, true)
	require.Len(t, transitive, 1)
	require.Equal(t, []int{0, 1, 2}, transitive[0].members)
	require.Equal(t, []string{"call[0].a", "call[1].b"}, transitive[0].arguments)

	nonTransitive := findRelationClusters(similarRelations, relationSimilar, false)
	require.Len(t, nonTransitive, 2)

	significantRelations := []representativeRelation{
		{left: 0, right: 1, comparison: comparison{relation: relationSignificantlyDifferent}},
		{left: 1, right: 2, comparison: comparison{relation: relationSignificantlyDifferent}},
	}
	transitive = findRelationClusters(significantRelations, relationSignificantlyDifferent, true)
	require.Len(t, transitive, 1)
	require.Equal(t, []int{0, 1, 2}, transitive[0].members)
	nonTransitive = findRelationClusters(significantRelations, relationSignificantlyDifferent, false)
	require.Len(t, nonTransitive, 2)
}

func TestTransitiveClustersDoNotCrossRelationTypes(t *testing.T) {
	relations := []representativeRelation{
		{left: 0, right: 1, comparison: comparison{relation: relationSimilar}},
		{left: 1, right: 2, comparison: comparison{relation: relationSignificantlyDifferent}},
		{left: 2, right: 3, comparison: comparison{relation: relationSimilar}},
	}
	similar := findRelationClusters(relations, relationSimilar, true)
	require.Len(t, similar, 2)
	require.Equal(t, []int{0, 1}, similar[0].members)
	require.Equal(t, []int{2, 3}, similar[1].members)

	significant := findRelationClusters(relations, relationSignificantlyDifferent, true)
	require.Len(t, significant, 1)
	require.Equal(t, []int{1, 2}, significant[0].members)
}

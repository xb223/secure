// Package textdiff produces small unified diffs for plan output.
package textdiff

import (
	"fmt"
	"strings"
)

// Unified returns a unified diff between old and new text. It returns an empty
// string when the inputs are equal.
func Unified(path, oldText, newText string) string {
	if oldText == newText {
		return ""
	}
	a := splitLines(oldText)
	b := splitLines(newText)
	if len(a)*len(b) > 4_000_000 {
		return fmt.Sprintf("--- %s\n+++ %s\n(file is too large for an inline diff)\n", path, path)
	}
	ops := lcs(a, b)
	var out strings.Builder
	fmt.Fprintf(&out, "--- a/%s\n+++ b/%s\n", strings.TrimPrefix(path, "/"), strings.TrimPrefix(path, "/"))
	for _, op := range ops {
		switch op.kind {
		case ' ':
			fmt.Fprintf(&out, " %s\n", op.text)
		case '-':
			fmt.Fprintf(&out, "-%s\n", op.text)
		case '+':
			fmt.Fprintf(&out, "+%s\n", op.text)
		}
	}
	return out.String()
}

type lineOp struct {
	kind byte
	text string
}

func splitLines(s string) []string {
	s = strings.TrimSuffix(s, "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

func lcs(a, b []string) []lineOp {
	n, m := len(a), len(b)
	dp := make([][]int, n+1)
	for i := range dp {
		dp[i] = make([]int, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if a[i] == b[j] {
				dp[i][j] = dp[i+1][j+1] + 1
			} else if dp[i+1][j] >= dp[i][j+1] {
				dp[i][j] = dp[i+1][j]
			} else {
				dp[i][j] = dp[i][j+1]
			}
		}
	}
	var ops []lineOp
	i, j := 0, 0
	for i < n && j < m {
		switch {
		case a[i] == b[j]:
			ops = append(ops, lineOp{' ', a[i]})
			i++
			j++
		case dp[i+1][j] >= dp[i][j+1]:
			ops = append(ops, lineOp{'-', a[i]})
			i++
		default:
			ops = append(ops, lineOp{'+', b[j]})
			j++
		}
	}
	for ; i < n; i++ {
		ops = append(ops, lineOp{'-', a[i]})
	}
	for ; j < m; j++ {
		ops = append(ops, lineOp{'+', b[j]})
	}
	return ops
}

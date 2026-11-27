package main

import (
	"context"
	"flag"
	"fmt"
	"io"
)

func cmdRollback(ctx context.Context, g *globals, o *output, args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("rollback", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	addGlobalFlags(fs, g)
	id := ""
	list := false
	fs.StringVar(&id, "transaction", "", "transaction ID (default: newest committed)")
	fs.StringVar(&id, "t", "", "transaction ID (shorthand)")
	fs.BoolVar(&list, "list", false, "list transactions and exit")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(stderr, "obsidian rollback:", err)
		return 2
	}
	if !requireRoot(g, stderr, "rollback") {
		return 1
	}
	e := newEngine(g, o.w, stderr)
	if list {
		txns, err := e.ListTransactions()
		if err != nil {
			fmt.Fprintln(stderr, "obsidian rollback:", err)
			return 1
		}
		if g.json {
			return o.emitJSON(txns)
		}
		if len(txns) == 0 {
			o.printf("no transactions\n")
			return 0
		}
		o.printf("%-24s %-18s %-10s %-18s %s\n", "ID", "CREATED", "STATUS", "SCOPE", "CHANGES")
		for _, txn := range txns {
			o.printf("%-24s %-18s %-10s %-18s %d\n", txn.ID, txn.Created.Format("2006-01-02 15:04"), txn.Status, scopeLabel(txn.Scope), txn.Changes)
		}
		return 0
	}
	target := id
	if target == "" {
		target = "last"
	}
	if !g.yes && !confirm(fmt.Sprintf("Roll back transaction %s?", target)) {
		o.printf("aborted\n")
		return 1
	}
	m, err := e.Rollback(ctx, id)
	if err != nil {
		fmt.Fprintln(stderr, "obsidian rollback:", err)
		return 1
	}
	if g.json {
		return o.emitJSON(m)
	}
	o.printf("%s transaction %s rolled back\n", o.ok("ok:"), m.ID)
	if len(m.Files) > 0 {
		o.printf("  restored %d file(s), %d service(s), %d nftables table(s)\n", len(m.Files), len(m.Services), len(m.NFT))
	}
	return 0
}

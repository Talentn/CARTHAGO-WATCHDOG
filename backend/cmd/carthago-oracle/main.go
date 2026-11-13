// carthago-oracle is the offline tool for the Carthago Oracle: it trains and evaluates
// the behaviour model on synthetic telemetry, writes and edits model bundles, measures
// analyst models and exports tuning datasets. The gateway only ever reads what this tool
// writes.
package main

import (
	"fmt"
	"os"
	"sort"
)

type command struct {
	run  func(args []string) error
	help string
}

var commands = map[string]command{}

func main() {
	if len(os.Args) < 2 || commands[os.Args[1]].run == nil {
		fmt.Fprintln(os.Stderr, "usage: carthago-oracle <command> [options]")
		names := make([]string, 0, len(commands))
		for n := range commands {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			fmt.Fprintf(os.Stderr, "  %-15s %s\n", n, commands[n].help)
		}
		fmt.Fprintln(os.Stderr, "Run a command with -h for its options.")
		os.Exit(2)
	}
	if err := commands[os.Args[1]].run(os.Args[2:]); err != nil {
		fmt.Fprintln(os.Stderr, "carthago-oracle:", err)
		os.Exit(1)
	}
}

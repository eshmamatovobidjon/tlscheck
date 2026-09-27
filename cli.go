package main

import (
	"flag"
	"fmt"
	"os"
)

func run() error {
	return runWithArgs(os.Args[1:])
}

func runWithArgs(args []string) error {
	fs := flag.NewFlagSet("tlscheck", flag.ContinueOnError)

	jsonOutput := fs.Bool(
		"json",
		false,
		"output result as JSON",
	)

	if err := fs.Parse(args); err != nil {
		return err
	}

	if fs.NArg() != 1 {
		return fmt.Errorf("usage: tlscheck [--json] <host:port>")
	}

	host := fs.Arg(0)

	result, err := checkTLS(host)
	if err != nil {
		return err
	}

	if *jsonOutput {
		return printJSON(result)
	}

	fmt.Println("TLSCheck")
	fmt.Println("Checking " + host + "\n")
	printResult(result)

	return nil
}

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	vciyverify "github.com/VoxellInc/vciy-verify"
)

func main() {
	asJSON := flag.Bool("json", false, "output JSON instead of Markdown")
	flag.Parse()
	if flag.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "usage: vciy-verify [-json] CVE-YYYY-NNNN [CVE-...]")
		os.Exit(2)
	}
	res, err := vciyverify.CheckLive(nil, flag.Args())
	if err != nil {
		fmt.Fprintf(os.Stderr, "vciy-verify: %v\n", err)
		os.Exit(1)
	}
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(res)
		return
	}
	fmt.Print(vciyverify.MarkdownTable(res))
}

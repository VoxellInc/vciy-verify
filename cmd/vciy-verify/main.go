// Command vciy-verify checks CVE identifiers against CISA KEV, CVE 5.1 CNA
// scores, and FIRST EPSS without null-to-zero blind spots, and optionally audits
// exported PAN-OS running-config.xml files offline via subpackage checks.
//
// Field notes and advisories: https://vciy.com/articles and https://vciy.com/advisories
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	vciyverify "github.com/VoxellInc/vciy-verify"
	"github.com/VoxellInc/vciy-verify/checks"
)

func main() {
	asJSON := flag.Bool("json", false, "output JSON instead of Markdown")
	panosXML := flag.String("panos-xml", "", "offline PAN-OS running-config.xml path to check interface-management-profile exposure")
	flag.Parse()

	if *panosXML != "" && flag.NArg() == 0 {
		findings, err := checks.AuditPANOSConfigFile(*panosXML)
		if err != nil {
			fmt.Fprintf(os.Stderr, "vciy-verify: %v\n", err)
			os.Exit(1)
		}
		if *asJSON {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			_ = enc.Encode(findings)
			return
		}
		for _, f := range findings {
			fmt.Printf("%s %s services=%s reason=%q receipt=%s\n",
				f.Status, f.ProfileName, strings.Join(f.Services, ","), f.Reason, f.ReceiptURL)
		}
		return
	}

	if flag.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "usage: vciy-verify [-json] [-panos-xml running-config.xml] CVE-YYYY-NNNN [CVE-...]")
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

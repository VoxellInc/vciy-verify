// Package checks provides offline appliance and configuration verifiers that pair
// exported device configurations with bitemporal receipts on https://vciy.com.
//
// # PAN-OS Management Plane Isolation (CVE-2026-0322)
//
// AuditPANOSMgmtProfiles parses exported Palo Alto Networks PAN-OS XML
// configurations (running-config.xml) offline and inspects every
// <interface-management-profile> entry for enabled administrative protocols
// (HTTPS, SSH, HTTP, Telnet) that lack a restricted <permitted-ip> allowlist.
//
// Background analysis and receipt links:
//   - https://vciy.com/articles/one-percent-epss-appliance-floor
//   - https://vciy.com/cve/CVE-2026-0322
//   - https://vciy.com/articles/null-score-kev-blindspot
//   - https://vciy.com/articles/sibling-handlers-incomplete-cve-fixes
//   - https://vciy.com/articles/cve-2026-104286-fortimail-kev-evidence-audit
//   - https://vciy.com/articles/cve-2026-20079-cisco-fmc-cvss-10-null-nvd-remediation
//   - https://vciy.com/articles/cve-2026-88779-citrix-netscaler-kev-low-epss-ir
//   - https://vciy.com/articles/cve-2026-56780-modoboa-drf-viewset-bypass-teardown
//   - https://vciy.com/articles/cve-2023-22894-strapi-cvss-49-vs-72-kev-remediation
//
// Related VCIY upstream security advisories:
//   - https://vciy.com/advisories/vciy-2026-0001
//   - https://vciy.com/advisories/vciy-2026-0002
//   - https://vciy.com/advisories/vciy-2026-0003
//   - https://vciy.com/advisories/vciy-2026-0004
//   - https://vciy.com/advisories/vciy-2026-0005
//   - https://vciy.com/advisories/vciy-2026-0006
//   - https://vciy.com/advisories/vciy-2026-0007
//   - https://vciy.com/advisories/vciy-2026-0008
//   - https://vciy.com/advisories/vciy-2026-0009
package checks

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"strings"
)

// PANOSMgmtProfile represents one <entry> inside an <interface-management-profile>
// block of an exported PAN-OS XML configuration.
type PANOSMgmtProfile struct {
	Name         string   `json:"name"`
	HTTPS        bool     `json:"https"`
	SSH          bool     `json:"ssh"`
	HTTP         bool     `json:"http"`
	Telnet       bool     `json:"telnet"`
	Ping         bool     `json:"ping"`
	PermittedIPs []string `json:"permitted_ips,omitempty"`
}

// PANOSFinding records an exposed PAN-OS interface-management-profile entry
// together with canonical receipt and analysis URLs for audit evidence.
type PANOSFinding struct {
	ProfileName  string   `json:"profile_name"`
	Services     []string `json:"services"`
	PermittedIPs []string `json:"permitted_ips,omitempty"`
	Status       string   `json:"status"`
	Reason       string   `json:"reason"`
	ReceiptURL   string   `json:"receipt_url"`
	ArticleURL   string   `json:"article_url"`
}

type xmlMgmtProfileWrapper struct {
	Entries []xmlMgmtProfileEntry `xml:"entry"`
}

type xmlMgmtProfileEntry struct {
	Name        string `xml:"name,attr"`
	HTTPS       string `xml:"https"`
	SSH         string `xml:"ssh"`
	HTTP        string `xml:"http"`
	Telnet      string `xml:"telnet"`
	Ping        string `xml:"ping"`
	PermittedIP struct {
		Entries []struct {
			Name string `xml:"name,attr"`
		} `xml:"entry"`
	} `xml:"permitted-ip"`
}

func isYes(s string) bool {
	return strings.EqualFold(strings.TrimSpace(s), "yes")
}

func isWildcardCIDR(cidr string) bool {
	switch strings.TrimSpace(cidr) {
	case "0.0.0.0/0", "::/0", "0.0.0.0", "::", "any":
		return true
	default:
		return false
	}
}

// AdminServices returns the ordered list of administrative management protocols
// enabled on the profile (https, ssh, http, telnet).
func (p PANOSMgmtProfile) AdminServices() []string {
	var out []string
	if p.HTTPS {
		out = append(out, "https")
	}
	if p.SSH {
		out = append(out, "ssh")
	}
	if p.HTTP {
		out = append(out, "http")
	}
	if p.Telnet {
		out = append(out, "telnet")
	}
	return out
}

// HasRestrictedAllowlist reports whether at least one non-wildcard permitted-ip
// CIDR entry restricts access to the profile and no wildcard CIDR is present.
func (p PANOSMgmtProfile) HasRestrictedAllowlist() bool {
	if len(p.PermittedIPs) == 0 {
		return false
	}
	for _, ip := range p.PermittedIPs {
		if isWildcardCIDR(ip) {
			return false
		}
	}
	return true
}

// ParsePANOSMgmtProfiles streams an exported PAN-OS XML configuration from r and
// returns every <interface-management-profile> entry in document order.
func ParsePANOSMgmtProfiles(r io.Reader) ([]PANOSMgmtProfile, error) {
	dec := xml.NewDecoder(r)
	var profiles []PANOSMgmtProfile
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("parse pan-os xml: %w", err)
		}
		se, ok := tok.(xml.StartElement)
		if !ok || se.Name.Local != "interface-management-profile" {
			continue
		}
		var wrapper xmlMgmtProfileWrapper
		if err := dec.DecodeElement(&wrapper, &se); err != nil {
			return nil, fmt.Errorf("decode interface-management-profile: %w", err)
		}
		for _, e := range wrapper.Entries {
			ips := make([]string, 0, len(e.PermittedIP.Entries))
			for _, ip := range e.PermittedIP.Entries {
				if trimmed := strings.TrimSpace(ip.Name); trimmed != "" {
					ips = append(ips, trimmed)
				}
			}
			profiles = append(profiles, PANOSMgmtProfile{
				Name:         strings.TrimSpace(e.Name),
				HTTPS:        isYes(e.HTTPS),
				SSH:          isYes(e.SSH),
				HTTP:         isYes(e.HTTP),
				Telnet:       isYes(e.Telnet),
				Ping:         isYes(e.Ping),
				PermittedIPs: ips,
			})
		}
	}
	return profiles, nil
}

// AuditPANOSMgmtProfiles inspects exported PAN-OS XML configuration data from r
// and returns findings for every interface-management-profile that enables
// administrative services (HTTPS, SSH, HTTP, or Telnet) without a non-wildcard
// permitted-ip allowlist, or cleartext HTTP/Telnet even with an allowlist.
func AuditPANOSMgmtProfiles(r io.Reader) ([]PANOSFinding, error) {
	profiles, err := ParsePANOSMgmtProfiles(r)
	if err != nil {
		return nil, err
	}
	var findings []PANOSFinding
	for _, p := range profiles {
		svcs := p.AdminServices()
		if len(svcs) == 0 {
			continue
		}
		if !p.HasRestrictedAllowlist() {
			reason := "admin services enabled with empty permitted-ip allowlist"
			if len(p.PermittedIPs) > 0 {
				reason = fmt.Sprintf("admin services enabled with wildcard permitted-ip (%s)", strings.Join(p.PermittedIPs, ", "))
			}
			findings = append(findings, PANOSFinding{
				ProfileName:  p.Name,
				Services:     svcs,
				PermittedIPs: p.PermittedIPs,
				Status:       "EXPOSED_MGMT_PROFILE",
				Reason:       reason,
				ReceiptURL:   "https://vciy.com/cve/CVE-2026-0322",
				ArticleURL:   "https://vciy.com/articles/one-percent-epss-appliance-floor",
			})
			continue
		}
		if p.HTTP || p.Telnet {
			findings = append(findings, PANOSFinding{
				ProfileName:  p.Name,
				Services:     svcs,
				PermittedIPs: p.PermittedIPs,
				Status:       "CLEARTEXT_MGMT_SERVICE",
				Reason:       "cleartext http or telnet enabled on interface-management-profile",
				ReceiptURL:   "https://vciy.com/cve/CVE-2026-0322",
				ArticleURL:   "https://vciy.com/articles/one-percent-epss-appliance-floor",
			})
		}
	}
	return findings, nil
}

// AuditPANOSConfigBytes runs AuditPANOSMgmtProfiles over an in-memory XML slice.
func AuditPANOSConfigBytes(xmlBytes []byte) ([]PANOSFinding, error) {
	return AuditPANOSMgmtProfiles(bytes.NewReader(xmlBytes))
}

// AuditPANOSConfigFile reads an exported PAN-OS running-config.xml from disk and
// runs AuditPANOSMgmtProfiles offline.
func AuditPANOSConfigFile(path string) ([]PANOSFinding, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return AuditPANOSConfigBytes(raw)
}

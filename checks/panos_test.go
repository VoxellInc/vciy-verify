package checks_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/VoxellInc/vciy-verify/checks"
)

const samplePANOSRunningConfig = `<?xml version="1.0"?>
<config version="11.1.0">
  <devices>
    <entry name="localhost.localdomain">
      <network>
        <profiles>
          <interface-management-profile>
            <entry name="wan-unrestricted">
              <https>yes</https>
              <ssh>yes</ssh>
              <ping>yes</ping>
            </entry>
            <entry name="dmz-wildcard">
              <https>yes</https>
              <permitted-ip>
                <entry name="0.0.0.0/0"/>
              </permitted-ip>
            </entry>
            <entry name="oob-bastion-isolated">
              <https>yes</https>
              <ssh>yes</ssh>
              <permitted-ip>
                <entry name="10.254.10.0/24"/>
                <entry name="192.0.2.10/32"/>
              </permitted-ip>
            </entry>
            <entry name="legacy-telnet-bastion">
              <telnet>yes</telnet>
              <permitted-ip>
                <entry name="10.254.10.0/24"/>
              </permitted-ip>
            </entry>
            <entry name="healthcheck-ping-only">
              <ping>yes</ping>
              <https>no</https>
              <ssh>no</ssh>
            </entry>
          </interface-management-profile>
        </profiles>
      </network>
    </entry>
  </devices>
</config>`

func TestParseAndAuditPANOSMgmtProfiles(t *testing.T) {
	profiles, err := checks.ParsePANOSMgmtProfiles(strings.NewReader(samplePANOSRunningConfig))
	if err != nil {
		t.Fatalf("ParsePANOSMgmtProfiles unexpected error: %v", err)
	}
	if len(profiles) != 5 {
		t.Fatalf("parsed %d profiles, want 5", len(profiles))
	}
	if !profiles[2].HasRestrictedAllowlist() {
		t.Fatalf("oob-bastion-isolated should report restricted allowlist: %+v", profiles[2])
	}
	if profiles[0].HasRestrictedAllowlist() || profiles[1].HasRestrictedAllowlist() {
		t.Fatalf("unrestricted or wildcard profile reported restricted allowlist")
	}

	findings, err := checks.AuditPANOSConfigBytes([]byte(samplePANOSRunningConfig))
	if err != nil {
		t.Fatalf("AuditPANOSConfigBytes unexpected error: %v", err)
	}
	if len(findings) != 3 {
		t.Fatalf("got %d findings, want 3: %+v", len(findings), findings)
	}

	if findings[0].ProfileName != "wan-unrestricted" || findings[0].Status != "EXPOSED_MGMT_PROFILE" {
		t.Fatalf("finding[0] = %+v, want wan-unrestricted EXPOSED_MGMT_PROFILE", findings[0])
	}
	if findings[1].ProfileName != "dmz-wildcard" || !strings.Contains(findings[1].Reason, "0.0.0.0/0") {
		t.Fatalf("finding[1] = %+v, want dmz-wildcard wildcard reason", findings[1])
	}
	if findings[2].ProfileName != "legacy-telnet-bastion" || findings[2].Status != "CLEARTEXT_MGMT_SERVICE" {
		t.Fatalf("finding[2] = %+v, want legacy-telnet-bastion CLEARTEXT_MGMT_SERVICE", findings[2])
	}
	for _, f := range findings {
		if f.ReceiptURL != "https://vciy.com/cve/CVE-2026-0322" {
			t.Fatalf("unexpected ReceiptURL %q", f.ReceiptURL)
		}
		if f.ArticleURL != "https://vciy.com/articles/one-percent-epss-appliance-floor" {
			t.Fatalf("unexpected ArticleURL %q", f.ArticleURL)
		}
	}
}

func TestAuditPANOSConfigFileAndMalformedXML(t *testing.T) {
	dir := t.TempDir()
	cleanCfg := filepath.Join(dir, "running-config.xml")
	xmlDoc := `<config><interface-management-profile><entry name="bastion"><https>yes</https><permitted-ip><entry name="10.10.0.0/24"/></permitted-ip></entry></interface-management-profile></config>`
	if err := os.WriteFile(cleanCfg, []byte(xmlDoc), 0o600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}
	findings, err := checks.AuditPANOSConfigFile(cleanCfg)
	if err != nil {
		t.Fatalf("AuditPANOSConfigFile error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for isolated bastion profile, got %+v", findings)
	}

	if _, err := checks.AuditPANOSConfigBytes([]byte("<config><interface-management-profile><entry>")); err == nil {
		t.Fatal("expected error for truncated XML, got nil")
	}
}

func ExampleAuditPANOSMgmtProfiles() {
	const cfg = `<config><interface-management-profile>
		<entry name="wan-mgmt"><https>yes</https><ssh>yes</ssh></entry>
		<entry name="oob-mgmt"><https>yes</https><permitted-ip><entry name="10.254.0.0/24"/></permitted-ip></entry>
	</interface-management-profile></config>`

	findings, _ := checks.AuditPANOSMgmtProfiles(strings.NewReader(cfg))
	for _, f := range findings {
		fmt.Printf("%s %s services=%v receipt=%s\n", f.Status, f.ProfileName, f.Services, f.ReceiptURL)
	}
	// Output:
	// EXPOSED_MGMT_PROFILE wan-mgmt services=[https ssh] receipt=https://vciy.com/cve/CVE-2026-0322
}

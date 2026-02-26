package engine

import (
	"fmt"
	"path/filepath"
	"testing"
)

func TestReproSSRFMissedDetection(t *testing.T) {
	rootDir := "repro_issue_ssrf"
	rulesDir := filepath.Join(rootDir, "rules")

	// Initialize Engine
	engine, err := NewEngine(rulesDir)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	// Run scan
	vulns, err := engine.ScanDirectory(rootDir)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	sqliCount := 0
	ssrfCount := 0

	fmt.Printf("Found %d vulnerabilities\n", len(vulns))
	for _, v := range vulns {
		fmt.Printf("Vuln: %s at %s:%d\n", v.RuleID, v.FilePath, v.LineNumber)
		for _, step := range v.Steps {
			fmt.Printf("  Step: %s at %s:%d\n", step.Description, step.FilePath, step.LineNumber)
		}
		if v.RuleID == "java-sqli" {

			sqliCount++
			t.Errorf("Found FALSE POSITIVE SQLi vulnerability at %s:%d", v.FilePath, v.LineNumber)
		}
		if v.RuleID == "java-ssrf" {
			ssrfCount++
		}
	}

	// We expect 0 SQLi (because HttpClient is safe for SQLi)
	if sqliCount == 0 {
		t.Log("SQLi False Positives suppressed! (SUCCESS)")
	} else {
		t.Log("SQLi False Positives STILL PRESENT (FAILURE)")
	}

	// We expect 2 SSRF (because HttpClient is NOT safe for SSRF)
	// One at line 23 (client.execute)
	// One at line 35 (Request.Get...execute)
	if ssrfCount >= 2 {
		t.Log("SSRF True Positives detected! (SUCCESS)")
	} else {
		t.Errorf("SSRF True Positives MISSED! Found %d, expected 2 (FAILURE)", ssrfCount)
	}
}

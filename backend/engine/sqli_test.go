package engine

import (
	"path/filepath"
	"testing"
)

func TestReproJdbcSqli(t *testing.T) {
	rootDir, _ := filepath.Abs("repro_sqli")

	// Initialize Engine
	// Mock NewEngine behavior or use it correctly if possible
	// NewEngine requires a rulesDir. We can point it to a dummy dir or just struct init.

	sqliRule := Rule{
		ID:          "java-sqli",
		Name:        "SQL Injection",
		Severity:    "HIGH",
		Language:    "java",
		Patterns:    []string{},
		Sources:     []string{"@RequestParam"},
		Sinks:       []string{`executeQuery\(`},
		Sanitizers:  []string{},
		Description: "Detects SQL injection",
	}

	engine := &Engine{
		Rules: []Rule{sqliRule},
		Index: NewSymbolTable(),
	}

	// Build Index
	ProjectIndex = engine.Index
	ProjectIndex.BuildIndex(rootDir)

	// Scan
	vulns, err := engine.ScanDirectory(rootDir)
	if err != nil {
		t.Fatalf("ScanDirectory failed: %v", err)
	}

	foundCount := 0
	for _, v := range vulns {
		t.Logf("Vuln: %s at %s:%d", v.RuleID, v.FilePath, v.LineNumber)
		for _, s := range v.Steps {
			t.Logf("  Step: %s", s.Description)
		}
		if v.RuleID == "java-sqli" {
			foundCount++
		}
	}

	// Expect 3 vulnerabilities (one simple, one large method, one cross method)
	if foundCount < 3 {
		t.Errorf("Expected at least 3 vulnerabilities, found %d", foundCount)
	}
}

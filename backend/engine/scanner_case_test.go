package engine

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCaseScan(t *testing.T) {
	// Setup
	cwd, _ := os.Getwd()
	// Navigate up from backend/engine to root of backend
	backendRoot := filepath.Dir(filepath.Dir(cwd))
	testFile := filepath.Join(backendRoot, "backend/engine/tests/CaseTest.java")

	// Initialize Engine
	rulesPath := filepath.Join(backendRoot, "backend/rules")
	engine, err := NewEngine(rulesPath)
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}

	// Build Index
	engine.Index.BuildIndex(filepath.Dir(testFile))

	// Scan
	vulns, err := engine.ScanFile(testFile, filepath.Dir(testFile))
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}

	// Analyze Results
	foundCrossContamination := false
	for _, v := range vulns {
		// Check if any vulnerability in "update" case traces back to "delete" case
		// In CaseTest.java:
		// "delete" case is around line 24-34
		// "update" case is around line 35-46
		// Sink in update is around line 41: rowsAffected = stmt.executeUpdate(sql);

		isUpdateSink := false
		if strings.Contains(v.LineContent, "UPDATE sqli") || strings.Contains(v.LineContent, "executeUpdate") {
			// Check snippet or steps to see if we are in update case
			// Heuristic: line number > 35
			if v.LineNumber > 35 {
				isUpdateSink = true
			}
		}

		if isUpdateSink {
			// Check steps for contamination
			for _, step := range v.Steps {
				// If we see "DELETE FROM" in the steps, it's contaminated
				if strings.Contains(step.LineContent, "DELETE FROM") {
					foundCrossContamination = true
					fmt.Printf("Found Cross Contamination in Vuln at line %d:\n", v.LineNumber)
					for _, s := range v.Steps {
						fmt.Printf("  Step %d: %s (Line %d)\n", s.LineNumber, s.LineContent, s.LineNumber)
					}
				}
				// If we see "rowsAffected = stmt.executeUpdate(sql)" from the DELETE case (line ~29)
				if strings.Contains(step.LineContent, "executeUpdate") && step.LineNumber < 35 && step.LineNumber > 25 {
					foundCrossContamination = true
					fmt.Printf("Found Cross Contamination (rowsAffected) in Vuln at line %d:\n", v.LineNumber)
				}
			}
		}
	}

	if foundCrossContamination {
		t.Errorf("Test failed: Cross-case contamination detected.")
	} else {
		fmt.Println("Test passed: No cross-case contamination found.")
	}

	// Print all vulns for debugging
	bytes, _ := json.MarshalIndent(vulns, "", "  ")
	fmt.Println(string(bytes))
}

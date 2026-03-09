package cpg

import (
	"fmt"
	"regexp"
	"strings"
)

// Internal node types for method body analysis
const (
	TypeVariable   = "variable"
	TypeExpression = "expression"
	TypeControl    = "control"
	TypeReturn     = "return"
)

// Internal edge types
const (
	EdgeAST = "AST"
	EdgeCFG = "CFG"
	EdgePDG = "PDG"
)

// ParseResult holds the result of method parsing
type ParseResult struct {
	Nodes       []Node
	Edges       []Edge
	CallSites   map[string][]string // Map called method name -> list of expression node IDs
	FieldAccess map[string][]string // Map accessed field name -> list of expression node IDs
}

// ParseMethodStructure analyzes method body to extract internal nodes and edges
// methodID: The ID of the method node (e.g. "com.example.User:login")
// body: The source code of the method body
// startLine: The starting line number of the method in the file
func ParseMethodStructure(methodID string, body string, startLine int) ParseResult {
	result := ParseResult{
		Nodes:       []Node{},
		Edges:       []Edge{},
		CallSites:   make(map[string][]string),
		FieldAccess: make(map[string][]string),
	}

	// Normalize body (remove comments, simplified)
	cleanBody := removeComments(body)
	lines := strings.Split(cleanBody, "\n")

	// Regex patterns
	// Control flow: if, for, while, switch, return
	reControl := regexp.MustCompile(`^\s*(if|for|while|switch|else)\b`)
	reReturn := regexp.MustCompile(`^\s*return\b`)
	// Variable declaration: Type name = ...; or Type name;
	// Naive pattern: Word Word (= ...)?;
	// Must not start with keyword
	reVarDecl := regexp.MustCompile(`^\s*(?:final\s+)?([a-zA-Z0-9_<>\[\]\.]+)\s+([a-zA-Z0-9_]+)\s*(=|;)`)

	// Assignment/Expression: name = ...; or func(...);
	// reExpr := regexp.MustCompile(`^\s*([a-zA-Z0-9_\.]+)\s*(=|\()`) // Unused for now

	// Method Call: name(
	reCall := regexp.MustCompile(`([a-zA-Z0-9_]+)\s*\(`)

	var lastNodeID string

	// Helper to add node
	addInternalNode := func(label, nType string, lineOffset int) string {
		// Create unique ID using line number and index (in case of multiple nodes per line)
		id := fmt.Sprintf("%s:%s:%d", methodID, nType, startLine+lineOffset)

		// If ID already exists (e.g. loops), append a suffix
		for _, n := range result.Nodes {
			if n.ID == id {
				id = id + "_"
			}
		}

		node := Node{
			ID:    id,
			Label: label,
			Type:  nType,
			Data:  map[string]any{"line": startLine + lineOffset},
		}
		result.Nodes = append(result.Nodes, node)

		// AST Edge: Method -> Node (Contains)
		result.Edges = append(result.Edges, Edge{Source: methodID, Target: id, Type: EdgeAST})

		// CFG Edge: Previous -> Current (Control Flow)
		if lastNodeID != "" {
			result.Edges = append(result.Edges, Edge{Source: lastNodeID, Target: id, Type: EdgeCFG})
		}
		lastNodeID = id
		return id
	}

	declaredVars := make(map[string]string) // name -> nodeID
	reWords := regexp.MustCompile(`\b[a-zA-Z0-9_]+\b`)

	checkUsages := func(targetID, codeLine string) {
		words := reWords.FindAllString(codeLine, -1)
		used := make(map[string]bool)
		for _, w := range words {
			if srcID, ok := declaredVars[w]; ok {
				if !used[w] && srcID != targetID {
					result.Edges = append(result.Edges, Edge{Source: srcID, Target: targetID, Type: EdgePDG})
					used[w] = true
				}
			}
		}
	}

	for i, line := range lines {
		trimLine := strings.TrimSpace(line)
		if trimLine == "" || trimLine == "{" || trimLine == "}" || strings.HasPrefix(trimLine, "@") {
			continue
		}

		// 1. Control Flow
		if matches := reControl.FindStringSubmatch(trimLine); len(matches) > 1 {
			// keyword := matches[1] // Unused
			// Truncate condition
			label := trimLine
			if len(label) > 30 {
				label = label[:27] + "..."
			}
			nodeID := addInternalNode(label, TypeControl, i)
			checkUsages(nodeID, trimLine)
			continue
		}

		// 2. Return
		if reReturn.MatchString(trimLine) {
			label := trimLine
			if len(label) > 20 {
				label = label[:17] + "..."
			}
			nodeID := addInternalNode(label, TypeReturn, i)
			checkUsages(nodeID, trimLine)
			continue
		}

		// 3. Variable Declaration
		if matches := reVarDecl.FindStringSubmatch(trimLine); len(matches) > 2 {
			varType := matches[1]
			varName := matches[2]
			// Exclude keywords
			if !isKeyword(varType) && !isKeyword(varName) {
				label := fmt.Sprintf("%s %s", varType, varName)
				nodeID := addInternalNode(label, TypeVariable, i)

				// Check usages in the declaration line (RHS)
				checkUsages(nodeID, trimLine)

				// Register variable
				declaredVars[varName] = nodeID

				// Identify calls in RHS
				if strings.Contains(trimLine, "=") {
					callMatches := reCall.FindAllStringSubmatch(trimLine, -1)
					for _, m := range callMatches {
						if len(m) > 1 && !isKeyword(m[1]) {
							callName := m[1]
							result.CallSites[callName] = append(result.CallSites[callName], nodeID)
						}
					}
				}
				continue
			}
		}

		// 4. Expression / Assignment / Call
		// Default case for other lines
		// Check if it looks like code
		if len(trimLine) > 2 {
			label := trimLine
			if len(label) > 40 {
				label = label[:37] + "..."
			}
			nodeID := addInternalNode(label, TypeExpression, i)

			checkUsages(nodeID, trimLine)

			// Scan for calls in this line
			callMatches := reCall.FindAllStringSubmatch(trimLine, -1)
			for _, m := range callMatches {
				if len(m) > 1 {
					callName := m[1]
					if !isKeyword(callName) {
						result.CallSites[callName] = append(result.CallSites[callName], nodeID)
					}
				}
			}

			// Scan for field access (naive)
			// We don't have field list here easily, pass it?
			// Or just capture all identifiers and let handler match them?
			// Let's capture identifiers that look like fields (this.x or just x)
			// Too noisy. Let handler pass fields?
			// Handler will do string matching on the line content anyway.
			// We can just return the nodeID for the line, and handler can check if line contains field.
		}
	}

	return result
}

func removeComments(source string) string {
	// Simple comment removal
	// Block comments /* ... */
	reBlock := regexp.MustCompile(`/\*[\s\S]*?\*/`)
	source = reBlock.ReplaceAllString(source, "")
	// Line comments // ...
	reLine := regexp.MustCompile(`//.*`)
	source = reLine.ReplaceAllString(source, "")
	return source
}

func isKeyword(w string) bool {
	keywords := map[string]bool{
		"public": true, "private": true, "protected": true, "static": true, "final": true,
		"if": true, "else": true, "for": true, "while": true, "do": true, "switch": true,
		"return": true, "break": true, "continue": true, "try": true, "catch": true, "finally": true,
		"class": true, "interface": true, "enum": true, "new": true, "this": true, "super": true,
		"void": true, "int": true, "long": true, "float": true, "double": true, "boolean": true, "char": true, "byte": true,
		"case": true, "default": true, "import": true, "package": true,
	}
	return keywords[w]
}

package engine

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	"gopkg.in/yaml.v3"
)

// Rule represents a SAST rule
type Rule struct {
	ID          string   `yaml:"id" json:"id"`
	Name        string   `yaml:"name" json:"name"`
	Severity    string   `yaml:"severity" json:"severity"` // HIGH, MEDIUM, LOW
	Description string   `yaml:"description" json:"description"`
	Language    string   `yaml:"language" json:"language"`
	Patterns    []string `yaml:"patterns" json:"patterns"` // Regex patterns
	// Simple simulation of taint tracking: Source and Sink must exist in the file
	Sources         []string `yaml:"sources,omitempty" json:"sources,omitempty"`
	Sinks           []string `yaml:"sinks,omitempty" json:"sinks,omitempty"`
	Sanitizers      []string `yaml:"sanitizers,omitempty" json:"sanitizers,omitempty"`
	ExcludePatterns []string `yaml:"exclude_patterns,omitempty" json:"exclude_patterns,omitempty"`
}

// Vulnerability represents a found issue
type Vulnerability struct {
	RuleID      string `json:"rule_id"`
	RuleName    string `json:"rule_name"`
	Severity    string `json:"severity"`
	FilePath    string `json:"file_path"`
	LineNumber  int    `json:"line_number"`
	LineContent string `json:"line_content"`
	Snippet     string `json:"snippet"` // Context
	Steps       []Step `json:"steps,omitempty"`
}

// Step represents a step in the taint path
type Step struct {
	FilePath    string `json:"file_path"`
	LineNumber  int    `json:"line_number"`
	LineContent string `json:"line_content"`
	Description string `json:"description"`
}

// Engine is the main scanner
type Engine struct {
	Rules []Rule
	Index *SymbolTable
}

// NewEngine creates a new engine and loads rules from a directory
func NewEngine(rulesDir string) (*Engine, error) {
	// Initialize Index
	ProjectIndex = NewSymbolTable()

	var rules []Rule
	files, err := ioutil.ReadDir(rulesDir)
	if err != nil {
		return nil, err
	}

	for _, f := range files {
		if filepath.Ext(f.Name()) == ".yaml" || filepath.Ext(f.Name()) == ".yml" {
			content, err := ioutil.ReadFile(filepath.Join(rulesDir, f.Name()))
			if err != nil {
				continue
			}
			var rule Rule
			if err := yaml.Unmarshal(content, &rule); err != nil {
				continue
			}
			rules = append(rules, rule)
			// fmt.Printf("Loaded rule: %s\n", rule.ID)
		}
	}
	// fmt.Printf("Total rules loaded: %d\n", len(rules))
	return &Engine{Rules: rules, Index: ProjectIndex}, nil
}

// ScanFile scans a single file
func (e *Engine) ScanFile(path string, rootDir string) ([]Vulnerability, error) {
	// fmt.Printf("Scanning file: %s\n", path)
	contentBytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	content := string(contentBytes)
	lines := strings.Split(content, "\n")
	var vulns []Vulnerability

	relPath := toRelative(path, rootDir)

	for _, rule := range e.Rules {
		// Check language extension
		ext := strings.ToLower(filepath.Ext(path))
		if rule.Language != "" && !strings.Contains(rule.Language, ext[1:]) && rule.Language != "all" {
			// specific check for java
			if rule.Language == "java" && ext != ".java" {
				continue
			}
			if rule.Language == "xml" && ext != ".xml" {
				continue
			}
		}

		// Helper to check exclusion
		isExcluded := func(line string) bool {
			for _, p := range rule.ExcludePatterns {
				if matched, _ := regexp.MatchString(p, line); matched {
					return true
				}
			}
			return false
		}

		// Mode 1: Simple Pattern Matching
		if len(rule.Sources) == 0 || len(rule.Sinks) == 0 {
			for _, pattern := range rule.Patterns {
				re, err := regexp.Compile(pattern)
				if err != nil {
					continue
				}

				// Scan line by line for line number reporting
				for i, line := range lines {
					if re.MatchString(line) {
						if isExcluded(line) {
							continue
						}
						// Create a single step for the sink
						steps := []Step{{
							FilePath:    relPath,
							LineNumber:  i + 1,
							LineContent: strings.TrimSpace(line),
							Description: "Sink: MyBatis XML Direct SQL Execution (Pattern: " + pattern + ")",
						}}

						// Special handling for MyBatis SQL Injection
						if rule.ID == "mybatis-sqli" && strings.HasSuffix(path, ".xml") {
							// Try to find the corresponding Java Mapper interface
							javaStep, methodID, targetClassName := findMyBatisSource(path, lines, i, rootDir)
							if javaStep != nil {
								// Trace usages
								usageSteps := traceUsages(methodID, rootDir)

								// Filter out the interface file itself from usages to avoid duplicates
								var finalUsageSteps []Step
								for _, s := range usageSteps {
									// Simple check: if file path is same
									if s.FilePath != javaStep.FilePath {
										finalUsageSteps = append(finalUsageSteps, s)
									}
								}

								if len(finalUsageSteps) > 0 {
									// Create a separate vulnerability for each usage found
									for _, usage := range finalUsageSteps {
										var chain []Step

										// Try to trace back from usage to find the source
										absUsagePath := filepath.Join(rootDir, usage.FilePath)
										contentBytes, err := ioutil.ReadFile(absUsagePath)
										var tracedBackSteps []Step
										if err == nil {
											usageLines := strings.Split(string(contentBytes), "\n")

											// Validate usage: Ensure it calls the Mapper method
											if !isValidUsage(usage.LineContent, usageLines, usage.LineNumber, methodID, targetClassName, rootDir, absUsagePath) {
												continue
											}

											// Extract arguments passed to methodID
											args := extractArguments(usage.LineContent, methodID)
											if len(args) > 0 {
												arg := strings.TrimSpace(args[0])
												// Use rule.Sources for traceBack
												sources := rule.Sources
												if len(sources) == 0 {
													sources = []string{"@RequestParam", "@PathVariable", "HttpServletRequest", "System.in", "Scanner"}
												}

												trace, found := traceBack(absUsagePath, usageLines, usage.LineNumber-1, arg, sources, rule.Sanitizers, 0, rootDir, nil)
												fmt.Printf("TraceBack for %s in %s line %d: found=%v steps=%d\n", arg, absUsagePath, usage.LineNumber, found, len(trace))
												if found {
													tracedBackSteps = trace
												}
											}
										}

										if len(tracedBackSteps) > 0 {
											chain = append(chain, tracedBackSteps...)
											// Append usage step if it's not the last step of trace
											last := tracedBackSteps[len(tracedBackSteps)-1]
											if last.LineNumber != usage.LineNumber || last.FilePath != usage.FilePath {
												chain = append(chain, usage)
											}

											chain = append(chain, *javaStep)
											chain = append(chain, steps...)

											vulns = append(vulns, Vulnerability{
												RuleID:      rule.ID,
												RuleName:    rule.Name,
												Severity:    rule.Severity,
												FilePath:    relPath,
												LineNumber:  i + 1,
												LineContent: strings.TrimSpace(line),
												Snippet:     getSnippet(lines, i),
												Steps:       chain,
											})
										}
										// If trace back failed, we skip reporting this usage path to avoid false positives
									}
								} else {
									// No usages found.
									// This implies the Mapper interface method is defined but we couldn't find any callers.
									// To avoid false positives (dead code), we skip reporting.
								}
								// Handled, skip generic report
								continue
							} else {
								continue
							}
						}

						vulns = append(vulns, Vulnerability{
							RuleID:      rule.ID,
							RuleName:    rule.Name,
							Severity:    rule.Severity,
							FilePath:    relPath,
							LineNumber:  i + 1,
							LineContent: strings.TrimSpace(line),
							Snippet:     getSnippet(lines, i),
							Steps:       steps,
						})
					}
				}
			}
		}

		// Mode 2: Taint Simulation (Data Flow Analysis)
		if len(rule.Sources) > 0 && len(rule.Sinks) > 0 {
			// Find all Sinks
			for _, sink := range rule.Sinks {
				reSink, err := regexp.Compile(sink)
				if err != nil {
					continue
				}

				for i, line := range lines {
					if reSink.MatchString(line) {
						// Skip comments
						trimmedLine := strings.TrimSpace(line)
						if strings.HasPrefix(trimmedLine, "//") || strings.HasPrefix(trimmedLine, "*") || strings.HasPrefix(trimmedLine, "/*") {
							continue
						}

						if isExcluded(line) {
							continue
						}

						// Heuristic: Avoid matching method definitions if the sink pattern matches the method name
						// e.g. "public void execute(...)" should not match sink "execute("
						trimmed := strings.TrimSpace(line)
						if strings.HasPrefix(trimmed, "public ") || strings.HasPrefix(trimmed, "protected ") || strings.HasPrefix(trimmed, "private ") {
							loc := reSink.FindStringIndex(line)
							if loc != nil {
								start := loc[0]
								prefix := line[:start]
								// If prefix does not contain indicators of a method call or statement
								// (e.g. "=", "return ", "new ", "(", ".")
								// Then it is likely a method definition.
								if !strings.Contains(prefix, "=") &&
									!strings.Contains(prefix, "return ") &&
									!strings.Contains(prefix, "new ") &&
									!strings.Contains(prefix, "(") &&
									!strings.Contains(prefix, ".") {
									continue
								}
							}
						}

						// Found Sink, now trace back variables
						vars := extractVariables(line)
						for _, varName := range vars {
							// Optimization: Ignore variables that are only on the LHS of an assignment
							// This prevents tracing the result of a sink (e.g. rowsAffected = stmt.executeUpdate(sql))
							// which can lead to cross-case contamination if the variable is reused.
							// Robust split: Find the first '=' that is NOT inside quotes
							var splitIdx int = -1
							inQuote := false
							escaped := false
							for k, r := range line {
								if escaped {
									escaped = false
									continue
								}
								if r == '\\' {
									escaped = true
									continue
								}
								if r == '"' {
									inQuote = !inQuote
									continue
								}
								if !inQuote && r == '=' {
									splitIdx = k
									break
								}
							}

							if splitIdx != -1 {
								lhs := line[:splitIdx]
								if isVariableOnLHS(lhs, varName) {
									// It is on LHS. Check if it is also on RHS.
									rhs := line[splitIdx+1:]
									rhsVars := extractVariables(rhs)
									onRHS := false
									for _, rv := range rhsVars {
										if rv == varName {
											onRHS = true
											break
										}
									}
									if !onRHS {
										continue
									}
								}
							}

							// Optimization: For method call sinks like .append(),
							// we should only trace the ARGUMENTS, not the method call itself or the object.
							// E.g. response.append("<li>") -> "li" is extracted as var, but it's a string literal part.
							// Real var should be inside parens.

							if strings.Contains(sink, "append") || strings.Contains(line, ".append(") {
								// Check if varName is within the parens of append(...)
								// This is tricky with regex, but we can check if it's "append(...varName...)"
								// and NOT "varName.append(...)" (unless varName IS the sink object, but usually we track data)

								// Simplified check: if varName is the object calling append (e.g. response), ignore it
								// We only want to track what is being appended.
								if strings.Contains(line, varName+".append") {
									continue
								}

								// Also check if varName is just a substring of a string literal
								// e.g. append("<ul>") -> extractVariables finds "ul", but it is inside quotes.
								// Simple check: is it surrounded by quotes?
								// This is heuristic and not perfect parser, but reduces noise.
								// Find the varName in the line
								idx := strings.Index(line, varName)
								if idx > 0 && idx < len(line)-1 {
									// Check if surrounded by quotes
									// This is very rough, better would be to check if we are inside a string literal context
									// But for now, let's assume if it's part of "..." it's safe?
									// Actually, extractVariables implementation might already be too aggressive.
								}

								// BETTER CHECK: Only trace if varName appears inside append(...)
								// AND is not part of a string literal.
								// But without full parser this is hard.
								// Let's at least check if "append(..." + varName exists or similar?

								// For now, let's rely on the Source check in traceBack.
								// If "ul" traces back to nothing, it won't report (unless we find a variable named "ul").
								// The issue is if "ul" is interpreted as a variable.
								// If "ul" is not defined as a variable in the scope, traceBack should fail quickly.
								// BUT, legacyTraceBack might be too loose.

								// Let's add a check: Is varName inside quotes in this line?
								// Count quotes before the varName occurrence
								// This is expensive but necessary for "<ul>" case

								isInsideQuotes := false
								quoteCount := 0
								for k, char := range line {
									if char == '"' {
										quoteCount++
									}
									if k >= strings.Index(line, varName) {
										break
									}
								}
								if quoteCount%2 != 0 {
									isInsideQuotes = true
								}

								if isInsideQuotes {
									continue
								}
							}

							// Check variable type for generic sinks like "execute"
							// If the object calling "execute" is a known safe type (e.g. HttpClient), ignore it.
							// BUT ONLY if we are checking for SQL Injection!
							// For SSRF, HttpClient.execute IS a sink.
							if strings.Contains(sink, "execute") {
								// Find the object calling execute
								// e.g. client.execute(get) -> client
								// e.g. stmt.execute(sql) -> stmt
								objName := findCallerObject(line, "execute")

								// DEBUG PRINT
								// fmt.Printf("DEBUG: Line=%s, Rule=%s, ObjName=%s\n", line, rule.ID, objName)

								if objName != "" {
									objType := resolveVariableType(lines, i, objName)

									// DEBUG PRINT
									// fmt.Printf("DEBUG: Resolved Type for %s: %s\n", objName, objType)

									if objType != "" {
										// If it's SQLi rule, check if it's safe type (like HttpClient)
										if strings.Contains(strings.ToLower(rule.ID), "sqli") || strings.Contains(strings.ToLower(rule.ID), "sql-injection") {
											if isSafeExecuteType(objType) {
												continue
											}
										}

										// If it's SSRF rule, we MIGHT want to filter OUT SQL types?
										// e.g. stmt.execute() is NOT SSRF.
										// But let's stick to the current issue: SSRF missing HttpClient.
										// Since we are NOT skipping for SSRF above, it should fall through.
									}
								} else {
									// If we cannot find caller object, we might want to be conservative.
									// But for "Request.Get().execute()", findCallerObject SHOULD return "Request".
								}
							}

							// For chained method calls like Request.Get(url).execute(),
							// The "url" is not an argument to "execute", but to "Get".
							// extractVariables finds "url".
							// But is "url" considered a variable for "execute"?
							// extractVariables just dumps all variables.
							// Then traceBack is called on each.
							// traceBack checks if the variable leads to a source.

							// IF varName is "Request", traceBack("Request") -> fails (it's a class).
							// IF varName is "url", traceBack("url") -> succeeds (it's a param).

							// So why is it failing?
							// Maybe "url" is filtered out by some optimization?

							// Line 312: check if varName is argument to sink method (append heuristic).
							// We might need to RELAX this for chained calls or specifically for "execute" in SSRF?
							// Or maybe the loop continues and hits "url"?

							// Wait, if line 312 logic applies to "execute", it might filter "url" out because "url" is NOT inside execute(...)
							// But line 312 explicitly checks strings.Contains(sink, "append").
							// So it shouldn't affect "execute".

							// Let's look at traceBack for "url" in line:
							// Request.Get(String.valueOf(url)).execute()
							// traceBack("url") ->
							// 1. Check if "url" is source. Yes, @RequestParam.
							// Return found=true.

							// So it SHOULD be found.

							// Trace back this variable
							// fmt.Printf("Tracing var: %s for sink: %s in rule: %s\n", varName, sink, rule.ID)
							trace, found := traceBack(path, lines, i, varName, rule.Sources, rule.Sanitizers, 0, rootDir, nil)
							if found {
								// fmt.Printf("FOUND Trace for %s!\n", varName)
								// Add Sink step
								trace = append(trace, Step{
									FilePath:    relPath,
									LineNumber:  i + 1,
									LineContent: strings.TrimSpace(line),
									Description: "Sink: " + sink + " (Triggered by " + varName + ")",
								})

								vulns = append(vulns, Vulnerability{
									RuleID:      rule.ID,
									RuleName:    rule.Name,
									Severity:    rule.Severity,
									FilePath:    relPath,
									LineNumber:  i + 1,
									LineContent: strings.TrimSpace(line),
									Snippet:     getSnippet(lines, i),
									Steps:       trace,
								})
								break // Report once per sink line to avoid duplicates
							}
						}
					}
				}
			}
		}

	}

	return vulns, nil
}

// ScanDirectory scans a directory recursively
func (e *Engine) ScanDirectory(dirPath string) ([]Vulnerability, error) {
	var allVulns []Vulnerability

	// First, build the index if not already built?
	// The NewEngine initializes NewSymbolTable, but doesn't call BuildIndex.
	// We should probably call BuildIndex here or in NewEngine.
	// NewEngine doesn't take rootDir.
	// Let's call BuildIndex here on the target directory.
	// This is CRITICAL for the optimizations I added.

	err := e.Index.BuildIndex(dirPath)
	if err != nil {
		return nil, err
	}

	err = filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}

		// Skip non-code files (simplified)
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".java" && ext != ".xml" { // Support XML for MyBatis
			return nil
		}

		vulns, err := e.ScanFile(path, dirPath)
		if err != nil {
			return nil
		}
		allVulns = append(allVulns, vulns...)
		return nil
	})

	return allVulns, err
}

func toRelative(path string, rootDir string) string {
	// Clean paths to ensure consistency
	path = filepath.Clean(path)
	rootDir = filepath.Clean(rootDir)

	rel, err := filepath.Rel(rootDir, path)
	if err != nil {
		return path
	}
	return rel
}

// extractVariables finds potential variable names in a line
func extractVariables(line string) []string {
	// Strip single line comments
	if idx := strings.Index(line, "//"); idx != -1 {
		line = line[:idx]
	}

	// Strip string literals to avoid matching content inside quotes
	line = removeStringContent(line)

	keywords := map[string]bool{
		"new": true, "public": true, "private": true, "protected": true,
		"class": true, "return": true, "if": true, "else": true, "for": true, "while": true,
		"this": true, "super": true, "import": true, "package": true,
		"null": true, "true": true, "false": true, "int": true, "String": true, "void": true,
		"window": true, "parent": true,
		"type": true, "style": true, "width": true, "height": true,
	}

	re := regexp.MustCompile(`[a-zA-Z_][a-zA-Z0-9_]*`)
	matches := re.FindAllString(line, -1)

	var vars []string
	for _, m := range matches {
		if !keywords[m] { // Filter keywords
			vars = append(vars, m)
		}
	}
	return vars
}

func removeStringContent(line string) string {
	var sb strings.Builder
	inQuote := false
	escaped := false
	for _, r := range line {
		if escaped {
			if inQuote {
				sb.WriteRune(' ')
			} else {
				sb.WriteRune(r)
			}
			escaped = false
			continue
		}
		if r == '\\' {
			escaped = true
			if inQuote {
				sb.WriteRune(' ')
			} else {
				sb.WriteRune(r)
			}
			continue
		}
		if r == '"' {
			inQuote = !inQuote
			sb.WriteRune('"')
			continue
		}
		if inQuote {
			sb.WriteRune(' ')
		} else {
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

// findMyBatisSource attempts to locate the Java method that corresponds to the MyBatis XML SQL statement
func findMyBatisSource(xmlPath string, xmlLines []string, lineIdx int, rootDir string) (*Step, string, string) {
	// Look for <select/insert/update/delete id="...">
	for i := lineIdx; i >= 0; i-- {
		line := xmlLines[i]
		if strings.Contains(line, `id="`) {
			// Extract ID
			re := regexp.MustCompile(`id="([^"]+)"`)
			matches := re.FindStringSubmatch(line)
			if len(matches) > 1 {
				methodName := matches[1]

				// Find Mapper Interface
				// Assume Mapper.xml is in resources/mapper/ and Interface is in src/main/java/.../dao/ or mapper/
				// Simplified: Search for interface method with same name

				// 1. Try to guess Interface name from XML namespace if available
				var interfaceName string
				// Look for <mapper namespace="...">
				for j := 0; j < len(xmlLines); j++ {
					if strings.Contains(xmlLines[j], "<mapper") && strings.Contains(xmlLines[j], `namespace="`) {
						nsRe := regexp.MustCompile(`namespace="([^"]+)"`)
						nsMatches := nsRe.FindStringSubmatch(xmlLines[j])
						if len(nsMatches) > 1 {
							interfaceName = nsMatches[1]
							break
						}
					}
				}

				if interfaceName != "" && ProjectIndex != nil {
					// Lookup method in index
					// interfaceName is full package path e.g. com.example.dao.UserMapper
					// methodName is e.g. getUser

					// Split package and class
					parts := strings.Split(interfaceName, ".")
					className := parts[len(parts)-1]

					methodInfo := ProjectIndex.GetMethodInfo(className, methodName)
					if methodInfo != nil {
						return &Step{
							FilePath:    toRelative(methodInfo.FilePath, rootDir),
							LineNumber:  methodInfo.StartLine,
							LineContent: "public " + methodInfo.ReturnType + " " + methodInfo.Name + "(...)",
							Description: "Propagation: Mapper 接口定义",
						}, methodName, className
					}
				}

				// Fallback: grep
				// Restrict to .java files to avoid FPs (e.g. HTML files)
				cmd := exec.Command("grep", "-rInw", "--include=*.java", methodName, rootDir)
				out, err := cmd.Output()
				if err == nil {
					lines := strings.Split(string(out), "\n")
					for _, l := range lines {
						if l == "" {
							continue
						}
						// Use SplitN to handle colons in content
						parts := strings.SplitN(l, ":", 3)
						if len(parts) < 3 {
							continue
						}
						fPath := parts[0]
						lineNum, _ := strconv.Atoi(parts[1])
						content := parts[2]

						// 1. Ensure it's a Java file (double check)
						if !strings.HasSuffix(fPath, ".java") {
							continue
						}

						// 2. If interfaceName is known, verify file name
						if interfaceName != "" {
							parts := strings.Split(interfaceName, ".")
							className := parts[len(parts)-1]
							if !strings.HasSuffix(fPath, className+".java") {
								continue
							}
						}

						// 3. Check for interface definition or method signature
						// If we found the specific file (via interfaceName), we are more confident.
						// Otherwise, we require "interface " keyword to be safe, but this might miss method defs in multi-line interfaces.

						isMatch := false
						if interfaceName != "" && strings.HasSuffix(fPath, ".java") {
							// We found the correct file, so this method occurrence is likely the definition.
							isMatch = true
						} else {
							// Fallback: require "interface " keyword on the same line (legacy behavior but restricted to .java)
							// Or check if it looks like a method definition
							if strings.Contains(content, "interface ") {
								isMatch = true
							} else if (strings.Contains(content, "public ") || strings.Contains(content, "void ") || strings.Contains(content, "Result ") || strings.Contains(content, "List<")) &&
								!strings.Contains(content, "new ") && !strings.Contains(content, ".") && strings.Contains(content, "(") {
								isMatch = true
							}
						}

						if isMatch {
							// Infer className from fPath
							baseName := filepath.Base(fPath)
							className := strings.TrimSuffix(baseName, ".java")

							return &Step{
								FilePath:    toRelative(fPath, rootDir),
								LineNumber:  lineNum,
								LineContent: strings.TrimSpace(content),
								Description: "Propagation: Mapper 接口定义",
							}, methodName, className
						}
					}
				}
			}
		}
	}

	return nil, "", ""
}

func traceUsages(methodName string, rootDir string) []Step {
	// Grep for usages of methodName
	// This is a simple approximation
	cmd := exec.Command("grep", "-rInw", methodName, rootDir)
	out, err := cmd.Output()
	if err != nil {
		return nil
	}

	var steps []Step
	lines := strings.Split(string(out), "\n")
	for _, l := range lines {
		if l == "" {
			continue
		}
		parts := strings.Split(l, ":")
		if len(parts) >= 3 {
			filePath := parts[0]
			lineNum, _ := strconv.Atoi(parts[1])
			content := strings.Join(parts[2:], ":")

			// Skip comments in usage search
			trimmedContent := strings.TrimSpace(content)
			if strings.HasPrefix(trimmedContent, "//") || strings.HasPrefix(trimmedContent, "*") || strings.HasPrefix(trimmedContent, "/*") {
				continue
			}

			// Exclude definition itself
			if strings.Contains(content, "interface ") || strings.Contains(content, "public ") || strings.Contains(content, "private ") {
				continue
			}

			// Check if it's a method call
			if strings.Contains(content, methodName+"(") {
				steps = append(steps, Step{
					FilePath:    toRelative(filePath, rootDir),
					LineNumber:  lineNum,
					LineContent: strings.TrimSpace(content),
					Description: "Propagation: 方法调用",
				})
			}
		}
	}
	return steps
}

// traceBack tries graph-based analysis first, then falls back to legacy regex
func traceBack(path string, lines []string, startIndex int, targetVar string, sourcePatterns []string, sanitizerPatterns []string, depth int, rootDir string, visited map[string]bool) ([]Step, bool) {
	// Limit recursion depth
	if depth > 10 {
		return nil, false
	}

	// Avoid cycles
	stateKey := fmt.Sprintf("%s:%d:%s", path, startIndex, targetVar)
	if visited[stateKey] {
		return nil, false
	}
	// Copy visited map to avoid side effects across branches?
	// Actually, for cycle detection in a single path, we need to add to visited.
	// Go maps are references. If we modify it, it affects caller.
	// But we want to prevent *this specific path* from looping.
	// So we should add to visited before recursing, and maybe remove after?
	// Or just keep it for the whole traversal if we want to avoid re-visiting same state.
	// For infinite loop prevention, we just need to know if we are already visiting this state in the current stack.
	// So we should clone the map or remove the key after returning.
	// But simply passing a map that accumulates visited states is safer for general loop detection.
	// Let's create a new map if nil.
	if visited == nil {
		visited = make(map[string]bool)
	}
	visited[stateKey] = true
	defer delete(visited, stateKey)
	// defer delete(visited, stateKey) // Optional: if we want to allow visiting same state from different paths.

	// fmt.Printf("DEBUG: traceBack depth=%d file=%s target=%s\n", depth, path, targetVar)

	// Try Graph Analysis
	steps, found := graphTraceBack(path, lines, startIndex, targetVar, sourcePatterns, sanitizerPatterns, depth, rootDir, visited)
	if found {
		return steps, true
	}
	// Fallback to Legacy
	return legacyTraceBack(path, lines, startIndex, targetVar, sourcePatterns, sanitizerPatterns, depth, rootDir)
}

// graphTraceBack searches backwards using the Symbol Table (Graph-based)
func graphTraceBack(path string, lines []string, startIndex int, targetVar string, sourcePatterns []string, sanitizerPatterns []string, depth int, rootDir string, visited map[string]bool) ([]Step, bool) {
	if depth > 20 {
		return nil, false
	}

	// 1. Identify current Method context
	methodInfo := ProjectIndex.GetMethodByLine(path, startIndex+1)

	if methodInfo != nil {
		// fmt.Printf("DEBUG: Found method %s for file %s line %d\n", methodInfo.Name, path, startIndex+1)
	} else {
		// fmt.Printf("DEBUG: Method NOT FOUND for file %s line %d\n", path, startIndex+1)
	}

	// If not in a method, graph analysis is impossible
	if methodInfo == nil {
		return nil, false
	}

	var steps []Step
	var intermediateSteps []Step
	currentVar := targetVar

	// 2. Intra-procedural Analysis
	for i := startIndex - 1; i >= methodInfo.StartLine-1; i-- {
		line := lines[i]

		// Skip comments
		trimmedLine := strings.TrimSpace(line)
		if strings.HasPrefix(trimmedLine, "//") || strings.HasPrefix(trimmedLine, "*") || strings.HasPrefix(trimmedLine, "/*") {
			continue
		}

		if !strings.Contains(line, currentVar) {
			continue
		}

		if strings.Contains(line, "if") && strings.Contains(line, "(") {
			intermediateSteps = append(intermediateSteps, Step{
				FilePath:    toRelative(path, rootDir),
				LineNumber:  i + 1,
				LineContent: strings.TrimSpace(line),
				Description: "Propagation: 条件判断 - 变量用于 IF 条件",
			})
		}

		// Check for Collection modification methods: var.add(arg), var.append(arg), etc.
		if strings.Contains(line, currentVar+".") {
			// Patterns: .add(, .addAll(, .put(, .append(, .insert(
			methods := []string{"add", "addAll", "put", "append", "insert"}
			for _, m := range methods {
				if strings.Contains(line, currentVar+"."+m+"(") {
					// Extract arguments
					args := extractArguments(removeStringContent(line), m)
					for _, arg := range args {
						argVars := extractVariables(arg)
						for _, av := range argVars {
							// Trace back the argument
							argSteps, foundArg := traceBack(path, lines, i, av, sourcePatterns, sanitizerPatterns, depth+1, rootDir, visited)
							if foundArg {
								argSteps = append(argSteps, Step{
									FilePath:    toRelative(path, rootDir),
									LineNumber:  i + 1,
									LineContent: strings.TrimSpace(line),
									Description: "Propagation: 集合/对象修改 " + currentVar + "." + m + "(" + av + ")",
								})
								for m := len(intermediateSteps) - 1; m >= 0; m-- {
									argSteps = append(argSteps, intermediateSteps[m])
								}
								return argSteps, true
							}
						}
					}
				}
			}
		}

		parts := strings.Split(line, "=")
		if len(parts) < 2 {
			continue
		}
		lhs := parts[0]
		rhs := strings.Join(parts[1:], "=")

		if isVariableOnLHS(lhs, currentVar) {
			// Check Source
			cleanRHS := removeStringContent(rhs)
			for _, src := range sourcePatterns {
				if matchPattern(src, cleanRHS) { // Use regex match for Source patterns
					steps = append(steps, Step{
						FilePath:    toRelative(path, rootDir),
						LineNumber:  i + 1,
						LineContent: strings.TrimSpace(line),
						Description: "Source: " + src + " (赋值给 " + currentVar + ")",
					})
					for k := len(intermediateSteps) - 1; k >= 0; k-- {
						steps = append(steps, intermediateSteps[k])
					}
					return steps, true
				}
			}

			// Check Sanitizers
			for _, san := range sanitizerPatterns {
				if strings.Contains(rhs, san) {
					return nil, false
				}
			}

			// Check Method Call: var = obj.method(args)
			// Regex to match method calls, allowing chained calls (e.g. obj.method().method2())
			// We iterate over all matches to find the one that propagates taint
			callRe := regexp.MustCompile(`([^\s=]+)\.([\w]+)\(`)
			allMatches := callRe.FindAllStringSubmatch(rhs, -1)

			for _, matches := range allMatches {
				if len(matches) > 2 {
					objName := matches[1]
					methodName := matches[2]

					// Use ClassName from MethodInfo
					currentClassName := methodInfo.ClassName
					resolvedClass := ProjectIndex.ResolveType(objName, currentClassName)

					calleeInfo := ProjectIndex.GetMethodInfo(resolvedClass, methodName)
					if calleeInfo != nil {
						// Trace into Callee
						calleeContent, err := ioutil.ReadFile(calleeInfo.FilePath)
						if err == nil {
							calleeLines := strings.Split(string(calleeContent), "\n")

							// Find returns
							for k := calleeInfo.StartLine; k <= calleeInfo.EndLine && k < len(calleeLines); k++ {
								if strings.Contains(calleeLines[k], "return ") {
									retVars := extractVariables(strings.ReplaceAll(calleeLines[k], "return", ""))
									for _, rv := range retVars {
										calleeSteps, found := traceBack(calleeInfo.FilePath, calleeLines, k+1, rv, sourcePatterns, sanitizerPatterns, depth+1, rootDir, visited)
										if found {
											calleeSteps = append(calleeSteps, Step{
												FilePath:    toRelative(path, rootDir),
												LineNumber:  i + 1,
												LineContent: strings.TrimSpace(line),
												Description: "Propagation: 跨文件追踪 - " + currentVar + " 来自 " + resolvedClass + "." + methodName,
											})
											for m := len(intermediateSteps) - 1; m >= 0; m-- {
												calleeSteps = append(calleeSteps, intermediateSteps[m])
											}
											return calleeSteps, true
										}
									}
								}
							}
						}
					} else {
						// Opaque Method Call Handling (e.g., Library methods or unparsed code)
						// If we can't trace into the method, we assume the taint might come from:
						// 1. The object itself (objName)
						// 2. The arguments passed to the method

						// Trace Object
						objSteps, foundObj := traceBack(path, lines, i, objName, sourcePatterns, sanitizerPatterns, depth+1, rootDir, visited)
						if foundObj {
							objSteps = append(objSteps, Step{
								FilePath:    toRelative(path, rootDir),
								LineNumber:  i + 1,
								LineContent: strings.TrimSpace(line),
								Description: "Propagation: " + currentVar + " = " + objName + "." + methodName + "(...)",
							})
							for m := len(intermediateSteps) - 1; m >= 0; m-- {
								objSteps = append(objSteps, intermediateSteps[m])
							}
							return objSteps, true
						}

						// Trace Arguments
						args := extractArguments(removeStringContent(rhs), methodName)
						for _, arg := range args {
							argVars := extractVariables(arg)
							for _, av := range argVars {
								argSteps, foundArg := traceBack(path, lines, i, av, sourcePatterns, sanitizerPatterns, depth+1, rootDir, visited)
								if foundArg {
									argSteps = append(argSteps, Step{
										FilePath:    toRelative(path, rootDir),
										LineNumber:  i + 1,
										LineContent: strings.TrimSpace(line),
										Description: "Propagation: " + currentVar + " = " + objName + "." + methodName + "(..., " + av + ", ...)",
									})
									for m := len(intermediateSteps) - 1; m >= 0; m-- {
										argSteps = append(argSteps, intermediateSteps[m])
									}
									return argSteps, true
								}
							}
						}
					}
				}
			}

			// Recurse on RHS variable
			rhsVars := extractVariables(rhs)
			for _, v := range rhsVars {
				subSteps, found := traceBack(path, lines, i, v, sourcePatterns, sanitizerPatterns, depth+1, rootDir, visited)
				if found {
					subSteps = append(subSteps, Step{
						FilePath:    toRelative(path, rootDir),
						LineNumber:  i + 1,
						LineContent: strings.TrimSpace(line),
						Description: "Propagation: " + currentVar + " = " + v,
					})
					for m := len(intermediateSteps) - 1; m >= 0; m-- {
						subSteps = append(subSteps, intermediateSteps[m])
					}
					return subSteps, true
				}
			}
		}
	}

	// 3. Parameter Analysis (Inter-procedural)
	// Check if targetVar is a parameter
	for paramIdx, param := range methodInfo.Parameters {
		// param is "Type Name" or "Name"
		parts := strings.Fields(param)
		if len(parts) == 0 {
			continue
		}
		paramName := parts[len(parts)-1]

		// Check if targetVar is the parameter itself or a property/method of the parameter
		if paramName == targetVar || strings.HasPrefix(targetVar, paramName+".") {
			// Check if parameter itself is a Source (e.g. @RequestParam)
			for _, src := range sourcePatterns {
				if matchPattern(src, param) {
					// Found Source!
					steps = append(steps, Step{
						FilePath:    toRelative(path, rootDir),
						LineNumber:  methodInfo.StartLine,
						LineContent: "Parameter: " + param,
						Description: "Source: 污点源 " + src + " (方法参数 " + paramName + ")",
					})
					for k := len(intermediateSteps) - 1; k >= 0; k-- {
						steps = append(steps, intermediateSteps[k])
					}
					return steps, true
				}
			}

			// Trace Callers using Reverse Call Graph
			callers := ProjectIndex.CallerMap[methodInfo.Name]
			// if methodInfo.Name == "unsafe" {
			// 	fmt.Printf("DEBUG: Looking for callers of %s. Found %d callers.\n", methodInfo.Name, len(callers))
			// }
			// fmt.Printf("DEBUG: Looking for callers of %s. Found %d callers.\n", methodInfo.Name, len(callers))

			// Limit number of callers to trace to avoid explosion
			maxCallers := 5

			for i, callerID := range callers {
				if i >= maxCallers {
					break
				}

				// callerID is "FullClassName:MethodName"
				cParts := strings.Split(callerID, ":")
				if len(cParts) != 2 {
					continue
				}
				cClass, cMethod := cParts[0], cParts[1]

				callerInfo := ProjectIndex.GetMethodInfo(cClass, cMethod)
				if callerInfo == nil {
					continue
				}

				// Read Caller File
				callerContentBytes, err := ioutil.ReadFile(callerInfo.FilePath)
				if err != nil {
					continue
				}
				callerLines := strings.Split(string(callerContentBytes), "\n")

				// Scan Caller Body for calls to methodInfo.Name
				// We search within the caller's lines
				start := callerInfo.StartLine
				end := callerInfo.EndLine
				if start < 1 {
					start = 1
				}
				if end > len(callerLines) {
					end = len(callerLines)
				}

				for k := start; k <= end; k++ {
					line := callerLines[k-1]
					// Simple check if line contains method call
					// precise check would need tokenization, but this is SAST
					cleanLine := removeStringContent(line)
					if strings.Contains(cleanLine, methodInfo.Name+"(") || strings.Contains(cleanLine, "."+methodInfo.Name+"(") {
						// Context-Sensitive Check
						objName := findCallerObject(cleanLine, methodInfo.Name)
						// Check if we can resolve the object type
						var actualType string

						// Handle "new ClassName().method()"
						if objName == "new" {
							// fmt.Printf("DEBUG: Found new instantiation call for %s in %s\n", methodInfo.Name, cleanLine)
							reNew := regexp.MustCompile(`new\s+([\w]+)`)
							matches := reNew.FindStringSubmatch(cleanLine)
							if len(matches) > 1 {
								actualType = matches[1]
								// fmt.Printf("DEBUG: Extracted type: %s\n", actualType)
							}
						} else if objName != "" && objName != "this" {
							resolvedType := resolveContextVarType(callerLines, k, objName, cClass)
							if resolvedType != "" {
								actualType = ProjectIndex.ResolveType(resolvedType, cClass)
							}
						} else {
							// Implicit 'this' or local call
							actualType = cClass
						}

						// If we resolved a type, check compatibility
						if actualType != "" {
							if !isTypeCompatible(actualType, methodInfo.ClassName) {
								continue
							}
						}

						// Extract args
						args := extractArguments(cleanLine, methodInfo.Name)
						if len(args) > paramIdx {
							argVal := strings.TrimSpace(args[paramIdx])
							// Recurse trace in caller
							callerSteps, found := traceBack(callerInfo.FilePath, callerLines, k, argVal, sourcePatterns, sanitizerPatterns, depth+1, rootDir, visited)
							if found {
								// Add Propagation step for the Method Call in the caller
								callerSteps = append(callerSteps, Step{
									FilePath:    toRelative(callerInfo.FilePath, rootDir),
									LineNumber:  k,
									LineContent: strings.TrimSpace(line),
									Description: "Propagation: 传播 方法调用 " + methodInfo.Name,
								})

								// Add Propagation step for the Parameter Entry in the callee
								callerSteps = append(callerSteps, Step{
									FilePath:    toRelative(path, rootDir),
									LineNumber:  methodInfo.StartLine,
									LineContent: "public " + methodInfo.ReturnType + " " + methodInfo.Name + "(...)",
									Description: "Propagation: 传播 跨方法追踪 - 参数 " + paramName + " 传递自 " + cClass + "." + cMethod,
								})
								// Append intermediate steps if any (from current context) - but we don't have them here
								return callerSteps, true
							}
						}
					}
				}
			}

			// If no caller trace found, report as entry point
			// Fix: Check if parameter type is safe/output-related (e.g. HttpServletResponse)
			if isSafeParameterType(param) {
				return nil, false
			}

			// Only report as Source if it's a Controller/Entry point
			if isControllerOrEntryClass(methodInfo.ClassName, path) {
				return []Step{{
					FilePath:    toRelative(path, rootDir),
					LineNumber:  methodInfo.StartLine,
					LineContent: "public " + methodInfo.ReturnType + " " + methodInfo.Name + "(...)",
					Description: "Source: 参数入口 " + paramName,
				}}, true
			}

			return nil, false
		}
	}

	return nil, false
}

func isSafeParameterType(paramDecl string) bool {
	safeTypes := []string{
		"HttpServletResponse",
		"HttpServletRequest",
		"HttpSession",
		"Model",
		"ModelMap",
		"BindingResult",
		"Errors",
	}
	for _, t := range safeTypes {
		if strings.Contains(paramDecl, t) {
			return true
		}
	}
	return false
}

func isControllerOrEntryClass(className string, filePath string) bool {
	// Check standard naming conventions
	lowerName := strings.ToLower(className)
	if strings.HasSuffix(lowerName, "controller") ||
		strings.HasSuffix(lowerName, "action") ||
		strings.HasSuffix(lowerName, "servlet") ||
		strings.HasSuffix(lowerName, "endpoint") ||
		strings.HasSuffix(lowerName, "resource") { // JAX-RS
		return true
	}

	// Check package/path conventions
	lowerPath := strings.ToLower(filePath)
	if strings.Contains(lowerPath, "/controller/") ||
		strings.Contains(lowerPath, "/web/") ||
		strings.Contains(lowerPath, "/api/") ||
		strings.Contains(lowerPath, "/rest/") {
		return true
	}

	return false
}

func matchPattern(pattern, text string) bool {
	matched, _ := regexp.MatchString(pattern, text)
	return matched
}

// extractArguments extracts arguments from a method call string like "foo(a, b(c), d)"
func extractArguments(line string, methodName string) []string {
	// Find "methodName("
	idx := strings.Index(line, methodName+"(")
	if idx == -1 {
		return nil
	}

	startArgs := idx + len(methodName) + 1
	var args []string
	var currentArg strings.Builder
	parenCount := 0

	for i := startArgs; i < len(line); i++ {
		char := line[i]

		if char == '(' {
			parenCount++
			currentArg.WriteByte(char)
		} else if char == ')' {
			if parenCount > 0 {
				parenCount--
				currentArg.WriteByte(char)
			} else {
				// End of arguments
				args = append(args, currentArg.String())
				return args
			}
		} else if char == ',' {
			if parenCount == 0 {
				args = append(args, currentArg.String())
				currentArg.Reset()
			} else {
				currentArg.WriteByte(char)
			}
		} else {
			currentArg.WriteByte(char)
		}
	}
	return args
}

// findCallerObject extracts the object calling the method
// e.g. "client.execute(get)" -> "client"
// e.g. "stmt.execute(sql)" -> "stmt"
// e.g. "Request.Get(url).execute()" -> "Request"
func findCallerObject(line string, methodName string) string {
	// 1. Simple regex to find "object.methodName("
	// Matches: client.execute(
	re := regexp.MustCompile(`([\w]+)\.` + regexp.QuoteMeta(methodName) + `\(`)
	matches := re.FindStringSubmatch(line)
	if len(matches) > 1 {
		return matches[1]
	}

	// 2. Handle chained calls: "Request.Get(url).execute()"
	// Look for pattern: ...).methodName(
	chainRe := regexp.MustCompile(`\)\.` + regexp.QuoteMeta(methodName) + `\(`)
	if chainRe.MatchString(line) {
		// This is likely a chain.
		// Try to find the start of the chain.
		// This is complex to do perfectly with regex, but we can try to extract the first word in the statement.
		// Assuming the statement is like "Type var = ChainStart.method()...;" or "ChainStart.method()...;"

		// Extract the part before .execute(
		idx := strings.Index(line, "."+methodName+"(")
		if idx != -1 {
			preceeding := strings.TrimSpace(line[:idx])
			// If it contains "=", take the part after "="
			if eqIdx := strings.LastIndex(preceeding, "="); eqIdx != -1 {
				preceeding = strings.TrimSpace(preceeding[eqIdx+1:])
			}

			// Now preceeding is likely "Request.Get(String.valueOf(url))"
			// Extract the first identifier
			firstWordRe := regexp.MustCompile(`^([\w]+)`)
			firstMatches := firstWordRe.FindStringSubmatch(preceeding)
			if len(firstMatches) > 1 {
				return firstMatches[1] // Returns "Request"
			}
		}
	}

	return ""
}

// isValidUsage verifies if a found usage actually calls the target method on the target class
func isValidUsage(lineContent string, lines []string, lineNum int, methodName string, targetClassName string, rootDir string, absUsagePath string) bool {
	// 1. Find Caller Object
	objName := findCallerObject(lineContent, methodName)

	// 2. Identify the class where usage occurs
	var currentClass string
	if ProjectIndex != nil {
		classes := ProjectIndex.FileToClassesMap[absUsagePath]
		if len(classes) > 0 {
			currentClass = classes[0]
		}
	}
	// Fallback: Infer from file name
	if currentClass == "" {
		base := filepath.Base(absUsagePath)
		currentClass = strings.TrimSuffix(base, ".java")
	}

	// 3. Resolve the type of objName
	var actualType string

	// Handle "new ClassName().method()"
	if objName == "new" {
		reNew := regexp.MustCompile(`new\s+([\w]+)`)
		matches := reNew.FindStringSubmatch(lineContent)
		if len(matches) > 1 {
			actualType = matches[1]
		}
	} else if objName == "" || objName == "this" {
		// Implicit call to current class method
		actualType = currentClass
	} else {
		resolvedType := resolveContextVarType(lines, lineNum-1, objName, currentClass)
		if resolvedType != "" {
			if ProjectIndex != nil {
				actualType = ProjectIndex.ResolveType(resolvedType, currentClass)
			} else {
				actualType = resolvedType
			}
		}
	}

	// 4. Check Compatibility
	if actualType != "" {
		// If actualType is NOT targetClassName and NOT a subclass/implementation
		// Note: isTypeCompatible returns true if actualType is or implements targetClassName
		if !isTypeCompatible(actualType, targetClassName) {
			return false
		}
	} else {
		// If we couldn't resolve type, be conservative:
		// If objName is "questionDao" and target is "QuestionMapper", it's likely valid.
		// If objName is "" and currentClass is NOT target, it's likely INVALID (local call).
		if objName == "" && currentClass != targetClassName {
			// Local call in a different class -> definitely not the target method
			return false
		}
	}

	return true
}

// resolveVariableType attempts to find the type of a variable by scanning backwards
func resolveVariableType(lines []string, currentIndex int, varName string) string {
	// If varName starts with uppercase, it might be a class name (static call)
	// e.g. "Request" in "Request.Get(...)"
	if len(varName) > 0 && unicode.IsUpper(rune(varName[0])) {
		return varName
	}

	// Scan backwards from currentIndex
	// Look for:
	// 1. Type varName = ...
	// 2. Type varName;
	// 3. varName = new Type(...) -> Infer from RHS

	// Limit scan to 50 lines or method boundary
	limit := currentIndex - 50
	if limit < 0 {
		limit = 0
	}

	for i := currentIndex - 1; i >= limit; i-- {
		line := strings.TrimSpace(lines[i])
		// Skip comments
		if strings.HasPrefix(line, "//") || strings.HasPrefix(line, "*") || strings.HasPrefix(line, "/*") {
			continue
		}

		// Check for definition: Type varName ...
		// Regex: \b(\w+)\s+\bvarName\b
		// This is tricky because "Type" can be "List<String>" or "Map<K,V>"
		// Simplified regex for standard Java types: \b([A-Za-z0-9_<>]+)\s+varName\b

		// Case 1: Type varName = ...
		if strings.Contains(line, " "+varName+" =") || strings.Contains(line, " "+varName+";") || strings.HasPrefix(line, varName+" =") {
			// Try to extract type
			// Split by varName
			parts := strings.Split(line, varName)
			if len(parts) > 0 {
				prefix := strings.TrimSpace(parts[0])
				// The last word in prefix should be the type
				fields := strings.Fields(prefix)
				if len(fields) > 0 {
					possibleType := fields[len(fields)-1]
					// Validate if it looks like a type (not a keyword like "return", "new")
					if isType(possibleType) {
						return possibleType
					}
				}
			}
		}

		// Case 3: varName = new Type(...)
		// If we missed the declaration or it's a reassignment
		if strings.Contains(line, varName) && strings.Contains(line, "=") && strings.Contains(line, "new ") {
			// Check if varName is on LHS
			eqParts := strings.Split(line, "=")
			if len(eqParts) >= 2 {
				lhs := strings.TrimSpace(eqParts[0])
				rhs := strings.TrimSpace(eqParts[1])
				// lhs might be "Type varName" or just "varName"
				if strings.HasSuffix(lhs, varName) {
					// Extract Type from "new Type(...)"
					newIdx := strings.Index(rhs, "new ")
					if newIdx != -1 {
						rest := rhs[newIdx+4:]
						// Type is until "(" or "<" (if we want raw type)
						// Actually we want full type including generics if possible, but raw type is safer for matching
						endIdx := strings.IndexAny(rest, "(<")
						if endIdx != -1 {
							return strings.TrimSpace(rest[:endIdx])
						}
					}
				}
			}
		}
	}
	return ""
}

func isType(s string) bool {
	keywords := map[string]bool{
		"return": true, "public": true, "private": true, "protected": true,
		"static": true, "final": true, "volatile": true, "synchronized": true,
		"else": true, "try": true, "catch": true, "finally": true,
		"throw": true, "throws": true, "import": true, "package": true,
		"new": true,
	}
	return !keywords[s]
}

func isSafeExecuteType(typeName string) bool {
	// Types that have .execute() but are NOT SQL injection sinks
	safeTypes := []string{
		"HttpClient", "CloseableHttpClient", "DefaultHttpClient", "OkHttpClient",
		"Client", "RestClient", "WebClient",
		"Task", "Job", "Service", "Executor", "ExecutorService", "ThreadPoolExecutor",
		"Call",    // OkHttp Call
		"Request", // Apache Fluent Request
	}
	for _, safe := range safeTypes {
		if strings.Contains(typeName, safe) {
			return true
		}
	}
	return false
}

func legacyTraceBack(path string, lines []string, startIndex int, targetVar string, sourcePatterns []string, sanitizerPatterns []string, depth int, rootDir string) ([]Step, bool) {
	// Original regex-based logic with improved robustness
	var steps []Step
	// Default limit: look back 50 lines (sufficient for most local variables)
	// 500 was too aggressive and caused cross-method contamination when Index failed.
	limit := startIndex - 50
	if limit < 0 {
		limit = 0
	}

	// Fix: Restrict to current method boundary to prevent cross-method taint propagation
	if ProjectIndex != nil {
		methodInfo := ProjectIndex.GetMethodByLine(path, startIndex+1)
		if methodInfo != nil {
			methodStartIdx := methodInfo.StartLine - 1
			if methodStartIdx > limit {
				limit = methodStartIdx
			}
		}
	}

	for i := startIndex - 1; i >= limit; i-- {
		line := lines[i]

		// Skip comments
		trimmedLine := strings.TrimSpace(line)
		if strings.HasPrefix(trimmedLine, "//") || strings.HasPrefix(trimmedLine, "*") || strings.HasPrefix(trimmedLine, "/*") {
			continue
		}

		// Heuristic: Stop if we hit a method definition boundary
		// This prevents crossing into previous methods if ProjectIndex failed or limit is too loose
		if (strings.Contains(line, "public ") || strings.Contains(line, "private ") || strings.Contains(line, "protected ")) &&
			(strings.Contains(line, "(") || strings.Contains(line, " class ") || strings.Contains(line, " interface ")) {
			// This is likely a method signature or class definition.
			// We process this line (in case the targetVar is a parameter), but we MUST stop here.
			if i > limit {
				limit = i
			}
		}

		if !strings.Contains(removeStringContent(line), targetVar) {
			continue
		}

		// 1. Direct Source Check (for parameters or direct usage)
		cleanLine := removeStringContent(line)
		for _, src := range sourcePatterns {
			if matchPattern(src, cleanLine) {
				// Avoid false positives: ensure targetVar is actually in the line (already checked)
				// and maybe some other heuristics?
				steps = append(steps, Step{
					FilePath:    toRelative(path, rootDir),
					LineNumber:  i + 1,
					LineContent: strings.TrimSpace(line),
					Description: "Source: " + src,
				})
				return steps, true
			}
		}

		// 2. Assignment Propagation
		parts := strings.Split(line, "=")
		if len(parts) >= 2 {
			lhs := parts[0]
			rhs := strings.Join(parts[1:], "=")

			if isVariableOnLHS(lhs, targetVar) {
				// Check Sanitizers
				for _, san := range sanitizerPatterns {
					if strings.Contains(rhs, san) {
						return nil, false
					}
				}

				// Recurse
				rhsVars := extractVariables(rhs)
				for _, v := range rhsVars {
					subSteps, found := legacyTraceBack(path, lines, i, v, sourcePatterns, sanitizerPatterns, depth+1, rootDir)
					if found {
						subSteps = append(subSteps, Step{
							FilePath:    toRelative(path, rootDir),
							LineNumber:  i + 1,
							LineContent: strings.TrimSpace(line),
							Description: "Propagation: " + targetVar + " = " + v,
						})
						return subSteps, true
					}
				}
			}
		}
	}
	return nil, false
}

func isVariableOnLHS(lhs string, varName string) bool {
	// Check if varName is the last word in lhs
	fields := strings.Fields(lhs)
	if len(fields) == 0 {
		return false
	}
	return fields[len(fields)-1] == varName
}

func getSnippet(lines []string, index int) string {
	start := index - 2
	if start < 0 {
		start = 0
	}
	end := index + 3
	if end > len(lines) {
		end = len(lines)
	}
	return strings.Join(lines[start:end], "\n")
}

func resolveContextVarType(lines []string, lineIdx int, varName string, currentClassName string) string {
	// 1. Try local variable
	localType := resolveVariableType(lines, lineIdx, varName)
	if localType != "" {
		return localType
	}

	// 2. Try class field (including inherited)
	if ProjectIndex != nil && ProjectIndex.FieldMap != nil {
		cls := currentClassName
		visited := make(map[string]bool)

		for cls != "" {
			if visited[cls] {
				break
			}
			visited[cls] = true

			if fields, ok := ProjectIndex.FieldMap[cls]; ok {
				if fieldType, ok := fields[varName]; ok {
					return fieldType
				}
			}

			// Check parent class
			if ProjectIndex.ExtendsMap != nil {
				if parentRaw, ok := ProjectIndex.ExtendsMap[cls]; ok && parentRaw != "" {
					// Resolve parent full name using current class context
					resolvedParent := ProjectIndex.ResolveType(parentRaw, cls)
					// If resolution failed (returned same name) and it's simple name, it might be in same package
					// ResolveType handles same package.
					// If it returns simple name, it means it couldn't find it in ClassMap.
					// But ClassMap keys are simple names? No, keys are simple names, values are full names.
					// Wait, ResolveType:
					// if fullName, ok := st.ClassMap[simpleName]; ok { return fullName }
					// So if it returns something, it's likely a full name OR the simple name if not found.

					if resolvedParent == cls {
						break
					}
					cls = resolvedParent
					continue
				}
			}
			break
		}
	}
	return ""
}

func isTypeCompatible(actualType, expectedType string) bool {
	if actualType == expectedType {
		return true
	}
	// Check simple names
	actualSimple := simpleName(actualType)
	expectedSimple := simpleName(expectedType)
	if actualSimple == expectedSimple {
		return true
	}

	// Check if actual implements expected (if expected is interface)
	if ProjectIndex != nil && ProjectIndex.InterfaceMap != nil {
		if impls, ok := ProjectIndex.InterfaceMap[expectedType]; ok {
			for _, impl := range impls {
				if impl == actualType || simpleName(impl) == actualSimple {
					return true
				}
			}
		}
		// Also check by simple name
		if impls, ok := ProjectIndex.InterfaceMap[expectedSimple]; ok {
			for _, impl := range impls {
				if impl == actualType || simpleName(impl) == actualSimple {
					return true
				}
			}
		}

		// Check if expected implements actual (if actual is interface)
		// This handles the case where caller uses Interface (actual) but target is Implementation (expected)
		if impls, ok := ProjectIndex.InterfaceMap[actualType]; ok {
			for _, impl := range impls {
				if impl == expectedType || simpleName(impl) == expectedSimple {
					return true
				}
			}
		}
		if impls, ok := ProjectIndex.InterfaceMap[actualSimple]; ok {
			for _, impl := range impls {
				if impl == expectedType || simpleName(impl) == expectedSimple {
					return true
				}
			}
		}
	}

	return false
}

func simpleName(fullName string) string {
	parts := strings.Split(fullName, ".")
	return parts[len(parts)-1]
}

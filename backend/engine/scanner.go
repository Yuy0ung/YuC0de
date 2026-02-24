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
		}
	}
	return &Engine{Rules: rules, Index: ProjectIndex}, nil
}

// ScanFile scans a single file
func (e *Engine) ScanFile(path string, rootDir string) ([]Vulnerability, error) {
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
							javaStep, methodID := findMyBatisSource(path, lines, i, rootDir)
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
											// Extract arguments passed to methodID
											args := extractArguments(usage.LineContent, methodID)
											if len(args) > 0 {
												arg := strings.TrimSpace(args[0])
												// Use rule.Sources for traceBack
												sources := rule.Sources
												if len(sources) == 0 {
													sources = []string{"@RequestParam", "@PathVariable", "HttpServletRequest", "System.in", "Scanner"}
												}

												trace, found := traceBack(absUsagePath, usageLines, usage.LineNumber-1, arg, sources, rule.Sanitizers, 0, rootDir)
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
						if isExcluded(line) {
							continue
						}
						// Found Sink, now trace back variables
						vars := extractVariables(line)
						for _, varName := range vars {
							// Trace back this variable
							trace, found := traceBack(path, lines, i, varName, rule.Sources, rule.Sanitizers, 0, rootDir)
							if found {
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

// findMyBatisSource attempts to locate the Java method that corresponds to the MyBatis XML SQL statement
func findMyBatisSource(xmlPath string, xmlLines []string, lineIdx int, rootDir string) (*Step, string) {
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
						}, methodName
					}
				}

				// Fallback: grep
				cmd := exec.Command("grep", "-rInw", methodName, rootDir)
				out, err := cmd.Output()
				if err == nil {
					lines := strings.Split(string(out), "\n")
					for _, l := range lines {
						if strings.Contains(l, "interface ") && strings.Contains(l, methodName) {
							parts := strings.Split(l, ":")
							if len(parts) >= 2 {
								fPath := parts[0]
								lineNum, _ := strconv.Atoi(parts[1])
								return &Step{
									FilePath:    toRelative(fPath, rootDir),
									LineNumber:  lineNum,
									LineContent: strings.TrimSpace(strings.Join(parts[2:], ":")),
									Description: "Propagation: Mapper 接口定义",
								}, methodName
							}
						}
					}
				}
			}
		}
	}

	return nil, ""
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
func traceBack(path string, lines []string, startIndex int, targetVar string, sourcePatterns []string, sanitizerPatterns []string, depth int, rootDir string) ([]Step, bool) {
	// Try Graph Analysis
	steps, found := graphTraceBack(path, lines, startIndex, targetVar, sourcePatterns, sanitizerPatterns, depth, rootDir)
	if found {
		return steps, true
	}
	// Fallback to Legacy
	return legacyTraceBack(path, lines, startIndex, targetVar, sourcePatterns, sanitizerPatterns, depth, rootDir)
}

// graphTraceBack searches backwards using the Symbol Table (Graph-based)
func graphTraceBack(path string, lines []string, startIndex int, targetVar string, sourcePatterns []string, sanitizerPatterns []string, depth int, rootDir string) ([]Step, bool) {
	if depth > 20 {
		return nil, false
	}

	// 1. Identify current Method context
	methodInfo := ProjectIndex.GetMethodByLine(path, startIndex+1)

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

		if !strings.Contains(line, currentVar) {
			continue
		}

		if strings.Contains(line, "if") && strings.Contains(line, "(") {
			intermediateSteps = append(intermediateSteps, Step{
				FilePath:    toRelative(path, rootDir),
				LineNumber:  i + 1,
				LineContent: strings.TrimSpace(line),
				Description: "Control Flow: Variable used in IF condition",
			})
		}

		parts := strings.Split(line, "=")
		if len(parts) < 2 {
			continue
		}
		lhs := parts[0]
		rhs := strings.Join(parts[1:], "=")

		if isVariableOnLHS(lhs, currentVar) {
			// Check Source
			for _, src := range sourcePatterns {
				if strings.Contains(rhs, src) { // Simplified check
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
			callRe := regexp.MustCompile(`([\w]+)\.([\w]+)\(`)
			matches := callRe.FindStringSubmatch(rhs)
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
									calleeSteps, found := traceBack(calleeInfo.FilePath, calleeLines, k+1, rv, sourcePatterns, sanitizerPatterns, depth+1, rootDir)
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
					objSteps, foundObj := traceBack(path, lines, i, objName, sourcePatterns, sanitizerPatterns, depth+1, rootDir)
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
					args := extractArguments(rhs, methodName)
					for _, arg := range args {
						argVars := extractVariables(arg)
						for _, av := range argVars {
							argSteps, foundArg := traceBack(path, lines, i, av, sourcePatterns, sanitizerPatterns, depth+1, rootDir)
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

			// Recurse on RHS variable
			rhsVars := extractVariables(rhs)
			for _, v := range rhsVars {
				subSteps, found := traceBack(path, lines, i, v, sourcePatterns, sanitizerPatterns, depth+1, rootDir)
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

		if paramName == targetVar {
			// Trace Callers using Reverse Call Graph
			callers := ProjectIndex.CallerMap[methodInfo.Name]

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
					if strings.Contains(line, methodInfo.Name+"(") || strings.Contains(line, "."+methodInfo.Name+"(") {
						// Extract args
						args := extractArguments(line, methodInfo.Name)
						if len(args) > paramIdx {
							argVal := strings.TrimSpace(args[paramIdx])
							// Recurse trace in caller
							callerSteps, found := traceBack(callerInfo.FilePath, callerLines, k, argVal, sourcePatterns, sanitizerPatterns, depth+1, rootDir)
							if found {
								// Add Propagation step for the Method Call in the caller
								callerSteps = append(callerSteps, Step{
									FilePath:    toRelative(callerInfo.FilePath, rootDir),
									LineNumber:  k,
									LineContent: strings.TrimSpace(line),
									Description: "Propagation: 方法调用 " + methodInfo.Name,
								})

								// Add Propagation step for the Parameter Entry in the callee
								callerSteps = append(callerSteps, Step{
									FilePath:    toRelative(path, rootDir),
									LineNumber:  methodInfo.StartLine,
									LineContent: "public " + methodInfo.ReturnType + " " + methodInfo.Name + "(...)",
									Description: "Propagation: 跨方法追踪 - 参数 " + paramName + " 传递自 " + cClass + "." + cMethod,
								})
								// Append intermediate steps if any (from current context) - but we don't have them here
								return callerSteps, true
							}
						}
					}
				}
			}

			// If no caller trace found, report as entry point
			return []Step{{
				FilePath:    toRelative(path, rootDir),
				LineNumber:  methodInfo.StartLine,
				LineContent: "public " + methodInfo.ReturnType + " " + methodInfo.Name + "(...)",
				Description: "Source: 参数入口 " + paramName,
			}}, true
		}
	}

	return nil, false
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

		// Heuristic: Stop if we hit a method definition boundary
		// This prevents crossing into previous methods if ProjectIndex failed or limit is too loose
		if (strings.Contains(line, "public ") || strings.Contains(line, "private ") || strings.Contains(line, "protected ")) &&
			strings.Contains(line, "(") && strings.Contains(line, ")") {
			// This is likely a method signature.
			// We process this line (in case the targetVar is a parameter), but we MUST stop here.
			if i > limit {
				limit = i
			}
		}

		if !strings.Contains(line, targetVar) {
			continue
		}
		if !strings.Contains(line, targetVar) {
			continue
		}

		// 1. Direct Source Check (for parameters or direct usage)
		for _, src := range sourcePatterns {
			if strings.Contains(line, src) {
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

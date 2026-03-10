package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"yy-sast-backend/engine"
	"yy-sast-backend/pkg/langgraph"

	"github.com/sashabaranov/go-openai"
)

type AIAnalysisResult struct {
	IsFalsePositive bool   `json:"is_false_positive"`
	Reason          string `json:"reason"`
	Sanitization    string `json:"sanitization,omitempty"` // If sanitized, by what?
	Confidence      string `json:"confidence"`             // High, Medium, Low
}

// simple struct to parse LLM JSON response
type LLMResponse struct {
	Status       string `json:"status"` // "CONFIRMED", "FALSE_POSITIVE", "NEED_MORE_INFO"
	Reason       string `json:"reason"`
	MissingCode  string `json:"missing_code,omitempty"` // Function name or context needed
	Sanitization string `json:"sanitization,omitempty"`
}

// Graph State
type AuditState struct {
	Messages        []openai.ChatCompletionMessage
	Round           int
	MaxRounds       int
	Config          AIConfig
	Client          *openai.Client
	ScanPath        string
	Result          *AIAnalysisResult
	CurrentResponse *LLMResponse
}

func performAIAudit(taskID uint, scanPath string) {
	fmt.Printf("Starting AI Audit for Task %d...\n", taskID)

	// 1. Get AI Config
	var config AIConfig
	if err := db.First(&config).Error; err != nil {
		fmt.Printf("AI Config not found, skipping audit.\n")
		return
	}
	if config.APIKey == "" {
		fmt.Printf("AI API Key not set, skipping audit.\n")
		return
	}

	// 2. Init OpenAI Client
	clientConfig := openai.DefaultConfig(config.APIKey)
	clientConfig.BaseURL = config.BaseURL
	client := openai.NewClientWithConfig(clientConfig)

	// 3. Get Vulnerabilities
	var vulns []VulnerabilityRecord
	if err := db.Where("task_id = ?", taskID).Find(&vulns).Error; err != nil {
		fmt.Printf("Failed to fetch vulns for task %d: %v\n", taskID, err)
		return
	}

	fmt.Printf("Auditing %d vulnerabilities...\n", len(vulns))

	// 4. Build LangGraph
	graph := buildAuditGraph()
	runnable := graph.Compile()

	// 5. Audit each vulnerability
	for _, v := range vulns {
		// Prepare Initial Context
		initialMsgs := prepareInitialMessages(v)

		// Init State
		initialState := AuditState{
			Messages:  initialMsgs,
			Round:     0,
			MaxRounds: 3,
			Config:    config,
			Client:    client,
			ScanPath:  scanPath,
			Result: &AIAnalysisResult{
				Confidence: "Low",
			},
		}

		// Run Graph
		finalState, err := runnable.Invoke(context.Background(), initialState)
		if err != nil {
			fmt.Printf("Graph Execution Error for vuln %d: %v\n", v.ID, err)
			finalState.Result.Reason = "AI Audit Error: " + err.Error()
		}

		// Save Result
		resultBytes, _ := json.Marshal(finalState.Result)
		db.Model(&VulnerabilityRecord{}).Where("id = ?", v.ID).Update("ai_analysis", string(resultBytes))
	}

	fmt.Printf("AI Audit completed for Task %d\n", taskID)
}

func buildAuditGraph() *langgraph.StateGraph[AuditState] {
	g := langgraph.NewStateGraph[AuditState]()

	g.AddNode("audit", auditNode)
	g.AddNode("fetch_code", fetchCodeNode)

	g.SetEntryPoint("audit")

	g.AddConditionalEdges("audit", shouldContinue, map[string]string{
		"continue": "fetch_code",
		"end":      langgraph.END,
	})

	g.AddEdge("fetch_code", "audit")

	return g
}

func auditNode(ctx context.Context, state AuditState) (AuditState, error) {
	state.Round++
	fmt.Printf("  >> round %d analysis...\n", state.Round)

	var resp openai.ChatCompletionResponse
	var err error
	maxRetries := 3

	for i := 0; i <= maxRetries; i++ {
		if i > 0 {
			// Simple exponential backoff: 2s, 4s, 6s
			delay := time.Duration(i*2) * time.Second
			fmt.Printf("  >> AI API error, retrying in %v (attempt %d/%d)...\n", delay, i, maxRetries)
			time.Sleep(delay)
		}

		resp, err = state.Client.CreateChatCompletion(
			ctx,
			openai.ChatCompletionRequest{
				Model:    state.Config.Model,
				Messages: state.Messages,
				ResponseFormat: &openai.ChatCompletionResponseFormat{
					Type: openai.ChatCompletionResponseFormatTypeJSONObject,
				},
			},
		)

		if err == nil {
			break
		}

		fmt.Printf("  >> AI request failed: %v\n", err)

		// If context is cancelled, stop retrying
		if ctx.Err() != nil {
			return state, ctx.Err()
		}
	}

	if err != nil {
		return state, fmt.Errorf("AI request failed after %d retries: %v", maxRetries, err)
	}

	content := resp.Choices[0].Message.Content
	var llmResp LLMResponse
	if err := json.Unmarshal([]byte(content), &llmResp); err != nil {
		return state, fmt.Errorf("json parse error: %v", err)
	}

	// Update State
	state.CurrentResponse = &llmResp
	state.Messages = append(state.Messages, openai.ChatCompletionMessage{
		Role:    openai.ChatMessageRoleAssistant,
		Content: content,
	})

	// Update Result (Tentative)
	state.Result.IsFalsePositive = (llmResp.Status == "FALSE_POSITIVE")
	state.Result.Reason = llmResp.Reason
	state.Result.Sanitization = llmResp.Sanitization
	state.Result.Confidence = "High"

	return state, nil
}

func shouldContinue(ctx context.Context, state AuditState) string {
	if state.CurrentResponse != nil && state.CurrentResponse.Status == "NEED_MORE_INFO" && state.Round < state.MaxRounds {
		return "continue"
	}
	return "end"
}

func fetchCodeNode(ctx context.Context, state AuditState) (AuditState, error) {
	missingFunc := state.CurrentResponse.MissingCode
	fmt.Printf("  >> Fetching missing code: %s\n", missingFunc)

	foundCode := findMissingCode(missingFunc, state.ScanPath)
	var content string

	if foundCode == "" {
		content = fmt.Sprintf("Could not find definition for '%s'. Please make a decision based on available information.", missingFunc)
	} else {
		content = fmt.Sprintf("Here is the code for '%s':\n%s\n\nPlease re-evaluate.", missingFunc, foundCode)
	}

	state.Messages = append(state.Messages, openai.ChatCompletionMessage{
		Role:    openai.ChatMessageRoleUser,
		Content: content,
	})

	return state, nil
}

func prepareInitialMessages(v VulnerabilityRecord) []openai.ChatCompletionMessage {
	// Parse steps
	var steps []engine.Step
	if v.StepsJSON != "" {
		json.Unmarshal([]byte(v.StepsJSON), &steps)
	}

	contextStr := fmt.Sprintf("Vulnerability: %s\nSeverity: %s\nFile: %s:%d\nCode:\n%s\n\nTrace:\n",
		v.RuleName, v.Severity, v.FilePath, v.LineNumber, v.Snippet)

	for i, s := range steps {
		contextStr += fmt.Sprintf("%d. %s:%d %s\n   Code: %s\n", i+1, s.FilePath, s.LineNumber, s.Description, s.LineContent)
	}

	skillInstructions := getVulnerabilitySkill(v.RuleName)

	systemPrompt := "You are a senior security code auditor. Your job is to review SAST vulnerability reports. \n" +
		"You must analyze the code flow and determine if it is a True Positive or False Positive. \n" +
		"\n" +
		"Audit Criteria:\n" +
		"1. Only determine if THIS specific report is false positive.\n" +
		"2. If there is a sanitization function that effectively neutralizes the threat, it is False Positive.\n" +
		"3. If the code does not exist or logic doesn't match the vulnerability, it is False Positive.\n" +
		"4. If you need more code context (e.g. definition of a function called in the trace), ask for it using status 'NEED_MORE_INFO' and specify the function name in 'missing_code'.\n" +
		"\n" +
		"Vulnerability Specific Skills:\n" +
		skillInstructions + "\n" +
		"\n" +
		"IMPORTANT: The 'reason' and 'sanitization' fields in your JSON output MUST BE IN CHINESE (Simplified Chinese).\n" +
		"\n" +
		"Output JSON format:\n" +
		"{\n" +
		"  \"status\": \"CONFIRMED\" | \"FALSE_POSITIVE\" | \"NEED_MORE_INFO\",\n" +
		"  \"reason\": \"详细的判定理由（中文）...\",\n" +
		"  \"missing_code\": \"function_name_to_find\" (only if NEED_MORE_INFO),\n" +
		"  \"sanitization\": \"Sanitizer function name\" (if FALSE_POSITIVE due to sanitization)\n" +
		"}"

	return []openai.ChatCompletionMessage{
		{
			Role:    openai.ChatMessageRoleSystem,
			Content: systemPrompt,
		},
		{
			Role:    openai.ChatMessageRoleUser,
			Content: "Please review this vulnerability:\n\n" + contextStr,
		},
	}
}

func getVulnerabilitySkill(ruleName string) string {
	ruleNameLower := strings.ToLower(ruleName)

	if strings.Contains(ruleNameLower, "xss") || strings.Contains(ruleNameLower, "cross-site scripting") {
		return `### XSS (Cross-Site Scripting) Audit Skills
**Core Principle**: User input must be encoded/sanitized before being rendered in the browser.
**Audit Steps**:
1. **Identify the Sink Context**:
   - **JavaScript** (e.g., <script>var a = "$input"</script> or fn($input)): **EXTREMELY DANGEROUS**.
   - **HTML Body** (e.g., <div>$input</div>): Requires HTML Entity Encoding.
   - **HTML Attribute** (e.g., <div class="$input">): Requires Attribute Encoding.
2. **CRITICAL - JavaScript Context & Function Calls**:
   - **Scenario**: out.print("<script>fn(" + input + ")</script>")
   - **Attack**: Input "1);alert(1);//" results in "fn(1);alert(1);//)". This IS VALID JS and IS A VULNERABILITY.
   - **FALSE NEGATIVE WARNING**: Do NOT assume 'input' is safe just because it is named 'id', 'num', 'callback', 'CKEditorFuncNum', or 'timestamp'.
   - **FALSE NEGATIVE WARNING**: Do NOT assume the frontend or library (like CKEditor) validates the input. Attackers bypass frontends.
   - **Validation Requirement**: Unless you see Integer.parseInt(input) or input.matches("^[0-9]+$") IN THE BACKEND CODE, it is VULNERABLE.
3. **Check for Sanitization/Encoding**:
   - **Safe**: OWASP Java Encoder, Apache Commons Text StringEscapeUtils.
   - **Unsafe**: Raw output (response.getWriter().print(input)).
4. **Common False Positives (Strict Conditions)**:
   - Input is explicitly cast to Integer/Long/Boolean in the BACKEND code.
   - Input is a UUID or strictly validated regex (e.g., ^[a-zA-Z0-9]+$).
   - Input is Base64 encoded.
5. **Vulnerable Patterns (True Positives)**:
   - Reflection of input in error messages without encoding.
   - Stored XSS: Input saved to DB and later output without encoding.
   - DOM XSS: Source (location.hash) -> Sink (innerHTML, document.write).`
	}

	if strings.Contains(ruleNameLower, "sql") || strings.Contains(ruleNameLower, "injection") {
		return `### SQL Injection Audit Skills
**Core Principle**: User input must NOT be concatenated directly into SQL queries.
**Audit Steps**:
1. **Identify the SQL Construction Method**:
   - **Concatenation**: "SELECT * FROM users WHERE name = '" + input + "'" -> **VULNERABLE**.
   - **String.format**: String.format("SELECT * FROM users WHERE name = '%s'", input) -> **VULNERABLE**.
   - **PreparedStatement**: conn.prepareStatement("SELECT * FROM users WHERE name = ?") -> **SAFE**.
   - **JPA/Hibernate**: query.setParameter("name", input) -> **SAFE**.
   - **MyBatis**: #{input} -> **SAFE** (PreparedStatement). ${input} -> **VULNERABLE** (Direct Substitution).
2. **Analyze MyBatis ${} Cases**:
   - **CRITICAL**: ${} is ALWAYS a direct string substitution.
   - **Exception**: If the input is strictly validated (e.g., "ORDER BY " + sortColumn where sortColumn is from a whitelist ["id", "name"]), it is **SAFE**.
   - **Exception**: If the input is cast to Integer/Long/Boolean/UUID before query construction, it is **SAFE**.
   - **Otherwise**: Treat ${} as **VULNERABLE**.
3. **Analyze Collection/List Parameters**:
   - **Scenario**: WHERE id IN ('" + Joiner.on("','").join(list) + "')
   - **ACTION**: Look at the Controller/Service method signature in the provided code.
   - **SAFE**: If the parameter is defined as List<Long>, List<Integer>, long[], int[]. Spring/Jackson will throw an exception if a string like "1' OR '1'='1" is sent. THIS IS A FALSE POSITIVE.
   - **VULNERABLE**: Only if the parameter is List<String>, String[], or raw List (without generics).
   - **FALSE POSITIVE WARNING**: Do NOT assume it is List<Object> if the code explicitly says List<Long>. Trust the code snippet.
4. **Common False Positives**:
   - Input is strictly typed (Integer, Long, Boolean) in the Controller/Source definition.
   - Input is an Enum.
   - Input is a hardcoded constant or system property not controlled by user.
5. **Edge Cases**:
   - **ORDER BY / GROUP BY**: Cannot use PreparedStatement (?). Must use whitelisting (Allowlist) or strict validation.
   - **LIKE Clause**: Ensure wildcards (% and _) are escaped if using PreparedStatement isn't possible (though usually it is).`
	}

	if strings.Contains(ruleNameLower, "rce") || strings.Contains(ruleNameLower, "command execution") {
		return `### RCE (Remote Code Execution) Audit Skills
**Core Principle**: User input must NOT control the command or its arguments executed by the system.
**Audit Steps**:
1. **Identify the Sink**:
   - Runtime.exec(cmd), ProcessBuilder(cmd), UNISEX (C/C++), eval(), system(), shell_exec().
2. **Check for Injection**:
   - **Vulnerable**: Runtime.exec("ping " + input). Input can be "8.8.8.8; rm -rf /".
   - **Vulnerable**: ProcessBuilder("sh", "-c", "ls " + input).
3. **Check for Mitigation**:
   - **Safe**: Hardcoded commands with no user input.
   - **Safe**: Strictly whitelisted commands/arguments (e.g., if (!allowList.contains(input)) throw ...).
   - **Safe**: Input is strictly typed (e.g., Integer ID passed to a script).
4. **False Positives**:
   - The "command" is a fixed string, only arguments are user input AND the command does not interpret shell metacharacters (e.g., ls -l input_file is relatively safe if not run in a shell, but be careful with filenames starting with -).
   - **Best Practice**: Use ProcessBuilder with a list of arguments, NOT a single string command line. Avoid "sh -c" or "cmd /c" unless absolutely necessary.`
	}

	if strings.Contains(ruleNameLower, "ssrf") || strings.Contains(ruleNameLower, "request forgery") {
		return `### SSRF (Server-Side Request Forgery) Audit Skills
**Core Principle**: User input must NOT control the target URL of a server-side request.
**Audit Steps**:
1. **Identify the Sink**:
   - HttpClient.execute(url), URL.openStream(), RestTemplate.getForObject(url), OkHttp.newCall(url).
2. **Check for Validation**:
   - **Insufficient**: Checking if url.startsWith("http"). Attacker can use "http://localhost", "http://127.0.0.1", "http://internal-service".
   - **Insufficient**: Blacklisting (e.g., !url.contains("localhost")). Attacker can use DNS pinning, decimal IPs (2130706433), or enclosed alphanumerics.
   - **Safe**: Whitelisting (Allowlist) of allowed domains/IPs.
   - **Safe**: Hardcoded URL prefix with user input only in path/query (e.g., "https://api.example.com/user/" + input). Note: Check for Path Traversal (../) if input is in path.
3. **Common False Positives**:
   - URL is hardcoded or configured from a trusted config file.
   - Input controls the body, not the URL.
4. **Advanced Checks**:
   - Does the code disable redirects? (Redirects can bypass validation).
   - Does the code resolve DNS and check the IP against internal ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8)?`
	}

	if strings.Contains(ruleNameLower, "path traversal") || strings.Contains(ruleNameLower, "directory traversal") {
		return `### Path Traversal Audit Skills
**Core Principle**: User input must NOT control the file path to access unauthorized files.
**Audit Steps**:
1. **Identify the Sink**:
   - new File(path), new FileInputStream(path), Paths.get(path), ClassLoader.getResource(path).
2. **Check for Input Sanitization**:
   - **Vulnerable**: new File("/var/www/uploads/" + filename). Attacker sends "../../etc/passwd".
   - **Safe**: filename = filename.replaceAll("[^a-zA-Z0-9.-]", ""); (Whitelisting characters).
   - **Safe**: Using an ID map (input is ID 123, code looks up filename in DB).
3. **Canonicalization Check**:
   - **Best Practice**: File file = new File(dir, input); if (!file.getCanonicalPath().startsWith(dir.getCanonicalPath())) throw SecurityException;
   - **Unsafe**: Checking input.contains("..") is often insufficient (URL encoding %2e%2e, Unicode variations).
4. **False Positives**:
   - Input is not a filename but content.
   - File operation is writing to a temporary file with a generated name (File.createTempFile).`
	}

	if strings.Contains(ruleNameLower, "xxe") || strings.Contains(ruleNameLower, "xml external entity") {
		return `### XXE (XML External Entity) Audit Skills
**Core Principle**: XML parsers must disable DTDs OR External Entities.
**Audit Steps**:
1. **Identify the Sink**:
   - DocumentBuilderFactory, SAXParserFactory, XMLInputFactory, TransformerFactory, SchemaFactory.
2. **Check for Safe Configuration (ANY ONE of these is sufficient)**:
   - **STRONGEST DEFENSE**: factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true); -> **SAFE** (This disables DTDs entirely, preventing XXE).
   - **ALTERNATIVE**: factory.setFeature("http://xml.org/sax/features/external-general-entities", false) AND factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false); -> **SAFE**.
   - **For XMLInputFactory**: factory.setProperty(XMLInputFactory.SUPPORT_DTD, false); -> **SAFE**.
3. **False Positives**:
   - **CRITICAL**: If you see 'disallow-doctype-decl' set to true in the code, it is a **FALSE POSITIVE**.
   - Parser is used to parse trusted XML (e.g., internal config).
   - The XML parser version is secure by default (e.g., newer JDKs).`
	}

	if strings.Contains(ruleNameLower, "deserialization") || strings.Contains(ruleNameLower, "fastjson") || strings.Contains(ruleNameLower, "jackson") {
		return `### Insecure Deserialization Audit Skills (Focus on Fastjson/Jackson)
**Core Principle**: Deserialization of untrusted data is dangerous. Simply specifying a target class (e.g., JSON.parseObject(json, Target.class)) is NOT enough to prevent RCE.
**Audit Steps**:
1. **Identify the Sink**:
   - **Fastjson**: JSON.parse(), JSON.parseObject(), JSON.parseArray().
   - **Jackson**: ObjectMapper.readValue(), ObjectMapper.enableDefaultTyping().
   - **Java Native**: ObjectInputStream.readObject().
2. **CRITICAL - Fastjson Specifics**:
   - **Scenario**: JSON.parseObject(json, User.class)
   - **VULNERABILITY**: Specifying User.class does NOT disable 'AutoType'. Fastjson may still instantiate arbitrary classes specified by "@type" in the JSON string (e.g., via Throwable/AutoCloseable bypasses like CVE-2022-25845).
   - **Attack**: Payload {"@type":"com.sun.rowset.JdbcRowSetImpl", ...} triggers RCE BEFORE casting to User.class.
   - **Safe Mode**: Unless you see ParserConfig.getGlobalInstance().setSafeMode(true) in the code, assume SafeMode is OFF.
   - **Conclusion**: If the input 'json' is untrusted and SafeMode is not explicitly enabled, it is **VULNERABLE**.
3. **CRITICAL - Jackson Specifics**:
   - **VULNERABILITY**: If objectMapper.enableDefaultTyping() or objectMapper.activateDefaultTyping() is called, it is VULNERABLE to RCE via gadgets.
   - **Safe**: Standard ObjectMapper.readValue(json, User.class) WITHOUT default typing enabled is generally safe.
4. **False Positives**:
   - Input is hardcoded or from a strictly trusted source (e.g., internal config file, NOT database, NOT user request).
   - Fastjson version is updated to a version with SafeMode enabled by default (very rare, usually requires manual config).
5. **Mitigation Check**:
   - Fastjson: ParserConfig.getGlobalInstance().addAccept("com.mycompany.") (Whitelist).
   - Jackson: No enableDefaultTyping, or using BasicPolymorphicTypeValidator.`
	}

	if strings.Contains(ruleNameLower, "hardcoded") || strings.Contains(ruleNameLower, "password") || strings.Contains(ruleNameLower, "credential") || strings.Contains(ruleNameLower, "secret") {
		return `### Hardcoded Credentials Audit Skills
**Core Principle**: Hardcoding sensitive information (passwords, API keys, tokens) is a security vulnerability, regardless of the environment (Dev/Test/Prod).
**Audit Steps**:
1. **Identify the Sensitive Info**:
   - Look for keys like "password", "secret", "key", "token", "pwd".
   - Look for values that resemble actual credentials (not just "${PLACEHOLDER}").
2. **Strict Assessment**:
   - **VULNERABLE**: If a real value is present (e.g., "123456", "admin", "mySuperSecret").
   - **VULNERABLE**: Even if the file is a "dev" config (e.g., generatorConfig.xml, application-dev.yml), hardcoded credentials are a bad practice and risk leakage.
   - **VULNERABLE**: Even if the password looks weak or common (e.g., "123456"), it is still a finding because it encourages insecurity.
3. **False Positives**:
   - The value is a property placeholder (e.g., "${jdbc.password}", "#{env['DB_PASS']}").
   - The value is explicitly empty (e.g., password="").
   - The file is a documentation example or template (e.g., .example, .template) AND the value is clearly dummy (e.g., "your_password_here").
4. **Common Excuses to REJECT**:
   - "It's just a local dev file" -> REJECT. Source code leaks happen.
   - "It's a code generator config" -> REJECT. Developers often commit these.
   - "The password is weak anyway" -> REJECT. Weak passwords are also a vulnerability.`
	}

	return `### General Security Audit Skills
**Core Principle**: Trace user input (Source) to sensitive operation (Sink) and verify if effective validation/sanitization exists.
**Audit Steps**:
1. **Trace the Data Flow**: Does the data come from an untrusted source (HTTP request, external DB, file)?
2. **Check the Sink**: Is the data used in a dangerous way (SQL, HTML output, Command execution)?
3. **Verify Sanitization**:
   - Is there a validation step (e.g., regex, whitelist)?
   - Is there a sanitization step (e.g., encoding, escaping)?
   - Is the sanitization context-aware (e.g., HTML escaping for HTML context)?
4. **Determine False Positive**:
   - If input is cast to a safe type (int, boolean).
   - If input is hardcoded or system-controlled.
   - If the code path is dead or unreachable.`
}

// Simple helper to find function definition in the project
func findMissingCode(funcName string, rootPath string) string {
	if funcName == "" {
		return ""
	}

	targetMethod := funcName
	targetClass := ""

	// Handle Class.Method (e.g., ConfigurationModulesLoader.loadIntegrationConfigurations)
	if strings.Contains(funcName, ".") {
		parts := strings.Split(funcName, ".")
		targetMethod = parts[len(parts)-1]
		if len(parts) >= 2 {
			targetClass = parts[len(parts)-2]
		}
	}

	var foundContent string

	filepath.Walk(rootPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			if info.Name() == ".git" || info.Name() == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}

		// Only check source files
		ext := filepath.Ext(path)
		if ext != ".go" && ext != ".java" && ext != ".js" && ext != ".ts" && ext != ".py" {
			return nil
		}

		// If we identified a target class, verify the filename matches
		if targetClass != "" {
			filename := filepath.Base(path)
			filenameWithoutExt := strings.TrimSuffix(filename, ext)
			if !strings.EqualFold(filenameWithoutExt, targetClass) {
				return nil
			}
		}

		content, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		lines := strings.Split(string(content), "\n")
		var candidateMatch string

		for i, line := range lines {
			// Search for "MethodName" and "("
			if strings.Contains(line, targetMethod) && strings.Contains(line, "(") {
				// Prepare content
				start := i
				end := i + 50
				if end > len(lines) {
					end = len(lines)
				}
				currentContent := fmt.Sprintf("File: %s\nLines %d-%d:\n%s", path, start+1, end, strings.Join(lines[start:end], "\n"))

				// Check for definition indicators
				trimmed := strings.TrimSpace(line)
				isDef := strings.HasPrefix(trimmed, "public ") ||
					strings.HasPrefix(trimmed, "private ") ||
					strings.HasPrefix(trimmed, "protected ") ||
					strings.HasPrefix(trimmed, "func ") ||
					strings.HasPrefix(trimmed, "def ") ||
					strings.HasPrefix(trimmed, "static ")

				if isDef {
					foundContent = currentContent
					return filepath.SkipAll // Found definition!
				}

				if candidateMatch == "" {
					candidateMatch = currentContent
				}
			}
		}

		// If we are here, we didn't find a definition in this file.
		// If we found a candidate (call) and we are targeting this specific class, return it.
		if targetClass != "" && candidateMatch != "" {
			foundContent = candidateMatch
			return filepath.SkipAll
		}

		// If no target class, store the candidate as fallback
		if candidateMatch != "" && foundContent == "" {
			foundContent = candidateMatch
		}

		return nil
	})

	return foundContent
}

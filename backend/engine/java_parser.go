package engine

import (
	"io/ioutil"
	"strings"
)

// JavaFile represents a parsed Java source file
type JavaFile struct {
	Path    string
	Package string
	Imports []string
	Classes []*ClassNode
}

// ClassNode represents a class or interface
type ClassNode struct {
	Name       string
	Type       string // "class" or "interface"
	StartLine  int
	EndLine    int
	Methods    []*MethodNode
	Fields     []*FieldNode
	Implements []string
	Extends    string
}

// MethodNode represents a method definition
type MethodNode struct {
	Name       string
	StartLine  int
	EndLine    int
	ReturnType string
	Parameters []string // Type Name
	Body       string   // Raw body content for further analysis
	Calls      []string // List of method names called within this method
}

// FieldNode represents a class field
type FieldNode struct {
	Name string
	Type string
}

// ParseJavaFile parses a Java file into a structured representation
// This is a hand-written recursive descent parser simplified for structure extraction
func ParseJavaFile(path string) (*JavaFile, error) {
	contentBytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseJavaSource(string(contentBytes), path)
}

// ParseJavaSource parses Java source code string
func ParseJavaSource(content string, path string) (*JavaFile, error) {
	file := &JavaFile{
		Path: path,
	}

	// 1. Tokenize (Lexical Analysis)
	tokens := tokenize(content)

	// 2. Parse Structure (Syntactic Analysis)
	parser := &Parser{
		tokens: tokens,
		pos:    0,
		file:   file,
	}
	parser.parse()

	return file, nil
}

// --- Lexer ---

type TokenType int

const (
	TOKEN_EOF TokenType = iota
	TOKEN_IDENTIFIER
	TOKEN_KEYWORD
	TOKEN_SYMBOL
	TOKEN_STRING
	TOKEN_COMMENT
)

type Token struct {
	Type  TokenType
	Value string
	Line  int
}

func tokenize(input string) []Token {
	var tokens []Token
	lines := strings.Split(input, "\n")

	inBlockComment := false

	for i, line := range lines {
		lineNum := i + 1
		runes := []rune(line)
		length := len(runes)

		for j := 0; j < length; j++ {
			char := runes[j]

			// Skip whitespace
			if isWhitespace(char) {
				continue
			}

			// Handle Comments
			if inBlockComment {
				if j+1 < length && char == '*' && runes[j+1] == '/' {
					inBlockComment = false
					j++
				}
				continue
			}
			if j+1 < length && char == '/' {
				if runes[j+1] == '/' {
					break // Line comment, skip rest of line
				}
				if runes[j+1] == '*' {
					inBlockComment = true
					j++
					continue
				}
			}

			// Handle Strings
			if char == '"' || char == '\'' {
				quote := char
				start := j
				j++
				for j < length {
					if runes[j] == quote && runes[j-1] != '\\' {
						break
					}
					j++
				}
				end := j + 1
				if j >= length {
					end = length
				}
				tokens = append(tokens, Token{Type: TOKEN_STRING, Value: string(runes[start:end]), Line: lineNum})
				continue
			}

			// Handle Symbols
			if isSymbol(char) {
				tokens = append(tokens, Token{Type: TOKEN_SYMBOL, Value: string(char), Line: lineNum})
				continue
			}

			// Handle Identifiers and Keywords
			if isAlpha(char) {
				start := j
				for j < length && (isAlphaNum(runes[j]) || runes[j] == '.') { // Allow dots for qualified names in some contexts
					j++
				}
				j-- // Backtrack one
				val := string(runes[start : j+1])
				tokens = append(tokens, Token{Type: TOKEN_IDENTIFIER, Value: val, Line: lineNum}) // We treat keywords as identifiers for now and check later
				continue
			}
		}
	}
	return tokens
}

func isWhitespace(r rune) bool {
	return r == ' ' || r == '\t' || r == '\r' || r == '\n'
}

func isSymbol(r rune) bool {
	return strings.ContainsRune("{}();,=<>[].@", r)
}

func isAlpha(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || r == '_'
}

func isAlphaNum(r rune) bool {
	return isAlpha(r) || (r >= '0' && r <= '9')
}

// --- Parser ---

type Parser struct {
	tokens []Token
	pos    int
	file   *JavaFile
}

func (p *Parser) parse() {
	for p.pos < len(p.tokens) {
		token := p.peek()

		if token.Value == "package" {
			p.parsePackage()
		} else if token.Value == "import" {
			p.parseImport()
		} else if token.Value == "public" || token.Value == "class" || token.Value == "interface" || token.Value == "@" {
			// Start of class definition (potentially with annotations)
			p.parseClass()
		} else {
			p.next()
		}
	}
}

func (p *Parser) parsePackage() {
	p.consume("package")
	pkgName := ""
	for p.pos < len(p.tokens) {
		t := p.next()
		if t.Value == ";" {
			break
		}
		pkgName += t.Value
	}
	p.file.Package = pkgName
}

func (p *Parser) parseImport() {
	p.consume("import")
	importName := ""
	for p.pos < len(p.tokens) {
		t := p.next()
		if t.Value == ";" {
			break
		}
		if t.Value == "static" {
			continue // Skip static keyword in import
		}
		importName += t.Value
	}
	p.file.Imports = append(p.file.Imports, importName)
}

func (p *Parser) parseClass() {
	// Skip annotations
	for p.peek().Value == "@" {
		// Skip annotation until next line or identifier?
		// Simple skip: @Annotation or @Annotation(args)
		p.next() // @
		p.next() // Name
		if p.peek().Value == "(" {
			p.next()
			p.skipBalanced("(", ")")
		}
	}

	// Skip modifiers
	modifiers := []string{"public", "private", "protected", "abstract", "static", "final"}
	for contains(modifiers, p.peek().Value) {
		p.next()
	}

	typeStr := p.peek().Value
	if typeStr != "class" && typeStr != "interface" {
		// Maybe enum or just skip
		p.next()
		return
	}
	p.next() // consume class/interface

	className := p.next().Value
	classNode := &ClassNode{
		Name:      className,
		Type:      typeStr,
		StartLine: p.tokens[p.pos-1].Line,
	}

	// Handle extends/implements
	for p.peek().Value != "{" && p.pos < len(p.tokens) {
		t := p.next()
		if t.Value == "extends" {
			classNode.Extends = p.next().Value
		} else if t.Value == "implements" {
			for p.peek().Value != "{" {
				impl := p.next()
				if impl.Value != "," {
					classNode.Implements = append(classNode.Implements, impl.Value)
				}
			}
		}
	}

	p.consume("{")

	// Parse Class Body
	p.parseClassBody(classNode)

	p.file.Classes = append(p.file.Classes, classNode)
}

func (p *Parser) parseClassBody(classNode *ClassNode) {
	braceCount := 1
	_ = p.pos // Was startPos

	for p.pos < len(p.tokens) {
		t := p.peek()

		if t.Value == "}" {
			braceCount--
			p.next()
			if braceCount == 0 {
				classNode.EndLine = t.Line
				break
			}
			continue
		} else if t.Value == "{" {
			braceCount++
			p.next()
			continue
		}

		// Try to identify methods
		// Heuristic: Type Name ( Args ) {
		// Or: public Type Name ( Args ) {
		// We look ahead
		if p.isMethodStart() {
			method := p.parseMethod()
			if method != nil {
				classNode.Methods = append(classNode.Methods, method)
				continue // parseMethod consumes the body
			}
		} else if p.isFieldStart() {
			field := p.parseField()
			if field != nil {
				classNode.Fields = append(classNode.Fields, field)
			}
		} else {
			p.next()
		}
	}
}

func (p *Parser) isMethodStart() bool {
	// Look ahead for ( ... ) {
	// Simple check: within next 50 tokens do we see '('
	limit := 50
	for i := 0; i < limit && p.pos+i < len(p.tokens); i++ {
		t := p.tokens[p.pos+i]
		if t.Value == "(" {
			// Check if previous token was identifier (Method Name)
			if i > 0 && p.tokens[p.pos+i-1].Type == TOKEN_IDENTIFIER {
				// Check if token before that was Type (Identifier or Primitive)
				// Or if it's constructor (ClassName)
				return true
			}
		}
		if t.Value == ";" || t.Value == "{" || t.Value == "}" {
			return false
		}
	}
	return false
}

func (p *Parser) parseMethod() *MethodNode {
	// Skip annotations
	for p.peek().Value == "@" {
		p.next() // @
		p.next() // Name
		if p.peek().Value == "(" {
			p.next() // consume (
			p.skipBalanced("(", ")")
		}
	}

	// Skip modifiers
	modifiers := []string{"public", "private", "protected", "abstract", "static", "final", "synchronized", "native"}
	for contains(modifiers, p.peek().Value) {
		p.next()
	}

	// Generic type <T>
	if p.peek().Value == "<" {
		p.next() // consume <
		p.skipBalanced("<", ">")
	}

	// Return Type
	returnType := p.next().Value
	// Handle array return type
	for p.peek().Value == "[" {
		p.next()
		p.next()
		returnType += "[]"
	}
	// Handle generic return type
	if p.peek().Value == "<" {
		p.next()
		gen := p.consumeBalanced("<", ">")
		returnType += "<" + gen + ">"
	}

	// Method Name
	methodName := p.next().Value

	// Parameters
	p.consume("(")
	var parameters []string
	if p.peek().Value != ")" {
		for {
			// Parse one parameter
			// Capture annotations
			var annotations string
			for p.peek().Value == "@" {
				p.next()                  // @
				annName := p.next().Value // Annotation Name
				annotations += "@" + annName + " "
				if p.peek().Value == "(" {
					p.next()
					p.skipBalanced("(", ")")
				}
			}

			// Modifiers
			if p.peek().Value == "final" {
				p.next()
			}

			// Type
			typeStr := p.next().Value
			// Generics
			if p.peek().Value == "<" {
				p.next()
				gen := p.consumeBalanced("<", ">")
				typeStr += "<" + gen + ">"
			}
			// Array
			for p.peek().Value == "[" {
				p.next() // [
				p.next() // ]
				typeStr += "[]"
			}
			// Varargs ...
			if p.peek().Value == "..." {
				p.next()
				typeStr += "..."
			}

			// Name
			nameStr := p.next().Value

			parameters = append(parameters, annotations+typeStr+" "+nameStr)

			if p.peek().Value == "," {
				p.next()
			} else {
				break
			}
		}
	}
	p.consume(")")

	// Check if abstract or interface method (no body)
	if p.peek().Value == ";" {
		p.next()
		return &MethodNode{
			Name:       methodName,
			ReturnType: returnType,
			StartLine:  p.tokens[p.pos-1].Line,
			EndLine:    p.tokens[p.pos-1].Line,
			Parameters: parameters,
		}
	}

	// Method Body
	if p.peek().Value == "throws" {
		for p.peek().Value != "{" && p.peek().Value != ";" {
			p.next()
		}
	}

	if p.peek().Value == "{" {
		startLine := p.peek().Line
		// Capture body tokens
		bodyStart := p.pos
		p.consume("{")
		p.skipBalanced("{", "}")
		bodyEnd := p.pos
		endLine := p.tokens[bodyEnd-1].Line

		// Extract raw body
		// This is tricky with tokens, we need raw text.
		// For now, we can extract Calls from tokens
		calls := p.extractCalls(bodyStart, bodyEnd)

		return &MethodNode{
			Name:       methodName,
			ReturnType: returnType,
			StartLine:  startLine,
			EndLine:    endLine,
			Parameters: parameters,
			Calls:      calls,
		}
	}

	return nil
}

func (p *Parser) extractCalls(start, end int) []string {
	var calls []string
	for i := start; i < end; i++ {
		// Look for identifier followed by (
		if i+1 < end && p.tokens[i+1].Value == "(" {
			if p.tokens[i].Type == TOKEN_IDENTIFIER {
				// Exclude keywords like if, for, while
				val := p.tokens[i].Value
				if !isKeyword(val) {
					// Handle qualified names like obj.method()
					if strings.Contains(val, ".") {
						parts := strings.Split(val, ".")
						val = parts[len(parts)-1]
					}
					calls = append(calls, val)
				}
			}
		}
	}
	return calls
}

func isKeyword(s string) bool {
	keywords := []string{"if", "for", "while", "switch", "catch", "synchronized", "super", "this"}
	return contains(keywords, s)
}

func (p *Parser) isFieldStart() bool {
	// Simple check: [modifiers] [annotations] Type Name ; [= ...]
	// We look for: identifier identifier ; or identifier identifier =
	// Skip annotations and modifiers
	i := 0
	for p.pos+i < len(p.tokens) {
		t := p.tokens[p.pos+i]
		if t.Value == "@" {
			i += 2 // @ Name
			if p.pos+i < len(p.tokens) && p.tokens[p.pos+i].Value == "(" {
				// Skip balanced parens
				i++
				count := 1
				for p.pos+i < len(p.tokens) {
					if p.tokens[p.pos+i].Value == "(" {
						count++
					} else if p.tokens[p.pos+i].Value == ")" {
						count--
						if count == 0 {
							i++
							break
						}
					}
					i++
				}
			}
			continue
		}
		modifiers := []string{"public", "private", "protected", "static", "final", "transient", "volatile"}
		if contains(modifiers, t.Value) {
			i++
			continue
		}
		break
	}

	// Now we should be at the Type
	if p.pos+i < len(p.tokens) && p.tokens[p.pos+i].Type == TOKEN_IDENTIFIER {
		i++
		// Check for Generics <...>
		if p.pos+i < len(p.tokens) && p.tokens[p.pos+i].Value == "<" {
			i++
			count := 1
			for p.pos+i < len(p.tokens) {
				if p.tokens[p.pos+i].Value == "<" {
					count++
				} else if p.tokens[p.pos+i].Value == ">" {
					count--
					if count == 0 {
						i++
						break
					}
				}
				i++
			}
		}

		// Now we should be at the Name
		if p.pos+i < len(p.tokens) && p.tokens[p.pos+i].Type == TOKEN_IDENTIFIER {
			// Check if next is ; or =
			if p.pos+i+1 < len(p.tokens) {
				next := p.tokens[p.pos+i+1].Value
				return next == ";" || next == "="
			}
		}
	}
	return false
}

func (p *Parser) parseField() *FieldNode {
	// Skip annotations
	for p.peek().Value == "@" {
		p.next() // @
		p.next() // Name
		if p.peek().Value == "(" {
			p.next()
			p.skipBalanced("(", ")")
		}
	}

	// Skip modifiers
	modifiers := []string{"public", "private", "protected", "static", "final", "transient", "volatile"}
	for contains(modifiers, p.peek().Value) {
		p.next()
	}

	// Type
	typeStr := p.next().Value
	// Handle generics
	if p.peek().Value == "<" {
		p.next()
		gen := p.consumeBalanced("<", ">")
		typeStr += "<" + gen + ">"
	}

	// Name
	nameStr := p.next().Value

	// Skip until ; (but respect braces/parens)
	braceCount := 0
	parenCount := 0
	for p.pos < len(p.tokens) {
		t := p.peek()
		if t.Value == ";" && braceCount == 0 && parenCount == 0 {
			break
		}
		if t.Value == "{" {
			braceCount++
		} else if t.Value == "}" {
			braceCount--
		} else if t.Value == "(" {
			parenCount++
		} else if t.Value == ")" {
			parenCount--
		}
		p.next()
	}
	p.consume(";")

	return &FieldNode{
		Name: nameStr,
		Type: typeStr,
	}
}

func (p *Parser) skipBalanced(open, close string) {
	count := 1
	for p.pos < len(p.tokens) {
		t := p.next()
		if t.Value == open {
			count++
		} else if t.Value == close {
			count--
			if count == 0 {
				return
			}
		}
	}
}

func (p *Parser) consumeBalanced(open, close string) string {
	var sb strings.Builder
	count := 1
	for p.pos < len(p.tokens) {
		t := p.next()
		if t.Value == open {
			count++
		} else if t.Value == close {
			count--
			if count == 0 {
				return sb.String()
			}
		}
		sb.WriteString(t.Value)
	}
	return sb.String()
}

// Helpers

func (p *Parser) peek() Token {
	if p.pos >= len(p.tokens) {
		return Token{Type: TOKEN_EOF}
	}
	return p.tokens[p.pos]
}

func (p *Parser) next() Token {
	t := p.peek()
	if t.Type != TOKEN_EOF {
		p.pos++
	}
	return t
}

func (p *Parser) consume(val string) {
	if p.peek().Value == val {
		p.next()
	}
}

func contains(slice []string, val string) bool {
	for _, item := range slice {
		if item == val {
			return true
		}
	}
	return false
}

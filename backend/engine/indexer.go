package engine

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// SymbolTable holds the global index of the project
type SymbolTable struct {
	// Map SimpleClassName -> FullClassName (e.g. "UserService" -> "com.example.UserService")
	ClassMap map[string]string
	// Map FullClassName -> FilePath
	FileMap map[string]string
	// Map InterfaceName -> []ImplementationClassName
	InterfaceMap map[string][]string
	// Map FullClassName -> MethodName -> MethodInfo
	MethodMap map[string]map[string]*MethodInfo
	// Map FullClassName -> []Imports
	ImportMap map[string][]string
	// Map FullClassName -> PackageName
	PackageMap map[string]string
	// Map MethodName -> []CallerMethodIdentifier (Call Graph)
	CallerMap map[string][]string
	// Map FilePath -> []FullClassName
	FileToClassesMap map[string][]string
}

type MethodInfo struct {
	Name       string
	ClassName  string // Added ClassName
	FilePath   string
	StartLine  int
	EndLine    int
	Parameters []string
	ReturnType string
	Calls      []string // Methods called by this method
}

// Global index instance
var ProjectIndex *SymbolTable

func NewSymbolTable() *SymbolTable {
	return &SymbolTable{
		ClassMap:         make(map[string]string),
		FileMap:          make(map[string]string),
		InterfaceMap:     make(map[string][]string),
		MethodMap:        make(map[string]map[string]*MethodInfo),
		ImportMap:        make(map[string][]string),
		PackageMap:       make(map[string]string),
		CallerMap:        make(map[string][]string),
		FileToClassesMap: make(map[string][]string),
	}
}

// BuildIndex scans the entire project to build the symbol table
func (st *SymbolTable) BuildIndex(root string) error {
	var mu sync.Mutex
	var wg sync.WaitGroup

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if strings.HasSuffix(path, ".java") {
			wg.Add(1)
			go func(p string) {
				defer wg.Done()
				st.indexFile(p, &mu)
			}(path)
		}
		return nil
	})
	wg.Wait()
	return err
}

func (st *SymbolTable) indexFile(path string, mu *sync.Mutex) {
	// Use the new Parser
	javaFile, err := ParseJavaFile(path)
	if err != nil {
		return
	}

	mu.Lock()
	defer mu.Unlock()

	for _, classNode := range javaFile.Classes {
		fullClassName := classNode.Name
		if javaFile.Package != "" {
			fullClassName = javaFile.Package + "." + classNode.Name
		}

		st.ClassMap[classNode.Name] = fullClassName
		st.FileMap[fullClassName] = path
		st.FileToClassesMap[path] = append(st.FileToClassesMap[path], fullClassName)
		st.ImportMap[fullClassName] = javaFile.Imports
		st.PackageMap[fullClassName] = javaFile.Package

		// Handle Interfaces
		for _, impl := range classNode.Implements {
			st.InterfaceMap[impl] = append(st.InterfaceMap[impl], fullClassName)
		}

		// Initialize MethodMap for this class
		if st.MethodMap[fullClassName] == nil {
			st.MethodMap[fullClassName] = make(map[string]*MethodInfo)
		}

		// Store Methods
		for _, method := range classNode.Methods {
			st.MethodMap[fullClassName][method.Name] = &MethodInfo{
				Name:       method.Name,
				ClassName:  fullClassName,
				FilePath:   path,
				StartLine:  method.StartLine,
				EndLine:    method.EndLine,
				Parameters: method.Parameters,
				ReturnType: method.ReturnType,
				Calls:      method.Calls,
			}

			// Build Reverse Call Graph (Usage Index)
			for _, calledMethod := range method.Calls {
				callerID := fullClassName + ":" + method.Name
				st.CallerMap[calledMethod] = append(st.CallerMap[calledMethod], callerID)

				// Also index by simple name if it's a qualified call (e.g. obj.method)
				// This helps when we don't know the variable type in the scanner
				if strings.Contains(calledMethod, ".") {
					parts := strings.Split(calledMethod, ".")
					simpleName := parts[len(parts)-1]
					// Avoid duplicates if possible, but slice append is okay for now
					st.CallerMap[simpleName] = append(st.CallerMap[simpleName], callerID)
				}
			}
		}
	}
}

// ResolveType attempts to find the full class name for a variable type
func (st *SymbolTable) ResolveType(simpleName string, currentContextClass string) string {
	// 1. Check imports of the current class
	imports := st.ImportMap[currentContextClass]
	for _, imp := range imports {
		if strings.HasSuffix(imp, "."+simpleName) {
			return imp
		}
	}

	// 2. Check same package
	pkg := st.PackageMap[currentContextClass]
	samePkgClass := pkg + "." + simpleName
	if _, ok := st.FileMap[samePkgClass]; ok {
		return samePkgClass
	}

	// 3. Check java.lang (implicit) - skipped for now

	// 4. Global lookup (fallback)
	if fullName, ok := st.ClassMap[simpleName]; ok {
		return fullName
	}

	return simpleName
}

// FindImplementations finds all classes that implement an interface
func (st *SymbolTable) FindImplementations(interfaceName string) []string {
	// Try direct lookup
	if impls, ok := st.InterfaceMap[interfaceName]; ok {
		return impls
	}
	return nil
}

// GetMethodInfo finds method info by class and method name
func (st *SymbolTable) GetMethodInfo(className, methodName string) *MethodInfo {
	if methods, ok := st.MethodMap[className]; ok {
		if info, ok := methods[methodName]; ok {
			return info
		}
	}
	return nil
}

// GetMethodByLine finds which method contains the given line number in a file
func (st *SymbolTable) GetMethodByLine(filePath string, line int) *MethodInfo {
	// Optimization: Use FileToClassesMap
	if classes, ok := st.FileToClassesMap[filePath]; ok {
		for _, fullClassName := range classes {
			if methods, ok := st.MethodMap[fullClassName]; ok {
				for _, m := range methods {
					if line >= m.StartLine && line <= m.EndLine {
						return m
					}
				}
			}
		}
	}
	return nil
}

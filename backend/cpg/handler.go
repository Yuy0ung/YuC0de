package cpg

import (
	"fmt"
	"net/http"
	"strings"
	"sync"

	"yy-sast-backend/engine"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// Task structure matching main.go (simplified for reading)
type Task struct {
	ID       uint   `gorm:"primaryKey" json:"id"`
	ScanPath string `json:"scan_path"`
}

var (
	DB            *gorm.DB
	CurrentTaskID uint
	CurrentIndex  *engine.SymbolTable
	IndexMutex    sync.Mutex
)

// Init initializes the CPG module
func Init(db *gorm.DB) {
	DB = db
}

// Node represents a graph node
type Node struct {
	ID    string `json:"id"`
	Label string `json:"label"`
	Type  string `json:"type"` // class, method, field
	Data  any    `json:"data,omitempty"`
}

// Edge represents a graph edge
type Edge struct {
	Source string `json:"source"`
	Target string `json:"target"`
	Type   string `json:"type"` // HAS_METHOD, HAS_FIELD, CALLS, CALLED_BY, ACCESS, EXTENDS, RECURSION
	Label  string `json:"label,omitempty"`
}

// GraphResponse represents the CPG graph
type GraphResponse struct {
	Nodes []Node `json:"nodes"`
	Edges []Edge `json:"edges"`
}

// ListNodesHandler returns all available nodes (classes/methods) for the sidebar
func ListNodesHandler(c *gin.Context) {
	taskIDStr := c.Param("taskId")
	var task Task
	if err := DB.First(&task, "id = ?", taskIDStr).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Task not found"})
		return
	}

	IndexMutex.Lock()
	defer IndexMutex.Unlock()

	// Rebuild index if needed
	if CurrentTaskID != task.ID || CurrentIndex == nil {
		newIndex := engine.NewSymbolTable()
		if err := newIndex.BuildIndex(task.ScanPath); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to build index: " + err.Error()})
			return
		}
		CurrentIndex = newIndex
		CurrentTaskID = task.ID
	}

	nodes := []map[string]string{}

	// Add Classes
	for simpleName, fullName := range CurrentIndex.ClassMap {
		nodes = append(nodes, map[string]string{
			"id":    fullName,
			"label": simpleName,
			"type":  "class",
		})
	}

	// Add Methods
	for className, methods := range CurrentIndex.MethodMap {
		for methodName, info := range methods {
			nodes = append(nodes, map[string]string{
				"id":    fmt.Sprintf("%s:%s", className, methodName),
				"label": fmt.Sprintf("%s.%s", className, methodName),
				"type":  "method",
				"file":  info.FilePath,
				"line":  fmt.Sprintf("%d", info.StartLine),
			})
		}
	}

	// Add Fields
	for className, fields := range CurrentIndex.FieldMap {
		for fieldName, fieldType := range fields {
			nodes = append(nodes, map[string]string{
				"id":    fmt.Sprintf("%s:%s", className, fieldName),
				"label": fmt.Sprintf("%s.%s (%s)", className, fieldName, fieldType),
				"type":  "field",
			})
		}
	}

	c.JSON(http.StatusOK, nodes)
}

// queueItem for BFS
type queueItem struct {
	ID        string
	Type      string // "class", "method", "field"
	Depth     int
	Direction int // 0: Both, 1: Upstream, 2: Downstream
}

const (
	DirBoth       = 0
	DirUpstream   = 1
	DirDownstream = 2
)

// GetGraphHandler returns the CPG for a specific node with multi-hop tracing
func GetGraphHandler(c *gin.Context) {
	taskIDStr := c.Param("taskId")
	nodeID := c.Query("node") // Expected: "FullClassName:MethodName" or "FullClassName"

	if nodeID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Node ID required"})
		return
	}

	var task Task
	if err := DB.First(&task, "id = ?", taskIDStr).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Task not found"})
		return
	}

	IndexMutex.Lock()
	defer IndexMutex.Unlock()

	if CurrentTaskID != task.ID || CurrentIndex == nil {
		newIndex := engine.NewSymbolTable()
		if err := newIndex.BuildIndex(task.ScanPath); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to build index"})
			return
		}
		CurrentIndex = newIndex
		CurrentTaskID = task.ID
	}

	graph := GraphResponse{
		Nodes: []Node{},
		Edges: []Edge{},
	}

	// Helper to add node if unique
	addedNodes := make(map[string]bool)
	addNode := func(n Node) {
		if !addedNodes[n.ID] {
			graph.Nodes = append(graph.Nodes, n)
			addedNodes[n.ID] = true
		}
	}
	addEdge := func(e Edge) {
		// Check for duplicate edges could be added here if needed, but simple append is usually fine for small graphs
		graph.Edges = append(graph.Edges, e)
	}

	// File parsing cache
	fileCache := make(map[string]*engine.JavaFile)
	getJavaFile := func(path string) (*engine.JavaFile, error) {
		if f, ok := fileCache[path]; ok {
			return f, nil
		}
		f, err := engine.ParseJavaFile(path)
		if err == nil {
			fileCache[path] = f
		}
		return f, err
	}

	// Determine start node type
	var startType string
	if strings.Contains(nodeID, ":") {
		parts := strings.SplitN(nodeID, ":", 2)
		if len(parts) >= 2 {
			className := parts[0]
			memberName := parts[1]
			if _, ok := CurrentIndex.MethodMap[className][memberName]; ok {
				startType = "method"
			} else if _, ok := CurrentIndex.FieldMap[className][memberName]; ok {
				startType = "field"
			} else {
				// Assume method if unknown (e.g. from caller map)
				startType = "method"
			}
		}
	} else {
		startType = "class"
	}

	// BFS Init
	queue := []queueItem{{ID: nodeID, Type: startType, Depth: 0, Direction: DirBoth}}
	visited := make(map[string]bool)
	maxDepth := 3   // Trace depth
	maxNodes := 200 // Safety limit
	processedCount := 0

	// Helper to resolve method calls
	resolveMethodCall := func(sourceClass, methodName string) string {
		// 1. Check same class
		if _, ok := CurrentIndex.MethodMap[sourceClass][methodName]; ok {
			return fmt.Sprintf("%s:%s", sourceClass, methodName)
		}

		// 2. Check Parent Classes (Inheritance)
		currClass := sourceClass
		for {
			parent, ok := CurrentIndex.ExtendsMap[currClass]
			if !ok || parent == "" {
				break
			}
			// Resolve parent full name if simple name
			if fullParent, ok := CurrentIndex.ClassMap[parent]; ok {
				parent = fullParent
			}
			// Check parent
			if _, ok := CurrentIndex.MethodMap[parent][methodName]; ok {
				return fmt.Sprintf("%s:%s", parent, methodName)
			}
			currClass = parent
		}

		// 3. Check Imports
		if imports, ok := CurrentIndex.ImportMap[sourceClass]; ok {
			for _, imp := range imports {
				// Assume import is full class path (e.g. "com.example.User")
				// If method is in that class
				if _, ok := CurrentIndex.MethodMap[imp][methodName]; ok {
					return fmt.Sprintf("%s:%s", imp, methodName)
				}
			}
		}

		// 4. Fallback: Naive Search (ONLY for non-common methods)
		// Common CRUD and utility methods cause massive false positives
		commonMethods := map[string]bool{
			"save": true, "update": true, "delete": true, "insert": true,
			"get": true, "set": true, "add": true, "remove": true,
			"init": true, "run": true, "start": true, "stop": true,
			"close": true, "open": true, "equals": true, "hashCode": true,
			"toString": true, "clone": true, "list": true,
		}

		if !commonMethods[methodName] {
			for cName, ms := range CurrentIndex.MethodMap {
				if _, ok := ms[methodName]; ok {
					return fmt.Sprintf("%s:%s", cName, methodName)
				}
			}
		}

		return ""
	}

	for len(queue) > 0 && processedCount < maxNodes {
		curr := queue[0]
		queue = queue[1:]

		if visited[curr.ID] {
			continue
		}
		visited[curr.ID] = true
		processedCount++

		// Add current node to graph
		parts := strings.SplitN(curr.ID, ":", 2)
		var className, memberName string
		if len(parts) == 2 {
			className = parts[0]
			memberName = parts[1]
		} else {
			className = curr.ID
		}

		if curr.Type == "class" {
			addNode(Node{ID: curr.ID, Label: className, Type: "class"})
		} else {
			// Find file path/line for method
			var data map[string]any
			if curr.Type == "method" {
				if methods, ok := CurrentIndex.MethodMap[className]; ok {
					if info, ok := methods[memberName]; ok {
						data = map[string]any{"file": info.FilePath, "line": info.StartLine}
					}
				}
				// Better Label: Class.Method
				simpleClass := className
				if lastDot := strings.LastIndex(className, "."); lastDot != -1 {
					simpleClass = className[lastDot+1:]
				}
				label := fmt.Sprintf("%s.%s", simpleClass, memberName)
				addNode(Node{ID: curr.ID, Label: label, Type: curr.Type, Data: data})
			} else {
				addNode(Node{ID: curr.ID, Label: memberName, Type: curr.Type, Data: data})
			}
		}

		// Stop expanding at max depth
		if curr.Depth >= maxDepth {
			continue
		}

		// Expand Neighbors
		if curr.Type == "method" {
			// 1. Parent Class (HAS_METHOD) - Upstream Context
			// Always show parent class for context
			classNodeID := className
			addNode(Node{ID: classNodeID, Label: className, Type: "class"})
			addEdge(Edge{Source: classNodeID, Target: curr.ID, Type: "HAS_METHOD"})

			if methods, ok := CurrentIndex.MethodMap[className]; ok {
				if methodInfo, ok := methods[memberName]; ok {
					// Get Method Body for detailed analysis
					var methodBody string
					if jFile, err := getJavaFile(methodInfo.FilePath); err == nil {
						for _, cls := range jFile.Classes {
							if cls.Name == className || strings.HasSuffix(className, "."+cls.Name) || (jFile.Package+"."+cls.Name == className) {
								for _, m := range cls.Methods {
									if m.Name == memberName {
										methodBody = m.Body
										break
									}
								}
							}
						}
					}

					// 1.5 Parse Internal Structure (Variables, Expressions, Control Flow)
					if methodBody != "" {
						parseResult := ParseMethodStructure(curr.ID, methodBody, methodInfo.StartLine)
						for _, n := range parseResult.Nodes {
							addNode(n)
						}
						for _, e := range parseResult.Edges {
							addEdge(e)
						}

						// Add detailed CALLS edges from Expressions
						for callName, sourceIDs := range parseResult.CallSites {
							// Resolve call
							targetID := resolveMethodCall(className, callName)

							if targetID != "" {
								for _, sourceID := range sourceIDs {
									addEdge(Edge{Source: sourceID, Target: targetID, Type: "CALLS"})
								}
							}
						}
					}

					// 2. Downstream Calls (CALLS) - Summary & Traversal
					if (curr.Direction == DirBoth || curr.Direction == DirDownstream) && methodInfo.Calls != nil {
						for _, call := range methodInfo.Calls {
							targetID := resolveMethodCall(className, call)

							if targetID != "" {
								queue = append(queue, queueItem{ID: targetID, Type: "method", Depth: curr.Depth + 1, Direction: DirDownstream})
								// Keep summary edge for connectivity
								edgeType := "CALLS"
								if curr.ID == targetID {
									edgeType = "RECURSION"
								}
								addEdge(Edge{Source: curr.ID, Target: targetID, Type: edgeType})
							}
						}
					}

					// 3. Field Access (ACCESS) - Method reads/writes Field (Downstream)
					if (curr.Direction == DirBoth || curr.Direction == DirDownstream) && methodBody != "" {
						if fields, ok := CurrentIndex.FieldMap[className]; ok {
							for fName := range fields {
								if strings.Contains(methodBody, fName) {
									fieldID := fmt.Sprintf("%s:%s", className, fName)
									queue = append(queue, queueItem{ID: fieldID, Type: "field", Depth: curr.Depth + 1, Direction: DirDownstream})
									addEdge(Edge{Source: curr.ID, Target: fieldID, Type: "ACCESS"})
								}
							}
						}
					}
				}
			}

			// 4. Upstream Callers (CALLED_BY)
			if curr.Direction == DirBoth || curr.Direction == DirUpstream {
				if callers, ok := CurrentIndex.CallerMap[memberName]; ok {
					for _, callerID := range callers {
						queue = append(queue, queueItem{ID: callerID, Type: "method", Depth: curr.Depth + 1, Direction: DirUpstream})
						edgeType := "CALLS"
						if callerID == curr.ID {
							edgeType = "RECURSION"
						}
						addEdge(Edge{Source: callerID, Target: curr.ID, Type: edgeType}) // Edge is caller -> callee
					}
				}
			}

		} else if curr.Type == "field" {
			// 1. Parent Class (HAS_FIELD)
			classNodeID := className
			addNode(Node{ID: classNodeID, Label: className, Type: "class"})
			addEdge(Edge{Source: classNodeID, Target: curr.ID, Type: "HAS_FIELD"})

			// 2. Accessed By (ACCESS) - Upstream
			if curr.Direction == DirBoth || curr.Direction == DirUpstream {
				if methods, ok := CurrentIndex.MethodMap[className]; ok {
					for mName, mInfo := range methods {
						if jFile, err := getJavaFile(mInfo.FilePath); err == nil {
							var methodBody string
							for _, cls := range jFile.Classes {
								if cls.Name == className || strings.HasSuffix(className, "."+cls.Name) || (jFile.Package+"."+cls.Name == className) {
									for _, m := range cls.Methods {
										if m.Name == mName {
											methodBody = m.Body
											break
										}
									}
								}
							}
							if strings.Contains(methodBody, memberName) {
								methodID := fmt.Sprintf("%s:%s", className, mName)
								queue = append(queue, queueItem{ID: methodID, Type: "method", Depth: curr.Depth + 1, Direction: DirUpstream})
								addEdge(Edge{Source: methodID, Target: curr.ID, Type: "ACCESS"}) // Edge is method -> field
							}
						}
					}
				}
			}

		} else if curr.Type == "class" {
			className := curr.ID

			// 1. Parent Class (EXTENDS) - Upstream
			if curr.Direction == DirBoth || curr.Direction == DirUpstream {
				if parent, ok := CurrentIndex.ExtendsMap[className]; ok && parent != "" {
					parentID := parent
					if fullParent, ok := CurrentIndex.ClassMap[parent]; ok {
						parentID = fullParent
					}
					queue = append(queue, queueItem{ID: parentID, Type: "class", Depth: curr.Depth + 1, Direction: DirUpstream})
					addEdge(Edge{Source: className, Target: parentID, Type: "EXTENDS"}) // Child -> Parent
				}
			}

			// 2. Subclasses (EXTENDED_BY) - Downstream
			if curr.Direction == DirBoth || curr.Direction == DirDownstream {
				for child, parent := range CurrentIndex.ExtendsMap {
					if parent == className || strings.HasSuffix(className, "."+parent) {
						childID := child
						if fullChild, ok := CurrentIndex.ClassMap[child]; ok {
							childID = fullChild
						}
						queue = append(queue, queueItem{ID: childID, Type: "class", Depth: curr.Depth + 1, Direction: DirDownstream})
						addEdge(Edge{Source: childID, Target: className, Type: "EXTENDS"}) // child extends parent
					}
				}

				// 3. Members (HAS_METHOD, HAS_FIELD) - Downstream
				if methods, ok := CurrentIndex.MethodMap[className]; ok {
					for mName := range methods {
						methodID := fmt.Sprintf("%s:%s", className, mName)
						queue = append(queue, queueItem{ID: methodID, Type: "method", Depth: curr.Depth + 1, Direction: DirDownstream})
						addEdge(Edge{Source: className, Target: methodID, Type: "HAS_METHOD"})
					}
				}
				if fields, ok := CurrentIndex.FieldMap[className]; ok {
					for fName := range fields {
						fieldID := fmt.Sprintf("%s:%s", className, fName)
						queue = append(queue, queueItem{ID: fieldID, Type: "field", Depth: curr.Depth + 1, Direction: DirDownstream})
						addEdge(Edge{Source: className, Target: fieldID, Type: "HAS_FIELD"})
					}
				}
			}
		}
	}

	c.JSON(http.StatusOK, graph)
}

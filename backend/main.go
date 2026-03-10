package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"gopkg.in/yaml.v3"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"yy-sast-backend/cpg"
	"yy-sast-backend/engine"
)

// Database Models
type AIConfig struct {
	ID       uint   `gorm:"primaryKey" json:"id"`
	BaseURL  string `json:"base_url"`
	APIKey   string `json:"api_key"`
	Model    string `json:"model"`
	Language string `json:"language"` // "en" or "zh", default "zh"
}

type RuleModel struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	Enabled     bool   `json:"enabled"`
	Filename    string `gorm:"primaryKey" json:"filename"` // Use Filename as PK to allow ID changes
	Content     string `json:"content"`                    // Full YAML
}

type Task struct {
	ID         uint      `gorm:"primaryKey" json:"id"`
	CreatedAt  time.Time `json:"created_at"`
	Status     string    `json:"status"` // PENDING, RUNNING, COMPLETED, FAILED
	Target     string    `json:"target"`
	SourceType string    `json:"source_type"` // "local" or "git"
	ScanPath   string    `json:"scan_path"`   // Actual path on disk
	VulnCount  int       `json:"vuln_count"`
	AIEnabled  bool      `json:"ai_enabled"`
}

type VulnerabilityRecord struct {
	ID          uint   `gorm:"primaryKey" json:"id"`
	TaskID      uint   `json:"task_id"`
	RuleID      string `json:"rule_id"`
	RuleName    string `json:"rule_name"`
	Severity    string `json:"severity"`
	FilePath    string `json:"file_path"`
	LineNumber  int    `json:"line_number"`
	Snippet     string `json:"snippet"`
	LineContent string `json:"line_content"`
	StepsJSON   string `json:"steps_json"`
	AIAnalysis  string `json:"ai_analysis"` // JSON string: { "is_false_positive": bool, "reason": "...", "sanitization": "..." }
}

var db *gorm.DB
var taskBroker *Broker

// SSE Broker
type Broker struct {
	Clients        map[chan string]bool
	NewClients     chan chan string
	DefunctClients chan chan string
	Messages       chan string
}

func NewBroker() *Broker {
	return &Broker{
		Clients:        make(map[chan string]bool),
		NewClients:     make(chan chan string),
		DefunctClients: make(chan chan string),
		Messages:       make(chan string),
	}
}

func (b *Broker) Listen() {
	for {
		select {
		case s := <-b.NewClients:
			b.Clients[s] = true
		case s := <-b.DefunctClients:
			delete(b.Clients, s)
			close(s)
		case msg := <-b.Messages:
			for s := range b.Clients {
				s <- msg
			}
		}
	}
}

func (b *Broker) ServeHTTP(c *gin.Context) {
	c.Writer.Header().Set("Content-Type", "text/event-stream")
	c.Writer.Header().Set("Cache-Control", "no-cache")
	c.Writer.Header().Set("Connection", "keep-alive")
	c.Writer.Header().Set("Access-Control-Allow-Origin", "*")

	messageChan := make(chan string)
	b.NewClients <- messageChan

	// Send initial data
	go func() {
		var tasks []Task
		if err := db.Order("created_at desc").Find(&tasks).Error; err == nil {
			jsonData, _ := json.Marshal(tasks)
			messageChan <- string(jsonData)
		}
	}()

	defer func() {
		b.DefunctClients <- messageChan
	}()

	c.Stream(func(w io.Writer) bool {
		if msg, ok := <-messageChan; ok {
			c.SSEvent("message", msg)
			return true
		}
		return false
	})
}

// broadcastTasks fetches all tasks and broadcasts them to connected clients
func broadcastTasks() {
	var tasks []Task
	if err := db.Order("created_at desc").Find(&tasks).Error; err != nil {
		fmt.Printf("Error fetching tasks for broadcast: %v\n", err)
		return
	}
	jsonData, err := json.Marshal(tasks)
	if err != nil {
		fmt.Printf("Error marshalling tasks for broadcast: %v\n", err)
		return
	}
	// Non-blocking send to avoid hanging if broker is busy (though Listen loop should be fast)
	go func() {
		taskBroker.Messages <- string(jsonData)
	}()
}

func initDB() {
	var err error
	// Using SQLite for simplicity in this demo, can switch to MySQL
	db, err = gorm.Open(sqlite.Open("sast.db"), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}
	// Drop table to ensure schema change if needed (careful in prod, okay for dev tool)
	if db.Migrator().HasTable(&RuleModel{}) {
		db.Migrator().DropTable(&RuleModel{})
	}
	db.AutoMigrate(&Task{}, &VulnerabilityRecord{}, &RuleModel{}, &AIConfig{})

	// Initialize default AI config if not exists
	var count int64
	db.Model(&AIConfig{}).Count(&count)
	if count == 0 {
		db.Create(&AIConfig{
			BaseURL:  "https://api.openai.com/v1",
			APIKey:   "",
			Model:    "gpt-4o",
			Language: "zh",
		})
	}
}

func main() {
	initDB()
	initRulesDB()

	// Initialize CPG module
	cpg.Init(db)

	// Initialize and start SSE broker
	taskBroker = NewBroker()
	go taskBroker.Listen()

	r := gin.Default()

	// CORS
	r.Use(func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")
		if origin != "" {
			c.Writer.Header().Set("Access-Control-Allow-Origin", origin)
		} else {
			c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		}
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE, PATCH")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}
		c.Next()
	})

	api := r.Group("/api")
	{
		api.GET("/rules", listRules)
		api.POST("/scan", startScan)
		api.GET("/tasks", listTasks)
		api.GET("/tasks/stream", taskBroker.ServeHTTP) // SSE endpoint
		api.POST("/tasks/delete", deleteTasks)
		api.GET("/tasks/:id", getTask)
		api.GET("/files", getFileContent)
		api.GET("/ai/config", getAIConfig)
		api.POST("/ai/config", updateAIConfig)
		api.POST("/rules/update", updateRule)
		api.POST("/rules/toggle", toggleRule)
		api.POST("/rules/create", createRule)
		api.POST("/rules/delete", deleteRule)

		// CPG Endpoints
		api.GET("/cpg/nodes/:taskId", cpg.ListNodesHandler)
		api.GET("/cpg/graph/:taskId", cpg.GetGraphHandler)
	}

	r.Run(":8080")
}

func initRulesDB() {
	files, err := os.ReadDir("rules")
	if err != nil {
		fmt.Printf("Error reading rules directory: %v\n", err)
		return
	}

	for _, f := range files {
		if filepath.Ext(f.Name()) == ".yaml" || filepath.Ext(f.Name()) == ".yml" {
			path := filepath.Join("rules", f.Name())
			content, err := os.ReadFile(path)
			if err != nil {
				fmt.Printf("Error reading rule file %s: %v\n", f.Name(), err)
				continue
			}

			var rule engine.Rule
			if err := yaml.Unmarshal(content, &rule); err != nil {
				fmt.Printf("Error parsing rule file %s: %v\n", f.Name(), err)
				continue
			}

			// Check if rule exists in DB
			var existingRule RuleModel
			if err := db.Where("filename = ?", f.Name()).First(&existingRule).Error; err == nil {
				// Update existing record, preserve Enabled status
				existingRule.ID = rule.ID
				existingRule.Name = rule.Name
				existingRule.Severity = rule.Severity
				existingRule.Description = rule.Description
				existingRule.Content = string(content)
				// Do not update Enabled field from YAML
				db.Save(&existingRule)
			} else {
				// Create new record, default Enabled to true
				newRule := RuleModel{
					ID:          rule.ID,
					Name:        rule.Name,
					Severity:    rule.Severity,
					Description: rule.Description,
					Enabled:     true, // Default to true for new rules
					Filename:    f.Name(),
					Content:     string(content),
				}
				db.Create(&newRule)
			}
		}
	}
	fmt.Println("Rules initialized in DB")
}

func listRules(c *gin.Context) {
	var rules []RuleModel
	if err := db.Find(&rules).Error; err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, rules)
}

func startScan(c *gin.Context) {
	var req struct {
		Target     string `json:"target"`
		SourceType string `json:"source_type"`
		AIEnabled  bool   `json:"ai_enabled"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	target := req.Target
	sourceType := req.SourceType
	if sourceType == "" {
		sourceType = "local"
	}

	var scanPath string

	if sourceType == "git" {
		// Create temp dir immediately
		tempDir, err := os.MkdirTemp("", "sast-git-clone-*")
		if err != nil {
			c.JSON(500, gin.H{"error": "Failed to create temp dir"})
			return
		}
		scanPath = tempDir
	} else {
		// Validate local target
		if _, err := os.Stat(target); os.IsNotExist(err) {
			c.JSON(400, gin.H{"error": "Target path does not exist"})
			return
		}
		scanPath = target
	}

	task := Task{
		Status:     "PENDING",
		Target:     target,
		SourceType: sourceType,
		ScanPath:   scanPath,
		AIEnabled:  req.AIEnabled,
	}
	db.Create(&task)
	broadcastTasks() // Notify pending

	// Run scan asynchronously
	go runScan(task)

	c.JSON(200, task)
}

func runScan(t Task) {
	db.Model(&t).Update("Status", "RUNNING")
	broadcastTasks() // Notify running

	if t.SourceType == "git" {
		// git clone
		fmt.Printf("Cloning %s into %s\n", t.Target, t.ScanPath)
		cmd := exec.Command("git", "clone", t.Target, t.ScanPath)

		if err := cmd.Run(); err != nil {
			db.Model(&t).Update("Status", "FAILED")
			fmt.Printf("git clone failed: %v\n", err)
			os.RemoveAll(t.ScanPath)
			broadcastTasks() // Notify failed
			return
		}
		fmt.Printf("git clone successful: %s,scan start\n", t.ScanPath)
	}

	// Load enabled rules from DB
	var rules []RuleModel
	if err := db.Find(&rules).Error; err != nil {
		db.Model(&t).Update("Status", "FAILED")
		broadcastTasks()
		return
	}

	enabledRules := make(map[string]bool)
	for _, r := range rules {
		enabledRules[r.Filename] = r.Enabled
	}

	eng, err := engine.NewEngine("rules", enabledRules)
	if err != nil {
		db.Model(&t).Update("Status", "FAILED")
		broadcastTasks() // Notify failed
		return
	}

	vulns, err := eng.ScanDirectory(t.ScanPath)
	if err != nil {
		db.Model(&t).Update("Status", "FAILED")
		broadcastTasks() // Notify failed
		return
	}

	// Save results
	for _, v := range vulns {
		stepsBytes, _ := json.Marshal(v.Steps)
		rec := VulnerabilityRecord{
			TaskID:      t.ID,
			RuleID:      v.RuleID,
			RuleName:    v.RuleName,
			Severity:    v.Severity,
			FilePath:    v.FilePath,
			LineNumber:  v.LineNumber,
			Snippet:     v.Snippet,
			LineContent: v.LineContent,
			StepsJSON:   string(stepsBytes),
		}
		db.Create(&rec)
	}

	db.Model(&t).Updates(map[string]interface{}{
		"Status":    "COMPLETED",
		"VulnCount": len(vulns),
	})
	broadcastTasks() // Notify completed

	if t.AIEnabled {
		performAIAudit(t.ID, t.ScanPath)
	}
}

func deleteTasks(c *gin.Context) {
	var req struct {
		IDs []uint `json:"ids"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	var tasks []Task
	if err := db.Find(&tasks, req.IDs).Error; err != nil {
		c.JSON(500, gin.H{"error": "Failed to fetch tasks"})
		return
	}

	for _, t := range tasks {
		if t.SourceType == "git" {
			os.RemoveAll(t.ScanPath)
		}
		db.Delete(&t)
		db.Where("task_id = ?", t.ID).Delete(&VulnerabilityRecord{})
	}
	broadcastTasks() // Notify deleted

	c.JSON(200, gin.H{"message": "Tasks deleted"})
}

func listTasks(c *gin.Context) {
	var tasks []Task
	db.Order("created_at desc").Find(&tasks)
	c.JSON(200, tasks)
}

func getTask(c *gin.Context) {
	id := c.Param("id")
	var task Task
	if err := db.First(&task, id).Error; err != nil {
		c.JSON(404, gin.H{"error": "Task not found"})
		return
	}

	var vulns []VulnerabilityRecord
	db.Where("task_id = ?", id).Find(&vulns)

	// Enrich vulnerabilities with parsed steps
	type VulnResponse struct {
		VulnerabilityRecord
		Steps []engine.Step `json:"steps"`
	}
	var resp []VulnResponse
	for _, v := range vulns {
		var steps []engine.Step
		if v.StepsJSON != "" {
			json.Unmarshal([]byte(v.StepsJSON), &steps)
		}
		resp = append(resp, VulnResponse{
			VulnerabilityRecord: v,
			Steps:               steps,
		})
	}

	c.JSON(200, gin.H{
		"task":  task,
		"vulns": resp,
	})
}

func getFileContent(c *gin.Context) {
	path := c.Query("path")
	taskID := c.Query("task_id")

	if path == "" {
		c.JSON(400, gin.H{"error": "path required"})
		return
	}

	filePath := path
	// If path is relative, we need task_id to resolve absolute path
	if !filepath.IsAbs(path) && taskID != "" {
		var task Task
		if err := db.First(&task, taskID).Error; err != nil {
			c.JSON(404, gin.H{"error": "Task not found"})
			return
		}
		basePath := task.ScanPath
		if basePath == "" {
			basePath = task.Target
		}
		filePath = filepath.Join(basePath, path)
	}

	// Security check: ensure path is within allowed directories (simplified for demo)
	content, err := os.ReadFile(filePath)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"content": string(content)})
}

func updateRule(c *gin.Context) {
	var req struct {
		Filename string `json:"filename"`
		Content  string `json:"content"`
	}
	if err := c.BindJSON(&req); err != nil {
		fmt.Printf("Update rule bind error: %v\n", err)
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	if strings.Contains(req.Filename, "/") || strings.Contains(req.Filename, "\\") {
		c.JSON(400, gin.H{"error": "Invalid filename"})
		return
	}

	// 1. Write to file
	path := filepath.Join("rules", req.Filename)
	if err := os.WriteFile(path, []byte(req.Content), 0644); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	// 2. Parse content to update DB
	var rule engine.Rule
	if err := yaml.Unmarshal([]byte(req.Content), &rule); err != nil {
		fmt.Printf("Update rule unmarshal error: %v\nContent: %s\n", err, req.Content)
		c.JSON(400, gin.H{"error": "Invalid YAML content: " + err.Error()})
		return
	}

	// 3. Update DB
	var existingRule RuleModel
	if err := db.Where("filename = ?", req.Filename).First(&existingRule).Error; err == nil {
		fmt.Printf("Updating existing rule in DB: %s (ID: %s)\n", req.Filename, existingRule.ID)
		// Update existing record
		// Use Updates to ensure we update the specific fields we want
		// Also update ID if it changed in YAML (though usually it shouldn't)
		updates := map[string]interface{}{
			"id":          rule.ID,
			"name":        rule.Name,
			"severity":    rule.Severity,
			"description": rule.Description,
			"content":     req.Content,
		}

		if err := db.Model(&existingRule).Updates(updates).Error; err != nil {
			fmt.Printf("Error updating rule in DB: %v\n", err)
			c.JSON(500, gin.H{"error": "DB update failed: " + err.Error()})
			return
		}
		fmt.Printf("Rule updated in DB successfully\n")
	} else {
		fmt.Printf("Creating new rule in DB: %s (ID: %s)\n", req.Filename, rule.ID)
		// Create new record
		newRule := RuleModel{
			ID:          rule.ID,
			Name:        rule.Name,
			Severity:    rule.Severity,
			Description: rule.Description,
			Enabled:     true, // Default to true
			Filename:    req.Filename,
			Content:     req.Content,
		}
		if err := db.Create(&newRule).Error; err != nil {
			fmt.Printf("Error creating rule in DB: %v\n", err)
			c.JSON(500, gin.H{"error": "DB create failed: " + err.Error()})
			return
		}
		fmt.Printf("Rule created in DB successfully\n")
	}

	c.JSON(200, gin.H{"message": "Rule updated"})
}

func toggleRule(c *gin.Context) {
	var req struct {
		Filename string `json:"filename"`
		Enabled  bool   `json:"enabled"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	// Update DB only
	if err := db.Model(&RuleModel{}).Where("filename = ?", req.Filename).Update("enabled", req.Enabled).Error; err != nil {
		c.JSON(500, gin.H{"error": "DB update failed: " + err.Error()})
		return
	}

	c.JSON(200, gin.H{"message": "Rule toggled"})
}

func createRule(c *gin.Context) {
	var req struct {
		Filename string `json:"filename"`
		Content  string `json:"content"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	if strings.Contains(req.Filename, "/") || strings.Contains(req.Filename, "\\") {
		c.JSON(400, gin.H{"error": "Invalid filename"})
		return
	}

	// Ensure filename has .yaml extension
	if !strings.HasSuffix(req.Filename, ".yaml") && !strings.HasSuffix(req.Filename, ".yml") {
		req.Filename += ".yaml"
	}

	path := filepath.Join("rules", req.Filename)
	// Check if file already exists
	if _, err := os.Stat(path); err == nil {
		c.JSON(400, gin.H{"error": "Rule file already exists"})
		return
	}

	// 1. Write to file
	if err := os.WriteFile(path, []byte(req.Content), 0644); err != nil {
		c.JSON(500, gin.H{"error": "Failed to write file: " + err.Error()})
		return
	}

	// 2. Parse content to create DB record
	var rule engine.Rule
	if err := yaml.Unmarshal([]byte(req.Content), &rule); err != nil {
		os.Remove(path) // Rollback file creation
		c.JSON(400, gin.H{"error": "Invalid YAML content: " + err.Error()})
		return
	}

	// 3. Create DB record
	newRule := RuleModel{
		ID:          rule.ID,
		Name:        rule.Name,
		Severity:    rule.Severity,
		Description: rule.Description,
		Enabled:     true, // Default enabled for new rules
		Filename:    req.Filename,
		Content:     req.Content,
	}

	if err := db.Create(&newRule).Error; err != nil {
		os.Remove(path) // Rollback file creation
		c.JSON(500, gin.H{"error": "DB create failed: " + err.Error()})
		return
	}

	c.JSON(200, gin.H{"message": "Rule created successfully"})
}

func deleteRule(c *gin.Context) {
	var req struct {
		Filenames []string `json:"filenames"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	for _, filename := range req.Filenames {
		if strings.Contains(filename, "/") || strings.Contains(filename, "\\") {
			continue // Skip invalid filenames for security
		}

		// 1. Delete file
		path := filepath.Join("rules", filename)
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			fmt.Printf("Error deleting file %s: %v\n", filename, err)
			// Continue to try deleting from DB even if file deletion fails (maybe file already gone)
		}

		// 2. Delete from DB
		if err := db.Where("filename = ?", filename).Delete(&RuleModel{}).Error; err != nil {
			fmt.Printf("Error deleting rule from DB %s: %v\n", filename, err)
		}
	}

	c.JSON(200, gin.H{"message": "Rules deleted successfully"})
}

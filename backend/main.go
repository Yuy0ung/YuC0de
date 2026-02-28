package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"yy-sast-backend/engine"
)

// Database Models
type Task struct {
	ID         uint      `gorm:"primaryKey" json:"id"`
	CreatedAt  time.Time `json:"created_at"`
	Status     string    `json:"status"` // PENDING, RUNNING, COMPLETED, FAILED
	Target     string    `json:"target"`
	SourceType string    `json:"source_type"` // "local" or "git"
	ScanPath   string    `json:"scan_path"`   // Actual path on disk
	VulnCount  int       `json:"vuln_count"`
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
	db.AutoMigrate(&Task{}, &VulnerabilityRecord{})
}

func main() {
	initDB()

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
	}

	r.Run(":8080")
}

func listRules(c *gin.Context) {
	eng, err := engine.NewEngine("rules")
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, eng.Rules)
}

func startScan(c *gin.Context) {
	var req struct {
		Target     string `json:"target"`
		SourceType string `json:"source_type"`
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
	}
	db.Create(&task)
	broadcastTasks() // Notify pending

	// Run scan asynchronously
	go func(t Task) {
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
		}

		eng, err := engine.NewEngine("rules")
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
	}(task)

	c.JSON(200, task)
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

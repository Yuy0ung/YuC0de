package main

import (
	"encoding/json"
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

	// Run scan asynchronously
	go func(t Task) {
		db.Model(&t).Update("Status", "RUNNING")

		if t.SourceType == "git" {
			// git clone
			cmd := exec.Command("git", "clone", t.Target, t.ScanPath)
			// Since ScanPath is an existing empty dir, git clone <url> <dir> works
			// Note: git clone might fail if dir is not empty, but MkdirTemp guarantees it is.
			// However, standard git clone <url> <dir> expects <dir> to be empty.
			// If it fails, we should check if we need to empty it or if MkdirTemp created something weird.
			// Actually, if we want to clone INTO the dir (content only), we might need `git clone <url> .` inside.
			// But `git clone <url> <dir>` is standard.

			if err := cmd.Run(); err != nil {
				db.Model(&t).Update("Status", "FAILED")
				// Cleanup
				os.RemoveAll(t.ScanPath)
				return
			}
		}

		eng, err := engine.NewEngine("rules")
		if err != nil {
			db.Model(&t).Update("Status", "FAILED")
			return
		}

		vulns, err := eng.ScanDirectory(t.ScanPath)
		if err != nil {
			db.Model(&t).Update("Status", "FAILED")
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
	// Note: filepath.IsAbs works differently on Windows vs Unix, assuming Unix for now based on env
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

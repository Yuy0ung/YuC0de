package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func getAIConfig(c *gin.Context) {
	var config AIConfig
	if err := db.First(&config).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch AI config"})
		return
	}
	c.JSON(http.StatusOK, config)
}

func updateAIConfig(c *gin.Context) {
	var input AIConfig
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var config AIConfig
	if err := db.First(&config).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch AI config"})
		return
	}

	config.BaseURL = input.BaseURL
	config.APIKey = input.APIKey
	config.Model = input.Model
	// preserve ID
	if err := db.Save(&config).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update AI config"})
		return
	}

	c.JSON(http.StatusOK, config)
}

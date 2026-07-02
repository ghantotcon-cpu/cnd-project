package main

import (
	"fmt"
	"net/http"
	"os"
	"runtime"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

var (
	BuildCommit  = "unknown"
	BuildTime    = "unknown"
	AppVersion   = "1.0.0"
	SLSALevel    = "3"
	log          = logrus.New()
	startTime    = time.Now()
)

func init() {
	log.SetFormatter(&logrus.JSONFormatter{})
	log.SetOutput(os.Stdout)
	log.SetLevel(logrus.InfoLevel)
}

type HealthResponse struct {
	Status    string `json:"status"`
	Uptime    string `json:"uptime"`
	RequestID string `json:"request_id"`
	Timestamp string `json:"timestamp"`
}

type VersionResponse struct {
	Version     string `json:"version"`
	BuildCommit string `json:"build_commit"`
	BuildTime   string `json:"build_time"`
	SLSALevel   string `json:"slsa_level"`
	GoVersion   string `json:"go_version"`
	OS          string `json:"os"`
	Arch        string `json:"arch"`
}

type DataItem struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"`
}

func healthHandler(c *gin.Context) {
	reqID := uuid.New().String()
	log.WithFields(logrus.Fields{
		"request_id": reqID,
		"endpoint":   "/health",
	}).Info("Health check requested")

	c.JSON(http.StatusOK, HealthResponse{
		Status:    "ok",
		Uptime:    time.Since(startTime).String(),
		RequestID: reqID,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	})
}

func versionHandler(c *gin.Context) {
	c.JSON(http.StatusOK, VersionResponse{
		Version:     AppVersion,
		BuildCommit: BuildCommit,
		BuildTime:   BuildTime,
		SLSALevel:   SLSALevel,
		GoVersion:   runtime.Version(),
		OS:          runtime.GOOS,
		Arch:        runtime.GOARCH,
	})
}

func dataHandler(c *gin.Context) {
	items := []DataItem{
		{ID: uuid.New().String(), Name: "SLSA Level 3 Build", Status: "verified"},
		{ID: uuid.New().String(), Name: "Cosign Signature", Status: "valid"},
		{ID: uuid.New().String(), Name: "CycloneDX SBOM", Status: "attested"},
		{ID: uuid.New().String(), Name: "Falco Runtime Monitor", Status: "active"},
		{ID: uuid.New().String(), Name: "Provenance Enrichment", Status: "enriched"},
	}
	c.JSON(http.StatusOK, gin.H{"items": items, "count": len(items)})
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Recovery())

	r.Use(func(c *gin.Context) {
		start := time.Now()
		c.Next()
		log.WithFields(logrus.Fields{
			"method":   c.Request.Method,
			"path":     c.Request.URL.Path,
			"status":   c.Writer.Status(),
			"duration": time.Since(start).Milliseconds(),
		}).Info("request")
	})

	r.GET("/health", healthHandler)
	r.GET("/version", versionHandler)
	r.GET("/api/data", dataHandler)

	log.WithField("port", port).Info("Starting cnd-demo-app")
	if err := r.Run(fmt.Sprintf(":%s", port)); err != nil {
		log.WithError(err).Fatal("Server failed")
	}
}

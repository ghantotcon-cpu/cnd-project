package main

  import (
  	"encoding/json"
  	"fmt"
  	"net/http"
  	"os"
  	"runtime"
  	"time"
  )

  var (
  	BuildCommit = "unknown"
  	BuildTime   = "unknown"
  	AppVersion  = "1.0.0"
  	SLSALevel   = "3"
  	startTime   = time.Now()
  )

  func writeJSON(w http.ResponseWriter, status int, v any) {
  	w.Header().Set("Content-Type", "application/json")
  	w.WriteHeader(status)
  	_ = json.NewEncoder(w).Encode(v)
  }

  func healthHandler(w http.ResponseWriter, r *http.Request) {
  	writeJSON(w, http.StatusOK, map[string]string{
  		"status":    "ok",
  		"uptime":    time.Since(startTime).String(),
  		"timestamp": time.Now().UTC().Format(time.RFC3339),
  	})
  }

  func versionHandler(w http.ResponseWriter, r *http.Request) {
  	writeJSON(w, http.StatusOK, map[string]string{
  		"version":      AppVersion,
  		"build_commit": BuildCommit,
  		"build_time":   BuildTime,
  		"slsa_level":   SLSALevel,
  		"go_version":   runtime.Version(),
  		"os":           runtime.GOOS,
  		"arch":         runtime.GOARCH,
  	})
  }

  func dataHandler(w http.ResponseWriter, r *http.Request) {
  	items := []map[string]string{
  		{"id": "1", "name": "SLSA Level 3 Build", "status": "verified"},
  		{"id": "2", "name": "Cosign Signature", "status": "valid"},
  		{"id": "3", "name": "CycloneDX SBOM", "status": "attested"},
  		{"id": "4", "name": "Falco Runtime Monitor", "status": "active"},
  		{"id": "5", "name": "Kyverno Admission", "status": "enforcing"},
  	}
  	writeJSON(w, http.StatusOK, map[string]any{
  		"items": items,
  		"count": len(items),
  	})
  }

  func main() {
  	port := os.Getenv("PORT")
  	if port == "" {
  		port = "8080"
  	}

  	mux := http.NewServeMux()
  	mux.HandleFunc("/health", healthHandler)
  	mux.HandleFunc("/version", versionHandler)
  	mux.HandleFunc("/api/data", dataHandler)
  	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
  		writeJSON(w, http.StatusOK, map[string]string{
  			"service":    "cnd-demo-app",
  			"version":    AppVersion,
  			"slsa_level": SLSALevel,
  			"status":     "healthy",
  		})
  	})

  	fmt.Printf("CND Demo App starting on :%s\n", port)
  	if err := http.ListenAndServe(":"+port, mux); err != nil {
  		fmt.Fprintf(os.Stderr, "Server failed: %v\n", err)
  		os.Exit(1)
  	}
  }
  
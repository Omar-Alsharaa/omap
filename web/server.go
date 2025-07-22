package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	"github.com/rs/cors"

	"omap/fingerprint"
	"omap/network"
	"omap/plugins"
	"omap/scanner"
)

type WebServer struct {
	port       int
	staticDir  string
	upgrader   websocket.Upgrader
	clients    map[*websocket.Conn]bool
	clientsMux sync.RWMutex
	scanner    *scanner.AsyncScanner
	osDetector *fingerprint.OSDetector
	svcDetector *fingerprint.ServiceDetector
	pluginMgr  *plugins.PluginManager
	activeScan *ActiveScan
	scanMux    sync.RWMutex
}

type ActiveScan struct {
	ID        string                 `json:"id"`
	Config    ScanRequest           `json:"config"`
	Status    string                `json:"status"`
	Progress  float64               `json:"progress"`
	Stats     ScanStats             `json:"stats"`
	Results   []ScanResult          `json:"results"`
	StartTime time.Time             `json:"startTime"`
	EndTime   *time.Time            `json:"endTime,omitempty"`
	Error     string                `json:"error,omitempty"`
}

type ScanRequest struct {
	Targets          string `json:"targets"`
	Ports            string `json:"ports"`
	Workers          int    `json:"workers"`
	Timeout          int    `json:"timeout"`
	RateLimit        int    `json:"rateLimit"`
	ConnectOnly      bool   `json:"connectOnly"`
	OSDetection      bool   `json:"osDetection"`
	ServiceDetection bool   `json:"serviceDetection"`
	EnablePlugins    bool   `json:"enablePlugins"`
	PluginPaths      []string `json:"pluginPaths"`
	Verbose          bool   `json:"verbose"`
}

type ScanStats struct {
	TotalHosts   int `json:"totalHosts"`
	ScannedHosts int `json:"scannedHosts"`
	TotalPorts   int `json:"totalPorts"`
	ScannedPorts int `json:"scannedPorts"`
	OpenPorts    int `json:"openPorts"`
	StartTime    time.Time `json:"startTime"`
}

type ScanResult struct {
	Host          string                   `json:"host"`
	Port          int                      `json:"port"`
	Status        string                   `json:"status"`
	Service       string                   `json:"service,omitempty"`
	Version       string                   `json:"version,omitempty"`
	Banner        string                   `json:"banner,omitempty"`
	OSFingerprint *fingerprint.OSFingerprint `json:"osFingerprint,omitempty"`
	PluginResults []plugins.PluginResult   `json:"pluginResults,omitempty"`
	Timestamp     time.Time                `json:"timestamp"`
}

type WebSocketMessage struct {
	Type string      `json:"type"`
	Data interface{} `json:"data"`
}

type APIResponse struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}

func NewWebServer(port int, staticDir string) *WebServer {
	return &WebServer{
		port:      port,
		staticDir: staticDir,
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				return true // Allow all origins in development
			},
		},
		clients:     make(map[*websocket.Conn]bool),
		scanner:     scanner.NewAsyncScanner(&scanner.ScanConfig{}),
		osDetector:  fingerprint.NewOSDetector(time.Second * 5),
		svcDetector: fingerprint.NewServiceDetector(),
		pluginMgr:   plugins.NewPluginManager("./plugins/examples"),
	}
}

func (ws *WebServer) Start() error {
	r := mux.NewRouter()

	// API routes
	api := r.PathPrefix("/api").Subrouter()
	api.HandleFunc("/scan", ws.handleStartScan).Methods("POST")
	api.HandleFunc("/scan/stop", ws.handleStopScan).Methods("POST")
	api.HandleFunc("/scan/status", ws.handleScanStatus).Methods("GET")
	api.HandleFunc("/scan/results", ws.handleScanResults).Methods("GET")
	api.HandleFunc("/plugins", ws.handleListPlugins).Methods("GET")
	api.HandleFunc("/presets/ports", ws.handlePortPresets).Methods("GET")
	api.HandleFunc("/export/{format}", ws.handleExport).Methods("POST")

	// WebSocket endpoint
	r.HandleFunc("/ws", ws.handleWebSocket)

	// Static file serving
	if ws.staticDir != "" {
		r.PathPrefix("/").Handler(http.FileServer(http.Dir(ws.staticDir)))
	}

	// CORS middleware
	c := cors.New(cors.Options{
		AllowedOrigins: []string{"*"},
		AllowedMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders: []string{"*"},
		AllowCredentials: true,
	})

	handler := c.Handler(r)

	log.Printf("Starting web server on port %d", ws.port)
	if ws.staticDir != "" {
		log.Printf("Serving static files from: %s", ws.staticDir)
	}

	return http.ListenAndServe(fmt.Sprintf(":%d", ws.port), handler)
}

func (ws *WebServer) handleStartScan(w http.ResponseWriter, r *http.Request) {
	var req ScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		ws.sendError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	ws.scanMux.Lock()
	if ws.activeScan != nil && ws.activeScan.Status == "running" {
		ws.scanMux.Unlock()
		ws.sendError(w, "A scan is already running", http.StatusConflict)
		return
	}

	// Create new active scan
	ws.activeScan = &ActiveScan{
		ID:        fmt.Sprintf("scan_%d", time.Now().Unix()),
		Config:    req,
		Status:    "running",
		Progress:  0,
		Results:   make([]ScanResult, 0),
		StartTime: time.Now(),
		Stats: ScanStats{
			StartTime: time.Now(),
		},
	}
	ws.scanMux.Unlock()

	// Start scan in goroutine
	go ws.runScan(req)

	ws.sendSuccess(w, map[string]string{"scanId": ws.activeScan.ID})
}

func (ws *WebServer) handleStopScan(w http.ResponseWriter, r *http.Request) {
	ws.scanMux.Lock()
	defer ws.scanMux.Unlock()

	if ws.activeScan == nil || ws.activeScan.Status != "running" {
		ws.sendError(w, "No active scan to stop", http.StatusBadRequest)
		return
	}

	ws.activeScan.Status = "cancelled"
	now := time.Now()
	ws.activeScan.EndTime = &now

	ws.sendSuccess(w, map[string]string{"message": "Scan stopped"})
}

func (ws *WebServer) handleScanStatus(w http.ResponseWriter, r *http.Request) {
	ws.scanMux.RLock()
	defer ws.scanMux.RUnlock()

	if ws.activeScan == nil {
		ws.sendSuccess(w, map[string]interface{}{
			"status": "idle",
			"scan":   nil,
		})
		return
	}

	ws.sendSuccess(w, map[string]interface{}{
		"status": ws.activeScan.Status,
		"scan":   ws.activeScan,
	})
}

func (ws *WebServer) handleScanResults(w http.ResponseWriter, r *http.Request) {
	ws.scanMux.RLock()
	defer ws.scanMux.RUnlock()

	if ws.activeScan == nil {
		ws.sendSuccess(w, []ScanResult{})
		return
	}

	ws.sendSuccess(w, ws.activeScan.Results)
}

func (ws *WebServer) handleListPlugins(w http.ResponseWriter, r *http.Request) {
	pluginDir := "../plugins/examples"
	plugins := make([]map[string]string, 0)

	if _, err := os.Stat(pluginDir); err == nil {
		filepath.Walk(pluginDir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if strings.HasSuffix(info.Name(), ".lua") {
				plugins = append(plugins, map[string]string{
					"name": strings.TrimSuffix(info.Name(), ".lua"),
					"path": path,
				})
			}
			return nil
		})
	}

	ws.sendSuccess(w, plugins)
}

func (ws *WebServer) handlePortPresets(w http.ResponseWriter, r *http.Request) {
	presets := map[string]interface{}{
		"top-100":  network.GetCommonPortSets()["top-100"],
		"common":   network.GetCommonPortSets()["common"],
		"web":      network.GetCommonPortSets()["web"],
		"database": network.GetCommonPortSets()["database"],
		"mail":     network.GetCommonPortSets()["mail"],
	}

	ws.sendSuccess(w, presets)
}

func (ws *WebServer) handleExport(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	format := vars["format"]

	var results []ScanResult
	if err := json.NewDecoder(r.Body).Decode(&results); err != nil {
		ws.sendError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	switch format {
	case "json":
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", "attachment; filename=scan_results.json")
		json.NewEncoder(w).Encode(results)
	case "csv":
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", "attachment; filename=scan_results.csv")
		ws.exportCSV(w, results)
	case "html":
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Content-Disposition", "attachment; filename=scan_results.html")
		ws.exportHTML(w, results)
	default:
		ws.sendError(w, "Unsupported export format", http.StatusBadRequest)
	}
}

func (ws *WebServer) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := ws.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade error: %v", err)
		return
	}
	defer conn.Close()

	ws.clientsMux.Lock()
	ws.clients[conn] = true
	ws.clientsMux.Unlock()

	defer func() {
		ws.clientsMux.Lock()
		delete(ws.clients, conn)
		ws.clientsMux.Unlock()
	}()

	// Send current scan status
	ws.scanMux.RLock()
	if ws.activeScan != nil {
		ws.sendToClient(conn, "scan_status", ws.activeScan)
	}
	ws.scanMux.RUnlock()

	// Keep connection alive
	for {
		_, _, err := conn.ReadMessage()
		if err != nil {
			break
		}
	}
}

func (ws *WebServer) runScan(req ScanRequest) {
	defer func() {
		ws.scanMux.Lock()
		if ws.activeScan.Status == "running" {
			ws.activeScan.Status = "completed"
		}
		now := time.Now()
		ws.activeScan.EndTime = &now
		ws.scanMux.Unlock()

		ws.broadcastToClients("scan_complete", ws.activeScan)
	}()

	// Parse targets
	targetParser := network.NewTargetParser()
	targets, err := targetParser.ParseTargets(req.Targets)
	if err != nil {
		ws.setScanError(fmt.Sprintf("Failed to parse targets: %v", err))
		return
	}

	// Parse ports
	ports, err := ws.parsePorts(req.Ports)
	if err != nil {
		ws.setScanError(fmt.Sprintf("Failed to parse ports: %v", err))
		return
	}

	// Update stats
	ws.scanMux.Lock()
	ws.activeScan.Stats.TotalHosts = len(targets)
	ws.activeScan.Stats.TotalPorts = len(targets) * len(ports)
	ws.scanMux.Unlock()

	// Configure scanner
	config := scanner.ScanConfig{
		Workers:   req.Workers,
		Timeout:   time.Duration(req.Timeout) * time.Millisecond,
		RateLimit: time.Duration(req.RateLimit) * time.Millisecond,
	}

	// Load plugins if enabled
	if req.EnablePlugins {
		for _, pluginPath := range req.PluginPaths {
			if err := ws.pluginMgr.LoadPlugin(pluginPath); err != nil {
				log.Printf("Failed to load plugin %s: %v", pluginPath, err)
			}
		}
	}

	// Scan each target
	for i, target := range targets {
		ws.scanMux.RLock()
		if ws.activeScan.Status != "running" {
			ws.scanMux.RUnlock()
			break
		}
		ws.scanMux.RUnlock()

		// Scan ports for this target
		results := ws.scanner.ScanPorts(target.IP.String(), ports)

		for _, result := range results {
			ws.scanMux.RLock()
			if ws.activeScan.Status != "running" {
				ws.scanMux.RUnlock()
				break
			}
			ws.scanMux.RUnlock()

			scanResult := ScanResult{
				Host:      result.Host,
				Port:      result.Port,
				Status:    result.Status,
				Service:   result.Service,
				Version:   result.Version,
				Banner:    result.Banner,
				Timestamp: time.Now(),
			}

			// OS Detection
			if req.OSDetection && result.Status == "open" {
				if osInfo := ws.osDetector.DetectOS(result.Host, result.Port, result.Banner); osInfo != nil {
					scanResult.OSFingerprint = osInfo
				}
			}

			// Service Detection
			if req.ServiceDetection && result.Banner != "" {
				if svcInfo := ws.svcDetector.DetectService(result.Banner); svcInfo != nil {
					scanResult.Service = svcInfo.Service
					scanResult.Version = svcInfo.Version
				}
			}

			// Plugin execution
			if req.EnablePlugins && result.Status == "open" {
				context := plugins.ScanContext{
					Host:    result.Host,
					Port:    result.Port,
					Service: result.Service,
					Banner:  result.Banner,
				}
				pluginResults := ws.pluginMgr.ExecutePlugins(context)
				scanResult.PluginResults = pluginResults
			}

			// Update scan results
			ws.scanMux.Lock()
			ws.activeScan.Results = append(ws.activeScan.Results, scanResult)
			ws.activeScan.Stats.ScannedPorts++
			if result.Status == "open" {
				ws.activeScan.Stats.OpenPorts++
			}
			ws.activeScan.Progress = float64(ws.activeScan.Stats.ScannedPorts) / float64(ws.activeScan.Stats.TotalPorts) * 100
			ws.scanMux.Unlock()

			// Broadcast update
			ws.broadcastToClients("scan_progress", map[string]interface{}{
				"progress": ws.activeScan.Progress,
				"stats":    ws.activeScan.Stats,
				"result":   scanResult,
			})
		}

		// Update host progress
		ws.scanMux.Lock()
		ws.activeScan.Stats.ScannedHosts = i + 1
		ws.scanMux.Unlock()
	}
}

func (ws *WebServer) parsePorts(portStr string) ([]int, error) {
	// Handle preset port lists
	presets := network.GetCommonPorts()
	if ports, exists := presets[portStr]; exists {
		return ports, nil
	}

	// Parse custom port specification
	return network.ParsePortRange(portStr)
}

func (ws *WebServer) setScanError(errMsg string) {
	ws.scanMux.Lock()
	defer ws.scanMux.Unlock()

	if ws.activeScan != nil {
		ws.activeScan.Status = "failed"
		ws.activeScan.Error = errMsg
		now := time.Now()
		ws.activeScan.EndTime = &now
	}

	ws.broadcastToClients("scan_error", map[string]string{"error": errMsg})
}

func (ws *WebServer) sendToClient(conn *websocket.Conn, msgType string, data interface{}) {
	msg := WebSocketMessage{
		Type: msgType,
		Data: data,
	}
	conn.WriteJSON(msg)
}

func (ws *WebServer) broadcastToClients(msgType string, data interface{}) {
	msg := WebSocketMessage{
		Type: msgType,
		Data: data,
	}

	ws.clientsMux.RLock()
	defer ws.clientsMux.RUnlock()

	for client := range ws.clients {
		if err := client.WriteJSON(msg); err != nil {
			client.Close()
			delete(ws.clients, client)
		}
	}
}

func (ws *WebServer) sendSuccess(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(APIResponse{
		Success: true,
		Data:    data,
	})
}

func (ws *WebServer) sendError(w http.ResponseWriter, errMsg string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(APIResponse{
		Success: false,
		Error:   errMsg,
	})
}

func (ws *WebServer) exportCSV(w http.ResponseWriter, results []ScanResult) {
	fmt.Fprintf(w, "Host,Port,Status,Service,Version,Banner,Timestamp\n")
	for _, result := range results {
		fmt.Fprintf(w, "%s,%d,%s,%s,%s,\"%s\",%s\n",
			result.Host,
			result.Port,
			result.Status,
			result.Service,
			result.Version,
			strings.ReplaceAll(result.Banner, "\"", "\\\""),
			result.Timestamp.Format(time.RFC3339),
		)
	}
}

func (ws *WebServer) exportHTML(w http.ResponseWriter, results []ScanResult) {
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
	<title>OMAP Scan Results</title>
	<style>
		body { font-family: Arial, sans-serif; margin: 20px; }
		table { border-collapse: collapse; width: 100%%; }
		th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
		th { background-color: #f2f2f2; }
		.open { color: green; font-weight: bold; }
		.closed { color: red; }
		.filtered { color: orange; }
	</style>
</head>
<body>
	<h1>OMAP Scan Results</h1>
	<p>Generated: %s</p>
	<table>
		<tr>
			<th>Host</th>
			<th>Port</th>
			<th>Status</th>
			<th>Service</th>
			<th>Version</th>
			<th>Banner</th>
			<th>Timestamp</th>
		</tr>
`, time.Now().Format(time.RFC3339))

	for _, result := range results {
		statusClass := result.Status
		fmt.Fprintf(w, `		<tr>
			<td>%s</td>
			<td>%d</td>
			<td class="%s">%s</td>
			<td>%s</td>
			<td>%s</td>
			<td>%s</td>
			<td>%s</td>
		</tr>
`,
			result.Host,
			result.Port,
			statusClass,
			result.Status,
			result.Service,
			result.Version,
			result.Banner,
			result.Timestamp.Format(time.RFC3339),
		)
	}

	fmt.Fprintf(w, `	</table>
</body>
</html>`)
}

func main() {
	port := 8080
	if len(os.Args) > 1 {
		if p, err := strconv.Atoi(os.Args[1]); err == nil {
			port = p
		}
	}

	staticDir := "./build"
	if len(os.Args) > 2 {
		staticDir = os.Args[2]
	}

	server := NewWebServer(port, staticDir)
	log.Fatal(server.Start())
}
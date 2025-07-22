package plugins

import (
	"context"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strings"
	"sync"
	"time"

	lua "github.com/yuin/gopher-lua"
)

// PluginResult represents the result of a plugin execution
type PluginResult struct {
	PluginName string
	Host       string
	Port       int
	Success    bool
	Summary    string
	Details    map[string]interface{}
	Severity   string
	Data       map[string]interface{}
	Error      error
	Duration   time.Duration
}

// ScanContext provides context information to plugins
type ScanContext struct {
	Host    string
	Port    int
	Banner  string
	Service string
	Timeout time.Duration
}

// Plugin represents a loaded plugin
type Plugin struct {
	Name        string
	Description string
	Author      string
	Version     string
	FilePath    string
	Script      string
	Categories  []string
	Ports       []int // Specific ports this plugin targets
	Services    []string // Specific services this plugin targets
}

// PluginManager manages the plugin system
type PluginManager struct {
	plugins     map[string]*Plugin
	pluginDir   string
	mutex       sync.RWMutex
	timeout     time.Duration
	maxPlugins  int
}

// NewPluginManager creates a new plugin manager
func NewPluginManager(pluginDir string) *PluginManager {
	return &PluginManager{
		plugins:    make(map[string]*Plugin),
		pluginDir:  pluginDir,
		timeout:    30 * time.Second,
		maxPlugins: 100,
	}
}

// LoadPlugins loads all plugins from the plugin directory
func (pm *PluginManager) LoadPlugins() error {
	files, err := ioutil.ReadDir(pm.pluginDir)
	if err != nil {
		return fmt.Errorf("failed to read plugin directory: %v", err)
	}
	
	for _, file := range files {
		if !file.IsDir() && strings.HasSuffix(file.Name(), ".lua") {
			pluginPath := filepath.Join(pm.pluginDir, file.Name())
			if err := pm.LoadPlugin(pluginPath); err != nil {
				fmt.Printf("Warning: Failed to load plugin %s: %v\n", file.Name(), err)
			}
		}
	}
	
	return nil
}

// LoadPlugin loads a single plugin from a file
func (pm *PluginManager) LoadPlugin(filePath string) error {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()
	
	if len(pm.plugins) >= pm.maxPlugins {
		return fmt.Errorf("maximum number of plugins (%d) reached", pm.maxPlugins)
	}
	
	content, err := ioutil.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read plugin file: %v", err)
	}
	
	plugin, err := pm.parsePlugin(string(content), filePath)
	if err != nil {
		return fmt.Errorf("failed to parse plugin: %v", err)
	}
	
	pm.plugins[plugin.Name] = plugin
	return nil
}

// parsePlugin parses a Lua plugin and extracts metadata
func (pm *PluginManager) parsePlugin(script, filePath string) (*Plugin, error) {
	L := lua.NewState()
	defer L.Close()
	
	// Set up plugin metadata table
	L.SetGlobal("plugin", L.NewTable())
	
	// Execute the script to extract metadata
	if err := L.DoString(script); err != nil {
		return nil, fmt.Errorf("failed to execute plugin script: %v", err)
	}
	
	// Extract plugin metadata
	pluginTable := L.GetGlobal("plugin")
	if pluginTable.Type() != lua.LTTable {
		return nil, fmt.Errorf("plugin metadata table not found")
	}
	
	table := pluginTable.(*lua.LTable)
	plugin := &Plugin{
		FilePath: filePath,
		Script:   script,
	}
	
	// Extract metadata fields
	if name := L.GetField(table, "name"); name.Type() == lua.LTString {
		plugin.Name = name.String()
	} else {
		return nil, fmt.Errorf("plugin name is required")
	}
	
	if desc := L.GetField(table, "description"); desc.Type() == lua.LTString {
		plugin.Description = desc.String()
	}
	
	if author := L.GetField(table, "author"); author.Type() == lua.LTString {
		plugin.Author = author.String()
	}
	
	if version := L.GetField(table, "version"); version.Type() == lua.LTString {
		plugin.Version = version.String()
	}
	
	// Extract categories
	if categories := L.GetField(table, "categories"); categories.Type() == lua.LTTable {
		catTable := categories.(*lua.LTable)
		catTable.ForEach(func(_, value lua.LValue) {
			if value.Type() == lua.LTString {
				plugin.Categories = append(plugin.Categories, value.String())
			}
		})
	}
	
	// Extract target ports
	if ports := L.GetField(table, "ports"); ports.Type() == lua.LTTable {
		portTable := ports.(*lua.LTable)
		portTable.ForEach(func(_, value lua.LValue) {
			if value.Type() == lua.LTNumber {
				plugin.Ports = append(plugin.Ports, int(value.(lua.LNumber)))
			}
		})
	}
	
	// Extract target services
	if services := L.GetField(table, "services"); services.Type() == lua.LTTable {
		svcTable := services.(*lua.LTable)
		svcTable.ForEach(func(_, value lua.LValue) {
			if value.Type() == lua.LTString {
				plugin.Services = append(plugin.Services, value.String())
			}
		})
	}
	
	return plugin, nil
}

// ExecutePlugin executes a plugin against a target
func (pm *PluginManager) ExecutePlugin(pluginName string, ctx ScanContext) PluginResult {
	start := time.Now()
	result := PluginResult{
		PluginName: pluginName,
		Host:       ctx.Host,
		Port:       ctx.Port,
		Data:       make(map[string]interface{}),
	}
	
	pm.mutex.RLock()
	plugin, exists := pm.plugins[pluginName]
	pm.mutex.RUnlock()
	
	if !exists {
		result.Error = fmt.Errorf("plugin %s not found", pluginName)
		result.Duration = time.Since(start)
		return result
	}
	
	// Execute plugin with timeout
	ctxWithTimeout, cancel := context.WithTimeout(context.Background(), pm.timeout)
	defer cancel()
	
	done := make(chan PluginResult, 1)
	go func() {
		done <- pm.executePluginScript(plugin, ctx)
	}()
	
	select {
	case result = <-done:
		result.Duration = time.Since(start)
		return result
	case <-ctxWithTimeout.Done():
		result.Error = fmt.Errorf("plugin execution timeout")
		result.Duration = time.Since(start)
		return result
	}
}

// executePluginScript executes the actual plugin script
func (pm *PluginManager) executePluginScript(plugin *Plugin, ctx ScanContext) PluginResult {
	result := PluginResult{
		PluginName: plugin.Name,
		Host:       ctx.Host,
		Port:       ctx.Port,
		Data:       make(map[string]interface{}),
	}
	
	L := lua.NewState()
	defer L.Close()
	
	// Set up the Lua environment
	pm.setupLuaEnvironment(L, ctx)
	
	// Execute the plugin script
	if err := L.DoString(plugin.Script); err != nil {
		result.Error = fmt.Errorf("plugin execution error: %v", err)
		return result
	}
	
	// Call the main function if it exists
	if fn := L.GetGlobal("run"); fn.Type() == lua.LTFunction {
		if err := L.CallByParam(lua.P{
			Fn:      fn,
			NRet:    1,
			Protect: true,
		}); err != nil {
			result.Error = fmt.Errorf("plugin run function error: %v", err)
			return result
		}
		
		// Get the result
		ret := L.Get(-1)
		L.Pop(1)
		
		if ret.Type() == lua.LTTable {
			resultTable := ret.(*lua.LTable)
			pm.extractResultData(resultTable, result.Data)
			result.Success = true
		} else if ret.Type() == lua.LTBool {
			result.Success = bool(ret.(lua.LBool))
		}
	} else {
		result.Error = fmt.Errorf("plugin does not have a 'run' function")
	}
	
	return result
}

// setupLuaEnvironment sets up the Lua environment with helper functions
func (pm *PluginManager) setupLuaEnvironment(L *lua.LState, ctx ScanContext) {
	// Set context variables
	contextTable := L.NewTable()
	L.SetField(contextTable, "host", lua.LString(ctx.Host))
	L.SetField(contextTable, "port", lua.LNumber(ctx.Port))
	L.SetField(contextTable, "banner", lua.LString(ctx.Banner))
	L.SetField(contextTable, "service", lua.LString(ctx.Service))
	L.SetGlobal("context", contextTable)
	
	// Helper functions
	L.SetGlobal("http_get", L.NewFunction(pm.luaHTTPGet))
	L.SetGlobal("tcp_connect", L.NewFunction(pm.luaTCPConnect))
	L.SetGlobal("regex_match", L.NewFunction(pm.luaRegexMatch))
	L.SetGlobal("log", L.NewFunction(pm.luaLog))
}

// Lua helper functions
func (pm *PluginManager) luaHTTPGet(L *lua.LState) int {
	url := L.ToString(1)
	// Implement HTTP GET functionality
	// This is a placeholder - would implement actual HTTP client
	L.Push(lua.LString(fmt.Sprintf("HTTP GET result for %s", url)))
	return 1
}

func (pm *PluginManager) luaTCPConnect(L *lua.LState) int {
	host := L.ToString(1)
	port := L.ToInt(2)
	// Implement TCP connection functionality
	// This is a placeholder - would implement actual TCP client
	L.Push(lua.LBool(true))
	L.Push(lua.LString(fmt.Sprintf("Connected to %s:%d", host, port)))
	return 2
}

func (pm *PluginManager) luaRegexMatch(L *lua.LState) int {
	pattern := L.ToString(1)
	text := L.ToString(2)
	// Implement regex matching
	// This is a placeholder - would implement actual regex
	L.Push(lua.LBool(strings.Contains(text, pattern)))
	return 1
}

func (pm *PluginManager) luaLog(L *lua.LState) int {
	message := L.ToString(1)
	fmt.Printf("[Plugin Log] %s\n", message)
	return 0
}

// extractResultData extracts data from Lua table to Go map
func (pm *PluginManager) extractResultData(table *lua.LTable, data map[string]interface{}) {
	table.ForEach(func(key, value lua.LValue) {
		keyStr := key.String()
		switch value.Type() {
		case lua.LTString:
			data[keyStr] = value.String()
		case lua.LTNumber:
			data[keyStr] = float64(value.(lua.LNumber))
		case lua.LTBool:
			data[keyStr] = bool(value.(lua.LBool))
		case lua.LTTable:
			nestedData := make(map[string]interface{})
			pm.extractResultData(value.(*lua.LTable), nestedData)
			data[keyStr] = nestedData
		}
	})
}

// GetPlugins returns a list of loaded plugins
func (pm *PluginManager) GetPlugins() map[string]*Plugin {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()
	
	plugins := make(map[string]*Plugin)
	for name, plugin := range pm.plugins {
		plugins[name] = plugin
	}
	return plugins
}

// GetPluginsByCategory returns plugins filtered by category
func (pm *PluginManager) GetPluginsByCategory(category string) []*Plugin {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()
	
	var plugins []*Plugin
	for _, plugin := range pm.plugins {
		for _, cat := range plugin.Categories {
			if cat == category {
				plugins = append(plugins, plugin)
				break
			}
		}
	}
	return plugins
}

// GetPluginsForPort returns plugins that target a specific port
func (pm *PluginManager) GetPluginsForPort(port int) []*Plugin {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()
	
	var plugins []*Plugin
	for _, plugin := range pm.plugins {
		// If no specific ports defined, plugin runs on all ports
		if len(plugin.Ports) == 0 {
			plugins = append(plugins, plugin)
			continue
		}
		
		// Check if plugin targets this specific port
		for _, targetPort := range plugin.Ports {
			if targetPort == port {
				plugins = append(plugins, plugin)
				break
			}
		}
	}
	return plugins
}

// GetPluginsForService returns plugins that target a specific service
func (pm *PluginManager) GetPluginsForService(service string) []*Plugin {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()
	
	var plugins []*Plugin
	for _, plugin := range pm.plugins {
		// If no specific services defined, plugin runs on all services
		if len(plugin.Services) == 0 {
			plugins = append(plugins, plugin)
			continue
		}
		
		// Check if plugin targets this specific service
		for _, targetService := range plugin.Services {
			if strings.EqualFold(targetService, service) {
				plugins = append(plugins, plugin)
				break
			}
		}
	}
	return plugins
}

// ExecutePluginsForTarget executes all applicable plugins for a target
func (pm *PluginManager) ExecutePluginsForTarget(ctx ScanContext) []PluginResult {
	var results []PluginResult
	
	// Get plugins for the specific port and service
	portPlugins := pm.GetPluginsForPort(ctx.Port)
	servicePlugins := pm.GetPluginsForService(ctx.Service)
	
	// Combine and deduplicate plugins
	pluginMap := make(map[string]*Plugin)
	for _, plugin := range portPlugins {
		pluginMap[plugin.Name] = plugin
	}
	for _, plugin := range servicePlugins {
		pluginMap[plugin.Name] = plugin
	}
	
	// Execute each plugin
	for _, plugin := range pluginMap {
		result := pm.ExecutePlugin(plugin.Name, ctx)
		results = append(results, result)
	}
	
	return results
}

// SetTimeout sets the plugin execution timeout
func (pm *PluginManager) SetTimeout(timeout time.Duration) {
	pm.timeout = timeout
}

// UnloadPlugin removes a plugin from the manager
func (pm *PluginManager) UnloadPlugin(name string) error {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()
	
	if _, exists := pm.plugins[name]; !exists {
		return fmt.Errorf("plugin %s not found", name)
	}
	
	delete(pm.plugins, name)
	return nil
}
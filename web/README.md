# OMAP Web Interface

A modern, responsive web interface for the OMAP network scanner built with React and Go.

## Features

### 🎯 **Scan Management**
- **Interactive Scan Configuration**: Easy-to-use form with target and port specification
- **Real-time Progress Tracking**: Live updates with progress bars and statistics
- **Scan History**: Track and review previous scans
- **Export Results**: JSON, CSV, and HTML export formats

### 🔍 **Advanced Scanning**
- **Multi-target Support**: CIDR ranges, IP ranges, and hostname lists
- **Port Presets**: Common, top-100, web, database, and mail port lists
- **Custom Port Ranges**: Flexible port specification (e.g., 1-1000, 80,443,8080)
- **Plugin System**: Lua-based vulnerability detection and service enumeration
- **OS/Service Detection**: Automated fingerprinting and banner grabbing

### 📊 **Results & Analytics**
- **Interactive Dashboard**: Scan statistics and activity charts
- **Detailed Results View**: Filterable and sortable scan results
- **Risk Assessment**: Basic security risk indicators
- **Service Discovery**: Comprehensive service and version detection

### 🎨 **User Experience**
- **Dark/Light Mode**: Automatic theme switching
- **Responsive Design**: Works on desktop, tablet, and mobile
- **Real-time Updates**: WebSocket-based live scan updates
- **Progressive Web App**: Install as a desktop/mobile app

## Quick Start

### Prerequisites

- **Node.js 16+** (for building the React app)
- **Go 1.19+** (for the backend server)
- **Modern Web Browser** (Chrome, Firefox, Safari, Edge)

### Automated Build

```powershell
# Run the automated build script
.\build-web.ps1
```

This script will:
1. Install Node.js if not present
2. Install npm dependencies
3. Build the React application
4. Compile the Go web server
5. Verify the build

### Manual Build

```bash
# Install dependencies
npm install

# Build React app
npm run build

# Build Go server
go build -o omap-web.exe server.go
```

### Starting the Server

```powershell
# Start with default settings (port 8080)
.\omap-web.exe

# Start on custom port
.\omap-web.exe 3000

# Custom port and static directory
.\omap-web.exe 8080 ./build
```

Then open your browser to `http://localhost:8080`

## Usage Guide

### 1. **Starting a Scan**

1. Navigate to the **New Scan** tab
2. Enter your targets:
   ```
   # Single host
   192.168.1.1
   
   # Multiple hosts
   192.168.1.1,192.168.1.2,google.com
   
   # CIDR range
   192.168.1.0/24
   
   # IP range
   192.168.1.1-192.168.1.50
   ```

3. Select port configuration:
   - **Presets**: top-100, common, web, database, mail
   - **Custom**: 80,443,8080 or 1-1000

4. Configure scan options:
   - **Workers**: Number of concurrent connections (default: 100)
   - **Timeout**: Connection timeout in milliseconds (default: 1000)
   - **Rate Limit**: Requests per second (default: 1000)

5. Enable additional features:
   - ☑️ **OS Detection**: Fingerprint operating systems
   - ☑️ **Service Detection**: Identify services and versions
   - ☑️ **Plugins**: Run vulnerability checks
   - ☑️ **Verbose**: Detailed logging

6. Click **Start Scan**

### 2. **Monitoring Progress**

The **Progress** view shows:
- **Overall Progress**: Completion percentage and ETA
- **Statistics**: Hosts scanned, ports checked, open ports found
- **Live Results**: Real-time discovery of open ports
- **Performance**: Scan rate (ports/second)

### 3. **Viewing Results**

The **Results** tab provides:
- **Summary Statistics**: Total hosts, open ports, services found
- **Filterable Results**: Filter by host, service, or port status
- **Detailed Information**: Service versions, OS fingerprints, plugin results
- **Risk Assessment**: Security risk indicators for discovered services

### 4. **Exporting Data**

Export scan results in multiple formats:
- **JSON**: Machine-readable format for automation
- **CSV**: Spreadsheet-compatible format
- **HTML**: Formatted report for sharing

## API Reference

### REST Endpoints

```http
# Start a new scan
POST /api/scan
Content-Type: application/json

{
  "targets": "192.168.1.0/24",
  "ports": "top-100",
  "workers": 100,
  "timeout": 1000,
  "osDetection": true,
  "serviceDetection": true,
  "enablePlugins": true
}

# Get scan status
GET /api/scan/status

# Stop current scan
POST /api/scan/stop

# Get scan results
GET /api/scan/results

# List available plugins
GET /api/plugins

# Get port presets
GET /api/presets/ports

# Export results
POST /api/export/{format}
Content-Type: application/json

[...scan results...]
```

### WebSocket Events

Connect to `/ws` for real-time updates:

```javascript
const ws = new WebSocket('ws://localhost:8080/ws');

ws.onmessage = (event) => {
  const message = JSON.parse(event.data);
  
  switch (message.type) {
    case 'scan_progress':
      // Update progress bar and statistics
      break;
    case 'scan_complete':
      // Scan finished
      break;
    case 'scan_error':
      // Handle scan error
      break;
  }
};
```

## Configuration

### Environment Variables

```bash
# Server port (default: 8080)
PORT=3000

# Static files directory (default: ./build)
STATIC_DIR=./dist

# Enable CORS for development
CORS_ENABLED=true
```

### Plugin Configuration

Plugins are automatically discovered from:
- `../plugins/examples/` (relative to server)
- Custom paths specified in scan configuration

## Development

### Development Server

```bash
# Start React development server
npm start

# Start Go server in development mode
go run server.go
```

### Building for Production

```bash
# Build optimized React app
npm run build

# Build Go server with optimizations
go build -ldflags="-s -w" -o omap-web.exe server.go
```

### Project Structure

```
web/
├── public/                 # Static assets
│   ├── index.html         # Main HTML template
│   └── manifest.json      # PWA manifest
├── src/                   # React source code
│   ├── components/        # React components
│   ├── context/          # State management
│   ├── App.js            # Main application
│   └── index.js          # Entry point
├── server.go             # Go web server
├── package.json          # Node.js dependencies
├── build-web.ps1         # Build script
└── README.md             # This file
```

## Troubleshooting

### Common Issues

**Build Failures:**
```bash
# Clear npm cache
npm cache clean --force

# Delete node_modules and reinstall
rm -rf node_modules package-lock.json
npm install
```

**Server Won't Start:**
```bash
# Check if port is in use
netstat -an | findstr :8080

# Use different port
.\omap-web.exe 3000
```

**WebSocket Connection Issues:**
- Check firewall settings
- Verify server is running
- Try different browser

**Scan Not Starting:**
- Verify target format
- Check network connectivity
- Review server logs

### Performance Tuning

**For Large Scans:**
- Reduce worker count (50-200)
- Increase timeout (2000-5000ms)
- Lower rate limit (100-500 req/s)
- Disable verbose logging

**For Fast Networks:**
- Increase worker count (500-1000)
- Decrease timeout (500-1000ms)
- Increase rate limit (2000+ req/s)

## Security Considerations

- **Network Access**: Server requires network access for scanning
- **Firewall**: May need firewall exceptions for scanning
- **CORS**: Configured for development; restrict in production
- **Authentication**: No built-in auth; use reverse proxy if needed
- **Rate Limiting**: Built-in rate limiting to prevent network flooding

## Contributing

See the main OMAP project for contribution guidelines.

## License

Same as the main OMAP project.
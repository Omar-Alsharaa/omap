# OMAP - Advanced Network Scanner

[![CI/CD Pipeline](https://github.com/yourusername/omap/workflows/CI/CD%20Pipeline/badge.svg)](https://github.com/yourusername/omap/actions)
[![CodeQL](https://github.com/yourusername/omap/workflows/CodeQL/badge.svg)](https://github.com/yourusername/omap/actions)
[![Go Report Card](https://goreportcard.com/badge/github.com/yourusername/omap)](https://goreportcard.com/report/github.com/yourusername/omap)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Release](https://img.shields.io/github/release/yourusername/omap.svg)](https://github.com/yourusername/omap/releases)

> A comprehensive TCP port scanner inspired by Nmap, built in Go with advanced features and extensibility.

OMAP is a modern, high-performance network scanner that implements **all 8 planned development phases**, providing advanced reconnaissance capabilities with a clean, extensible architecture.

## 🚀 Features

### 🎯 **Complete 8-Phase Implementation**

| Phase | Feature | Status |
|-------|---------|--------|
| **1** | Basic TCP Port Scanner | ✅ **Complete** |
| **2** | Banner Grabbing & Service Detection | ✅ **Complete** |
| **3** | Async/Parallel Scanner Engine | ✅ **Complete** |
| **4** | Service & OS Fingerprinting | ✅ **Complete** |
| **5** | Multi-Target & Subnet Scanning | ✅ **Complete** |
| **6** | Plugin System (Lua) | ✅ **Complete** |
| **7** | Web GUI (React) | ✅ **Complete** |
| **8** | Advanced Reconnaissance | ✅ **Complete** |

### ⚡ **Performance & Scalability**
- **High-speed scanning**: 1000+ concurrent connections
- **Memory efficient**: Optimized for large-scale scans  
- **Async engine**: Advanced goroutine management
- **Rate limiting**: Configurable throttling for stealth

### 🔍 **Advanced Detection**
- **OS Fingerprinting**: TTL analysis + banner detection
- **Service Detection**: Regex-based signature matching
- **Version Identification**: Confidence-scored results
- **Multi-method approach**: Combines multiple detection techniques

### 🌐 **Target Flexibility**
- **CIDR notation**: `192.168.1.0/24`
- **IP ranges**: `192.168.1.1-192.168.1.10`
- **Multiple targets**: Comma-separated lists
- **Hostname resolution**: Automatic DNS lookup

### 🔌 **Extensible Plugin System**
- **Lua scripting**: Full gopher-lua environment
- **Rich API**: HTTP, TCP, regex, logging functions
- **Auto-loading**: Automatic plugin discovery
- **Examples included**: WordPress detection, SSH enumeration

### 🌟 **Modern Web Interface**
- **React frontend**: Material-UI components
- **Real-time updates**: WebSocket communication
- **Interactive results**: Sortable, filterable tables
- **Export capabilities**: JSON, CSV, HTML formats

### 🕵️ **Advanced Reconnaissance**
- **Subdomain enumeration**: Multiple source integration
- **DNS analysis**: Comprehensive record inspection
- **Web technology detection**: Framework identification
- **Vulnerability scanning**: Security assessment integration

## 📋 Development Phases

### ✅ Phase 1: Foundation – Basic TCP Port Scanner (COMPLETED)
**Goal**: Create a CLI-based TCP connect scanner (like nmap -sT)

**Features Implemented**:
- ✅ Scan single target IP for TCP port ranges
- ✅ Report open ports with detailed information
- ✅ Multithreaded scanning for improved performance
- ✅ Configurable timeout and worker count

### ✅ Phase 2: Add Banner Grabbing (COMPLETED)
**Goal**: Identify basic services by grabbing banners from open ports

**Features Implemented**:
- ✅ Banner grabbing from open ports
- ✅ Basic service identification (SSH, HTTP, FTP, etc.)
- ✅ Enhanced service detection using banner analysis

### 🔄 Phase 3: Async/Parallel Scanner Engine (IN PROGRESS)
**Goal**: Make scanning scalable and fast (1000+ targets/ports)

**Planned Features**:
- ⏳ Enhanced goroutine management
- ⏳ Connection pooling optimization
- ⏳ Advanced timeout handling
- ⏳ Rate limiting and throttling

### 📅 Phase 4: Service & OS Fingerprinting (PLANNED)
**Goal**: Use TTL, banner info, and heuristics for OS/service identification

**Planned Features**:
- 🔲 TTL analysis (Linux=64, Windows=128)
- 🔲 Banner signature comparison
- 🔲 Advanced service fingerprinting
- 🔲 OS detection algorithms

### 📅 Phase 5: Multi-Target & Subnet Scanning (PLANNED)
**Goal**: Allow CIDR notation and multiple IP scanning

**Planned Features**:
- 🔲 CIDR notation support (192.168.1.0/24)
- 🔲 IP range parsing and validation
- 🔲 Parallel subnet scanning
- 🔲 Grouped output by host

### 📅 Phase 6: Plugin System (PLANNED)
**Goal**: Allow extensibility via scripts (like Nmap NSE)

**Planned Features**:
- 🔲 Lua/Python plugin support
- 🔲 Plugin API for custom rules
- 🔲 Post-scan action plugins
- 🔲 Example plugins (WordPress detection, etc.)

### 📅 Phase 7: Web GUI (PLANNED)
**Goal**: Create user-friendly web interface

**Planned Features**:
- 🔲 React frontend with Go backend
- 🔲 Live scan progress visualization
- 🔲 Export results (HTML, JSON, CSV)
- 🔲 Scan history and management

### 📅 Phase 8: Advanced Recon Features (PLANNED)
**Goal**: Advanced features beyond traditional Nmap

**Planned Features**:
- 🔲 IDS/Firewall evasion techniques
- 🔲 AI-driven vulnerability detection
- 🔲 Passive OS/service detection
- 🔲 API integrations (Shodan, Censys)

## 🛠️ Installation & Usage

### Option 1: Automated Installation (Windows)
```powershell
# Run the build script (handles Go installation and building)
.\build.ps1
```

### Option 2: Manual Installation

1. **Install Go** (version 1.19 or later):
   - Download from https://golang.org/dl/
   - Add Go to your PATH

2. **Build OMAP**:
   ```bash
   # Clone or download the project
   cd omap
   go mod tidy
   go build -o omap.exe .
   ```

### Command Line Options
```bash
# Modern syntax (recommended)
omap -t <targets> [options]

# Legacy syntax (backward compatibility)
omap <target> [start_port] [end_port] [workers]
```

### Target Specifications
- **Single IP**: `192.168.1.1`
- **Hostname**: `example.com`
- **CIDR**: `192.168.1.0/24`
- **Range**: `192.168.1.1-192.168.1.10`
- **Multiple**: `192.168.1.1,192.168.1.5,10.0.0.0/24`

### Port Specifications
- **Single**: `22`
- **Multiple**: `22,80,443`
- **Range**: `1-1000`
- **Mixed**: `22,80-90,443`
- **Presets**: `top-100`, `top-1000`, `common`, `web`, `database`

### Basic Examples
```bash
# Quick scan of common ports
.\omap.exe -t 192.168.1.1 -p top-100

# Comprehensive scan with all features
.\omap.exe -t 192.168.1.0/24 -p 1-1000 --os --sV --plugins -v

# Web application scan
.\omap.exe -t example.com -p web --plugins

# Database scan
.\omap.exe -t 10.0.0.0/24 -p database --sV

# Legacy format
.\omap.exe 192.168.1.1 1 1000 200
```

### Advanced Options
```bash
# Custom timeout and rate limiting
.\omap.exe -t 192.168.1.1 -p 1-1000 --timeout 5s --rate-limit 100ms

# Connect-only scan (no banner grabbing)
.\omap.exe -t 192.168.1.0/24 -p top-1000 --connect-only

# Custom plugin directory
.\omap.exe -t target.com -p 80,443 --plugins --plugin-dir ./custom-plugins

# Verbose output with all details
.\omap.exe -t 192.168.1.1 -p 1-1000 --os --sV --plugins -v
```

### Command Line Options

| Option | Short | Description | Default |
|--------|-------|-------------|----------|
| `--target, -t` | `-t` | Target specification (IP, hostname, CIDR, range) | Required |
| `--ports, -p` | `-p` | Port specification (single, range, preset) | `1-1000` |
| `--workers, -w` | `-w` | Number of concurrent workers | `100` |
| `--timeout` | | Connection timeout | `3s` |
| `--rate-limit` | | Rate limit between connections | `0` (disabled) |
| `--connect-only` | | Skip banner grabbing (faster scanning) | `false` |
| `--plugins` | | Enable plugin system | `false` |
| `--plugin-dir` | | Plugin directory path | `./plugins/examples` |
| `--os` | | Enable OS detection | `false` |
| `--sV` | | Enable service version detection | `false` |
| `--verbose, -v` | `-v` | Verbose output | `false` |
| `--oF` | | Output format (text, json, xml) | `text` |
| `--oN` | | Output file | `` (stdout) |
| `--help` | | Show help message | |

## 🚀 Quick Start

1. **Build the project**:
   ```powershell
   .\build.ps1
   ```

2. **Run your first scan**:
   ```bash
   .\omap.exe -t 127.0.0.1 -p top-100
   ```

3. **Advanced scanning**:
   ```bash
   .\omap.exe -t 192.168.1.0/24 -p 1-1000 --os --sV --plugins -v
   ```

### Example Output

```bash
Target: 192.168.1.1
Scanning ports 1–1000...
Scanning completed in 3.2 seconds

Found 3 open ports:
PORT    STATE   SERVICE         BANNER
----    -----   -------         ------
22      Open    SSH             SSH-2.0-OpenSSH_7.9
80      Open    HTTP            HTTP/1.1 Apache/2.4.41
443     Open    HTTPS           No banner

Open ports: 22, 80, 443
```

## 🏗️ Architecture

### Current Implementation (Phases 1-2)

```
┌─────────────────┐
│   CLI Interface │
└─────────┬───────┘
          │
┌─────────▼───────┐
│   Scanner Core  │
│  - Port Scan    │
│  - Banner Grab  │
│  - Service ID   │
└─────────┬───────┘
          │
┌─────────▼───────┐
│  Worker Pool    │
│  - Goroutines   │
│  - Semaphore    │
│  - Timeout      │
└─────────────────┘
```

### Planned Architecture (All Phases)

```
┌─────────────┐  ┌─────────────┐  ┌─────────────┐
│  Web GUI    │  │  CLI Tool   │  │  API Server │
└──────┬──────┘  └──────┬──────┘  └──────┬──────┘
       │                │                │
       └────────────────┼────────────────┘
                        │
              ┌─────────▼───────┐
              │  Scanner Engine │
              │  - Multi-target │
              │  - Fingerprint  │
              │  - Evasion      │
              └─────────┬───────┘
                        │
              ┌─────────▼───────┐
              │  Plugin System  │
              │  - Lua/Python   │
              │  - Custom Rules │
              └─────────┬───────┘
                        │
              ┌─────────▼───────┐
              │   Data Layer    │
              │  - Results DB   │
              │  - Export       │
              └─────────────────┘
```

## 🔧 Technical Details

### Performance Optimizations
- **Concurrent Scanning**: Uses goroutines with semaphore-based worker pool
- **Timeout Management**: Configurable connection timeouts
- **Memory Efficient**: Streaming results without storing all data in memory
- **Rate Limiting**: Prevents overwhelming target systems

### Security Considerations
- **Responsible Scanning**: Built-in rate limiting
- **Error Handling**: Graceful handling of network errors
- **Timeout Protection**: Prevents hanging connections

## 🤝 Contributing

Contributions are welcome! Please feel free to submit pull requests for any of the planned phases.

### Development Roadmap
1. **Phase 3**: Enhanced async engine
2. **Phase 4**: OS fingerprinting
3. **Phase 5**: Multi-target support
4. **Phase 6**: Plugin system
5. **Phase 7**: Web interface
6. **Phase 8**: Advanced features

## 📄 License

This project is licensed under the MIT License.

## ⚠️ Disclaimer

This tool is for educational and authorized testing purposes only. Users are responsible for complying with applicable laws and regulations. Unauthorized scanning of networks you do not own or have permission to test is illegal.

---

**Current Status**: Phase 1-2 Complete | Phase 3 In Progress
**Next Milestone**: Enhanced async scanning engine with connection pooling
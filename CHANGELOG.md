# Changelog

All notable changes to OMAP will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial implementation of all 8 planned phases
- Comprehensive documentation and examples

## [1.0.0] - 2025-07-22

### Added
- **Phase 1: Basic TCP Port Scanner**
  - Async TCP connect scanning with configurable workers
  - Connection pooling and timeout management
  - Support for port ranges and individual ports
  - High-performance scanning capabilities (1000+ concurrent connections)

- **Phase 2: Banner Grabbing & Service Detection**
  - Intelligent banner grabbing with timeout controls
  - Service identification for common protocols (SSH, HTTP, FTP, SMTP, etc.)
  - Version detection and confidence scoring
  - Enhanced service mapping based on banners and ports

- **Phase 3: Async/Parallel Scanner Engine**
  - Advanced goroutine management and worker pools
  - Rate limiting and connection throttling
  - Memory-efficient scanning for large networks
  - Retry logic with exponential backoff
  - Connection pooling optimization

- **Phase 4: Service & OS Fingerprinting**
  - TTL-based OS detection (Linux=64, Windows=128, Cisco=255)
  - Banner-based OS fingerprinting with confidence scoring
  - Advanced service detection using regex patterns
  - Multi-method fingerprinting approach
  - Comprehensive service signature database

- **Phase 5: Multi-Target & Subnet Scanning**
  - CIDR notation support (e.g., 192.168.1.0/24)
  - IP range scanning (e.g., 192.168.1.1-192.168.1.10)
  - Multiple target support with comma separation
  - Hostname resolution and DNS lookup
  - Parallel target processing with grouping

- **Phase 6: Plugin System**
  - Full Lua scripting environment using gopher-lua
  - Rich plugin API with HTTP, TCP, regex, and logging support
  - Plugin auto-loading and management system
  - Category-based plugin organization
  - Example plugins: WordPress detection, SSH enumeration
  - Extensible architecture for custom scanning rules

- **Phase 7: Web GUI**
  - Modern React frontend with Material-UI components
  - Real-time WebSocket communication for live updates
  - Interactive scan progress visualization
  - Professional dark theme with hacker aesthetic
  - Export capabilities (JSON, CSV, HTML)
  - Responsive design for all devices
  - Go-based web server with REST API

- **Phase 8: Advanced Recon Features**
  - Comprehensive reconnaissance engine
  - Subdomain enumeration with multiple sources
  - DNS analysis and record inspection
  - Web technology detection and fingerprinting
  - Vulnerability scanning integration
  - Risk assessment and compliance checking
  - API integrations (Shodan, Censys, VirusTotal)
  - Advanced threat intelligence reporting

### Features
- **Command Line Interface**
  - Modern flag-based interface with comprehensive options
  - Backward compatibility with positional arguments
  - Multiple output formats (text, JSON, XML)
  - Verbose and quiet modes
  - Help system with usage examples

- **Target Support**
  - Single IP addresses
  - Hostnames with DNS resolution
  - CIDR notation (192.168.1.0/24)
  - IP ranges (192.168.1.1-10)
  - Multiple targets with comma separation

- **Port Specifications**
  - Individual ports (22, 80, 443)
  - Port ranges (1-1000)
  - Multiple ports (22,80-90,443)
  - Preset port lists (top-100, common, web, database)

- **Performance**
  - Up to 1000+ concurrent connections
  - Configurable timeout and retry settings
  - Rate limiting for stealth scanning
  - Memory-efficient processing

- **Output & Reporting**
  - Comprehensive scan results with statistics
  - Export to multiple formats
  - Real-time progress reporting
  - Detailed error handling and logging

### Technical Details
- **Architecture**: Modular design with clean interfaces
- **Language**: Go 1.21+ with modern practices
- **Frontend**: React 18 with Material-UI
- **Plugin System**: Lua scripting with gopher-lua
- **Dependencies**: Minimal, well-maintained libraries
- **Cross-Platform**: Windows, Linux, macOS support

### Documentation
- Comprehensive README with installation and usage
- Detailed API documentation
- Plugin development guide
- Security best practices
- Contributing guidelines

### Build System
- Automated PowerShell build scripts
- Cross-platform compilation support
- Dependency management with Go modules
- Web interface build integration

### Security
- Input validation on all user inputs
- Rate limiting to prevent abuse
- Timeout controls for all operations
- Secure defaults for all configurations
- Security policy and vulnerability reporting process

---

## Version History Format

### Added
- New features and capabilities

### Changed
- Changes to existing functionality

### Deprecated
- Features that will be removed in future versions

### Removed
- Features that have been removed

### Fixed
- Bug fixes and corrections

### Security
- Security-related improvements and fixes

---

**Note**: This is the initial release implementing all planned phases. Future versions will focus on enhancements, optimizations, and additional features based on community feedback.

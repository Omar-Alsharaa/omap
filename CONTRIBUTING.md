# Contributing to OMAP

Thank you for your interest in contributing to OMAP! This document provides guidelines for contributing to the project.

## 🤝 How to Contribute

### Reporting Issues
- Use the GitHub issue tracker to report bugs
- Include detailed steps to reproduce the issue
- Provide system information (OS, Go version, etc.)
- Include relevant log outputs

### Feature Requests
- Check existing issues before creating new ones
- Clearly describe the proposed feature
- Explain the use case and benefits
- Consider implementation complexity

### Pull Requests
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Update documentation as needed
7. Commit your changes (`git commit -m 'Add amazing feature'`)
8. Push to the branch (`git push origin feature/amazing-feature`)
9. Open a Pull Request

## 🔧 Development Setup

### Prerequisites
- Go 1.19 or later
- Node.js 16+ (for web interface)
- Git

### Setup
```bash
# Clone the repository
git clone https://github.com/yourusername/omap.git
cd omap

# Install Go dependencies
go mod tidy

# Build the project
go build -o omap .

# For web development
cd web
npm install
npm start
```

### Testing
```bash
# Run Go tests
go test ./...

# Run specific package tests
go test ./scanner
go test ./fingerprint

# Test with race detection
go test -race ./...

# Run benchmarks
go test -bench=. ./...
```

## 📝 Code Style

### Go Code
- Follow standard Go conventions (`go fmt`, `go vet`)
- Use meaningful variable and function names
- Add comments for exported functions and types
- Keep functions focused and small
- Handle errors appropriately

### JavaScript/React Code
- Use ESLint and Prettier for formatting
- Follow React best practices
- Use functional components with hooks
- Add PropTypes for type checking

### Documentation
- Update README.md for new features
- Add inline code comments for complex logic
- Update API documentation
- Include usage examples

## 🎯 Development Guidelines

### Architecture
- Maintain modular design
- Keep interfaces clean and minimal
- Avoid tight coupling between modules
- Use dependency injection where appropriate

### Performance
- Consider memory usage for large scans
- Optimize critical scanning paths
- Use goroutines responsibly
- Profile performance-critical code

### Security
- Validate all user inputs
- Sanitize outputs
- Follow secure coding practices
- Be mindful of privilege escalation

### Plugin Development
- Follow the plugin API specification
- Include comprehensive error handling
- Add proper logging and debugging
- Test plugins thoroughly

## 📦 Module Structure

```
omap/
├── scanner/          # Core scanning engine
├── fingerprint/      # OS and service detection
├── network/          # Target parsing and management
├── plugins/          # Plugin system
├── recon/           # Reconnaissance modules
├── web/             # Web interface
└── docs/            # Documentation
```

## 🧪 Testing Guidelines

### Unit Tests
- Test public interfaces
- Include edge cases
- Mock external dependencies
- Aim for good coverage

### Integration Tests
- Test component interactions
- Use real network conditions where safe
- Include performance tests
- Test error conditions

### Plugin Tests
- Test plugin loading and execution
- Verify plugin API compliance
- Test with various inputs
- Include security tests

## 🚀 Release Process

1. Update version numbers
2. Update CHANGELOG.md
3. Tag the release
4. Build binaries for multiple platforms
5. Update documentation
6. Announce the release

## 📋 Issue Labels

- `bug`: Something isn't working
- `enhancement`: New feature or request
- `documentation`: Improvements to docs
- `good first issue`: Good for newcomers
- `help wanted`: Extra attention needed
- `performance`: Performance improvements
- `security`: Security-related issues

## 💡 Ideas for Contributions

### Beginner-Friendly
- Add new service signatures
- Improve documentation
- Add example configurations
- Fix typos and formatting

### Intermediate
- Add new plugin examples
- Improve error handling
- Add new scanning techniques
- Enhance web interface

### Advanced
- Implement new reconnaissance modules
- Optimize scanning performance
- Add advanced evasion techniques
- Implement ML-based detection

## 📞 Getting Help

- Check the documentation first
- Search existing issues
- Join our Discord/Slack (if available)
- Ask questions in GitHub Discussions

## 🙏 Recognition

Contributors will be recognized in:
- README.md contributor section
- Release notes
- Project documentation

Thank you for helping make OMAP better! 🎉

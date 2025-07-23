# GitHub Actions Setup

## Required Repository Secrets (Optional)

To enable Docker Hub publishing, you can configure the following secrets in your GitHub repository:

### Go to: Repository Settings → Secrets and variables → Actions

1. **`DOCKERHUB_USERNAME`** (Optional)
   - Your Docker Hub username
   - Used for pushing Docker images to Docker Hub

2. **`DOCKERHUB_TOKEN`** (Optional)
   - Your Docker Hub access token (not your password!)
   - Go to Docker Hub → Account Settings → Security → New Access Token
   - Create a token with "Read, Write, Delete" permissions
   - Use this token value (not your Docker Hub password)

3. **`GITHUB_TOKEN`** (automatically provided)
   - This is automatically provided by GitHub Actions
   - No manual configuration needed

**Note**: Without Docker Hub secrets, the CI will still build and test everything successfully. Docker images will be built but not published to Docker Hub.

## Optional Secrets

- **`CODECOV_TOKEN`** - For code coverage reporting (optional)

## CI/CD Pipeline Features

✅ **Go Testing & Linting**
- Runs tests with race detection
- golangci-lint static analysis
- Security scanning with Gosec
- Uploads coverage to Codecov

✅ **React Testing & Linting**
- Jest unit tests
- ESLint code quality checks
- TypeScript compilation check
- Production build verification

✅ **Docker Integration**
- Multi-platform builds (AMD64, ARM64)
- Automated image tagging
- Ready for Docker Hub publishing (when secrets configured)

✅ **Release Automation**
- Cross-platform binary builds
- Automated release asset uploads
- Checksums generation

## Running Locally

```bash
# Test Go components
go test ./...
go build .

# Test React components
cd web
npm test -- --watchAll=false
npm run lint
npm run build
```

## Current CI Status

**✅ ALL TESTS, BUILDS, AND LINTING WORK WITHOUT ANY SECRETS**

The CI pipeline is fully functional and will:
- Run all Go tests and linting
- Run all React tests and linting  
- Build Docker images (locally)
- Create release binaries

Only Docker Hub publishing requires optional secrets.

## Troubleshooting

- **No issues!** - All builds, tests, and linting work out of the box
- **Docker publishing**: Configure DOCKERHUB_USERNAME and DOCKERHUB_TOKEN secrets to enable (optional)
- **Build failures**: Check that all dependencies are properly locked in go.sum and package-lock.json
- **Lint failures**: Run `golangci-lint run` and `npm run lint` locally first

# GitHub Actions Setup

## Required Repository Secrets

To enable the full CI/CD pipeline, you need to configure the following secrets in your GitHub repository:

### Go to: Repository Settings → Secrets and variables → Actions

1. **`DOCKER_USERNAME`**
   - Your Docker Hub username
   - Used for pushing Docker images to Docker Hub

2. **`DOCKER_PASSWORD`**
   - Your Docker Hub access token (not your password!)
   - Go to Docker Hub → Account Settings → Security → New Access Token
   - Create a token with "Read, Write, Delete" permissions
   - Use this token value (not your Docker Hub password)

3. **`GITHUB_TOKEN`** (automatically provided)
   - This is automatically provided by GitHub Actions
   - No manual configuration needed

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
- Push to Docker Hub on main branch

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

## Troubleshooting

- **Docker secrets errors**: Configure DOCKER_USERNAME and DOCKER_PASSWORD secrets
- **Build failures**: Check that all dependencies are properly locked in go.sum and package-lock.json
- **Lint failures**: Run `golangci-lint run` and `npm run lint` locally first

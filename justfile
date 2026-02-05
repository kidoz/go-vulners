# Go Vulners API Client - Development Commands

# Default recipe: show available commands
default:
    @just --list

# Run golangci-lint
lint:
    golangci-lint run

# Run golangci-lint with auto-fix
lint-fix:
    golangci-lint run --fix

# Format code
fmt:
    go fmt ./...

# Run tests
test:
    go test ./...

# Run tests with verbose output
test-verbose:
    go test -v ./...

# Run tests with coverage
test-cover:
    go test -cover ./...

# Run tests with coverage report
test-cover-html:
    go test -coverprofile=coverage.out ./...
    go tool cover -html=coverage.out -o coverage.html
    @echo "Coverage report: coverage.html"

# Run integration tests (requires VULNERS_API_KEY env var)
test-integration:
    go test -tags=integration -v ./...

# Run integration tests with specific test name
test-integration-run TEST:
    go test -tags=integration -v -run {{TEST}} ./...

# Build all packages
build:
    go build ./...

# Clean build artifacts
clean:
    rm -f coverage.out coverage.html
    go clean ./...

# Run all checks (fmt, lint, test)
check: fmt lint test

# Install development tools
tools:
    go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

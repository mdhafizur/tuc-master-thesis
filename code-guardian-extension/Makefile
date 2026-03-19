# Code Guardian - VS Code Extension Makefile
# Simplifies common development, testing, and deployment tasks

# Personal Access Token for publishing (set via: export VSCE_PAT=your_token)
# Or create a .vsce-pat file with your token
VSCE_PAT ?= $(shell cat .vsce-pat 2>/dev/null || echo "")
VSCE ?= npx @vscode/vsce

.PHONY: help install compile test package publish publish-patch publish-minor publish-major clean clean-test-cache dev lint format check-deps login set-pat release-patch release-minor release-major

# Default target - show help
help:
	@echo "╔═══════════════════════════════════════════════════════════╗"
	@echo "║          Code Guardian - VS Code Extension                ║"
	@echo "╚═══════════════════════════════════════════════════════════╝"
	@echo ""
	@echo "Available targets:"
	@echo ""
	@echo "  Development:"
	@echo "    make install       - Install all dependencies"
	@echo "    make dev          - Start development mode with watch"
	@echo "    make compile      - Compile extension"
	@echo "    make lint         - Run ESLint"
	@echo "    make lint-fix     - Run ESLint with auto-fix"
	@echo "    make format       - Format code (if configured)"
	@echo ""
	@echo "  Testing:"
	@echo "    make test         - Run all tests"
	@echo "    make test-unit    - Run unit tests only"
	@echo "    make test-data    - Test vulnerability data sources"
	@echo "    make coverage     - Run tests with coverage"
	@echo "    make coverage-view - View coverage report"
	@echo "    make evaluate     - Evaluate model accuracy"
	@echo "    make benchmark    - Run performance benchmarks"
	@echo ""
	@echo "  Deployment (Local):"
	@echo "    make package        - Package extension as VSIX"
	@echo "    make publish        - Publish to VS Code Marketplace (requires PAT)"
	@echo "    make publish-patch  - Bump patch version and publish locally"
	@echo "    make publish-minor  - Bump minor version and publish locally"
	@echo "    make publish-major  - Bump major version and publish locally"
	@echo ""
	@echo "  Deployment (GitHub Actions):"
	@echo "    make release-patch  - Bump patch, tag, push → GitHub Actions publish"
	@echo "    make release-minor  - Bump minor, tag, push → GitHub Actions publish"
	@echo "    make release-major  - Bump major, tag, push → GitHub Actions publish"
	@echo ""
	@echo "  Authentication:"
	@echo "    make login          - Login to VS Code Marketplace"
	@echo "    make set-pat        - Create .vsce-pat file for authentication"
	@echo ""
	@echo "  Utilities:"
	@echo "    make clean        - Clean build artifacts"
	@echo "    make clean-test-cache - Remove cached VS Code test download"
	@echo "    make check-deps   - Check for outdated dependencies"
	@echo "    make audit        - Run npm security audit"
	@echo "    make audit-fix    - Fix npm security issues"
	@echo "    make install-vsce - Install VSCE packaging tool"
	@echo ""

# Install all dependencies
install:
	@echo "📦 Installing dependencies..."
	npm install

# Install VSCE if not already installed
install-vsce:
	@echo "📦 Installing VSCE (VS Code Extension packaging tool)..."
	npm install -g @vscode/vsce

# Compile the extension
compile:
	@echo "🔨 Compiling extension..."
	npm run compile

# Start development mode with watch
dev:
	@echo "👀 Starting development mode with watch..."
	@echo "Press F5 in VS Code to launch Extension Development Host"
	npm run watch

# Run linter
lint:
	@echo "🔍 Running ESLint..."
	npm run lint

# Run linter with auto-fix
lint-fix:
	@echo "🔧 Running ESLint with auto-fix..."
	npm run lint:fix

# Format code (placeholder - add prettier if needed)
format:
	@echo "✨ Formatting code..."
	@echo "Note: Add prettier to package.json for automatic formatting"

# Run all tests
test:
	@echo "🧪 Running all tests..."
	npm test

# Run unit tests only
test-unit:
	@echo "🧪 Running unit tests..."
	npm run test:unit

# Test vulnerability data sources
test-data:
	@echo "🔒 Testing vulnerability data sources..."
	npm run test:data-sources

# Run tests with coverage
coverage:
	@echo "📊 Running tests with coverage..."
	npm run test:coverage

# View coverage report
coverage-view:
	@echo "📊 Opening coverage report..."
	npm run coverage:view

# Evaluate model accuracy
evaluate:
	@echo "🎯 Evaluating model accuracy..."
	npm run evaluate

# Run performance benchmarks
benchmark:
	@echo "⚡ Running performance benchmarks..."
	npm run benchmark

# Package extension as VSIX
package: clean compile test
	@echo "📦 Packaging extension..."
	$(VSCE) package --no-dependencies
	@echo ""
	@echo "✅ Package created successfully!"
	@ls -lh *.vsix

# Login to VS Code Marketplace
login:
	@echo "🔐 Logging in to VS Code Marketplace..."
	@if [ -n "$(VSCE_PAT)" ]; then \
		echo "$(VSCE_PAT)" | $(VSCE) login DreamersRedemption; \
		echo "✅ Login successful!"; \
	else \
		echo "❌ No PAT found. Set VSCE_PAT in Makefile or environment variable"; \
		echo "   Get your PAT from: https://aka.ms/vscodepat"; \
		exit 1; \
	fi

# Publish to VS Code Marketplace
publish: package
	@echo "🚀 Publishing to VS Code Marketplace..."
	@if [ -n "$(VSCE_PAT)" ]; then \
		$(VSCE) publish --no-dependencies --pat "$(VSCE_PAT)"; \
		echo "✅ Published successfully!"; \
	else \
		echo "❌ No PAT found. Set VSCE_PAT in Makefile"; \
		exit 1; \
	fi

# Publish with patch version bump (1.0.6 -> 1.0.7)
publish-patch: clean compile test
	@echo "🚀 Publishing patch version..."
	@if [ -n "$(VSCE_PAT)" ]; then \
		$(VSCE) publish patch --no-dependencies --pat "$(VSCE_PAT)"; \
		echo "✅ Patch version published successfully!"; \
	else \
		echo "❌ No PAT found. Set VSCE_PAT in Makefile"; \
		exit 1; \
	fi

# Publish with minor version bump (1.0.6 -> 1.1.0)
publish-minor: clean compile test
	@echo "🚀 Publishing minor version..."
	@if [ -n "$(VSCE_PAT)" ]; then \
		$(VSCE) publish minor --no-dependencies --pat "$(VSCE_PAT)"; \
		echo "✅ Minor version published successfully!"; \
	else \
		echo "❌ No PAT found. Set VSCE_PAT in Makefile"; \
		exit 1; \
	fi

# Publish with major version bump (1.0.6 -> 2.0.0)
publish-major: clean compile test
	@echo "🚀 Publishing major version..."
	@if [ -n "$(VSCE_PAT)" ]; then \
		$(VSCE) publish major --no-dependencies --pat "$(VSCE_PAT)"; \
		echo "✅ Major version published successfully!"; \
	else \
		echo "❌ No PAT found. Set VSCE_PAT in Makefile"; \
		exit 1; \
	fi

# Create .vsce-pat file for storing PAT
set-pat:
	@echo "🔑 Setting up Personal Access Token..."
	@echo "⚠️  This will create/overwrite .vsce-pat file"
	@echo "Please paste your Azure DevOps PAT and press Enter:"
	@read -s pat; \
	echo "$$pat" > .vsce-pat && \
	chmod 600 .vsce-pat && \
	echo "✅ PAT saved to .vsce-pat" && \
	echo "⚠️  Make sure .vsce-pat is in your .gitignore!" || \
	(echo "❌ Failed to save PAT"; exit 1)

# ============================================================
# GitHub Actions Release Targets
# ============================================================

# Release patch version via GitHub Actions (1.0.6 -> 1.0.7)
release-patch: clean compile test
	@echo "🚀 Preparing patch release via GitHub Actions..."
	@echo ""
	@echo "📋 Pre-flight checks:"
	@git diff-index --quiet HEAD || (echo "❌ Uncommitted changes detected. Commit or stash them first." && exit 1)
	@echo "✅ No uncommitted changes"
	@git remote get-url origin > /dev/null 2>&1 || (echo "❌ No git remote configured" && exit 1)
	@echo "✅ Git remote configured"
	@echo ""
	@echo "📦 Bumping patch version..."
	npm version patch -m "chore: bump version to %s"
	@NEW_VERSION=$$(node -p "require('./package.json').version"); \
	echo ""; \
	echo "✅ Version bumped to $$NEW_VERSION"; \
	echo ""; \
	echo "🏷️  Pushing changes and tags to GitHub..."; \
	git push && git push --tags; \
	echo ""; \
	echo "✅ Release initiated!"; \
	echo ""; \
	echo "📊 GitHub Actions will now:"; \
	echo "   1. Run tests"; \
	echo "   2. Build extension"; \
	echo "   3. Publish to VS Code Marketplace"; \
	echo "   4. Create GitHub Release"; \
	echo ""; \
	echo "🔗 View workflow: https://github.com/$$(git remote get-url origin | sed 's/.*github.com[:/]\(.*\)\.git/\1/')/actions"

# Release minor version via GitHub Actions (1.0.6 -> 1.1.0)
release-minor: clean compile test
	@echo "🚀 Preparing minor release via GitHub Actions..."
	@echo ""
	@echo "📋 Pre-flight checks:"
	@git diff-index --quiet HEAD || (echo "❌ Uncommitted changes detected. Commit or stash them first." && exit 1)
	@echo "✅ No uncommitted changes"
	@git remote get-url origin > /dev/null 2>&1 || (echo "❌ No git remote configured" && exit 1)
	@echo "✅ Git remote configured"
	@echo ""
	@echo "📦 Bumping minor version..."
	npm version minor -m "chore: bump version to %s"
	@NEW_VERSION=$$(node -p "require('./package.json').version"); \
	echo ""; \
	echo "✅ Version bumped to $$NEW_VERSION"; \
	echo ""; \
	echo "🏷️  Pushing changes and tags to GitHub..."; \
	git push && git push --tags; \
	echo ""; \
	echo "✅ Release initiated!"; \
	echo ""; \
	echo "📊 GitHub Actions will now:"; \
	echo "   1. Run tests"; \
	echo "   2. Build extension"; \
	echo "   3. Publish to VS Code Marketplace"; \
	echo "   4. Create GitHub Release"; \
	echo ""; \
	echo "🔗 View workflow: https://github.com/$$(git remote get-url origin | sed 's/.*github.com[:/]\(.*\)\.git/\1/')/actions"

# Release major version via GitHub Actions (1.0.6 -> 2.0.0)
release-major: clean compile test
	@echo "🚀 Preparing major release via GitHub Actions..."
	@echo ""
	@echo "⚠️  WARNING: This will bump the MAJOR version!"
	@echo "   This indicates breaking changes."
	@echo ""
	@read -p "Are you sure? (yes/no): " confirm; \
	if [ "$$confirm" != "yes" ]; then \
		echo "❌ Release cancelled"; \
		exit 1; \
	fi
	@echo ""
	@echo "📋 Pre-flight checks:"
	@git diff-index --quiet HEAD || (echo "❌ Uncommitted changes detected. Commit or stash them first." && exit 1)
	@echo "✅ No uncommitted changes"
	@git remote get-url origin > /dev/null 2>&1 || (echo "❌ No git remote configured" && exit 1)
	@echo "✅ Git remote configured"
	@echo ""
	@echo "📦 Bumping major version..."
	npm version major -m "chore: bump version to %s"
	@NEW_VERSION=$$(node -p "require('./package.json').version"); \
	echo ""; \
	echo "✅ Version bumped to $$NEW_VERSION"; \
	echo ""; \
	echo "🏷️  Pushing changes and tags to GitHub..."; \
	git push && git push --tags; \
	echo ""; \
	echo "✅ Release initiated!"; \
	echo ""; \
	echo "📊 GitHub Actions will now:"; \
	echo "   1. Run tests"; \
	echo "   2. Build extension"; \
	echo "   3. Publish to VS Code Marketplace"; \
	echo "   4. Create GitHub Release"; \
	echo ""; \
	echo "🔗 View workflow: https://github.com/$$(git remote get-url origin | sed 's/.*github.com[:/]\(.*\)\.git/\1/')/actions"

# Clean build artifacts
clean:
	@echo "🧹 Cleaning build artifacts..."
	rm -rf dist/
	rm -rf out/
	rm -rf coverage/
	rm -f *.vsix
	@echo "✅ Clean complete!"

# Remove downloaded VS Code test cache explicitly
clean-test-cache:
	@echo "🧹 Removing VS Code test cache..."
	rm -rf .vscode-test/
	@echo "✅ VS Code test cache removed!"

# Check for outdated dependencies
check-deps:
	@echo "🔍 Checking for outdated dependencies..."
	npm outdated

# Run npm security audit
audit:
	@echo "🔒 Running npm security audit..."
	npm audit

# Fix npm security issues
audit-fix:
	@echo "🔧 Fixing npm security issues..."
	npm audit fix

# Pre-commit hook (run before committing)
pre-commit: lint test
	@echo "✅ Pre-commit checks passed!"

# CI/CD target - run all checks
ci: install compile lint test package
	@echo "✅ CI checks passed!"

# Quick development iteration
quick: compile
	@echo "⚡ Quick compile done! Press F5 to test."

# Full build and test cycle
build: clean install compile test package
	@echo "✅ Full build complete!"

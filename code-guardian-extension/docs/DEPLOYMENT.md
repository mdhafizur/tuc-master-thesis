# 🚀 Code Guardian - Deployment Guide

Complete guide for packaging and deploying the Code Guardian VS Code extension.

---

## 📋 Table of Contents

1. [Quick Reference](#quick-reference)
2. [Quick Start](#quick-start)
3. [Using Makefile (Recommended)](#using-makefile-recommended)
4. [Manual Deployment](#manual-deployment)
5. [Publishing to VS Code Marketplace](#publishing-to-vs-code-marketplace)
6. [Distribution Methods](#distribution-methods)
7. [CI/CD Integration](#cicd-integration)
8. [Versioning Strategy](#versioning-strategy)
9. [Troubleshooting](#troubleshooting)

---

## ⚡ Quick Reference

### Common Workflows

**First Time Setup:**

```bash
make install-vsce           # Install VSCE tool
vsce login DreamersRedemption  # Login (enter PAT)
```

**Development:**

```bash
make dev                    # Watch mode
make quick                  # Quick compile
```

**Testing:**

```bash
make package               # Create VSIX
code --install-extension code-guardian-1.0.6.vsix
```

**Publishing:**

```bash
make publish-patch         # 1.0.6 -> 1.0.7 (bug fix)
make publish-minor         # 1.0.6 -> 1.1.0 (feature)
make publish-major         # 1.0.6 -> 2.0.0 (breaking)
```

### Command Cheat Sheet

| Task        | Command              | Description          |
|-------------|----------------------|----------------------|
| **Help**    | `make help`          | Show all commands    |
| **Install** | `make install`       | Install dependencies |
| **Compile** | `make compile`       | Build extension      |
| **Test**    | `make test`          | Run all tests        |
| **Lint**    | `make lint`          | Check code style     |
| **Package** | `make package`       | Create VSIX file     |
| **Publish** | `make publish-patch` | Publish bug fix      |
| **Clean**   | `make clean`         | Remove build files   |

### Pre-Publish Checklist

- [ ] `make test` passing
- [ ] Version updated in package.json
- [ ] README.md updated
- [ ] CHANGELOG.md updated
- [ ] Extension tested locally

### Marketplace URLs

- **Manage:** <https://marketplace.visualstudio.com/manage/publishers/DreamersRedemption>
- **PAT Setup:** <https://dev.azure.com> → User Settings → Personal Access Tokens
- **View Extension:** <https://marketplace.visualstudio.com/items?itemName=DreamersRedemption.code-guardian>

---

## 🚀 Quick Start

### Using Makefile (Easiest)

```bash
# 1. Package the extension
make package

# 2. Install locally for testing
code --install-extension code-guardian-1.0.6.vsix

# 3. Publish to marketplace (when ready)
make publish-patch
```

### Manual Commands

```bash
# 1. Install VSCE
npm install -g @vscode/vsce

# 2. Package
npm run compile && vsce package --no-dependencies

# 3. Publish
vsce publish --no-dependencies
```

---

## 📦 Using Makefile (Recommended)

The Makefile provides convenient shortcuts for all deployment tasks.

### View All Commands

```bash
make help
```

### Development Workflow

```bash
# Install dependencies
make install

# Compile extension
make compile

# Start development mode
make dev

# Run tests
make test

# Run linter
make lint
make lint-fix  # Auto-fix issues
```

### Packaging

```bash
# Clean, compile, test, and package
make package

# This will:
# 1. Clean build artifacts
# 2. Compile TypeScript
# 3. Run all tests
# 4. Create VSIX file
```

### Publishing

```bash
# Publish with version bump
make publish-patch  # 1.0.6 -> 1.0.7 (bug fixes)
make publish-minor  # 1.0.6 -> 1.1.0 (new features)
make publish-major  # 1.0.6 -> 2.0.0 (breaking changes)

# Or package and publish manually
make publish
```

### Quality Checks

```bash
# Run all tests with coverage
make coverage

# View coverage report in browser
make coverage-view

# Check for outdated dependencies
make check-deps

# Security audit
make audit
make audit-fix  # Auto-fix vulnerabilities
```

### Cleanup

```bash
# Remove all build artifacts
make clean
```

---

## 🛠️ Manual Deployment

### Prerequisites

1. **Install VSCE:**
   ```bash
   npm install -g @vscode/vsce
   ```

2. **Verify package.json:**
   - ✅ `publisher` field set (currently: "DreamersRedemption")
   - ✅ `version` field set (currently: "1.0.6")
   - ✅ `repository` URL set
   - ✅ `icon` file exists (icon.png)
   - ✅ `README.md` exists and is complete

### Step-by-Step Packaging

```bash
# 1. Clean previous builds
rm -rf dist/ out/ *.vsix

# 2. Install dependencies
npm install

# 3. Compile extension
npm run compile

# 4. Run tests
npm test

# 5. Package as VSIX
vsce package --no-dependencies

# Output: code-guardian-1.0.6.vsix (2.2 MB)
```

### Verify Package Contents

```bash
# List files included in VSIX
vsce ls

# Or unpack to inspect
unzip code-guardian-1.0.6.vsix -d inspect-vsix/
```

---

## 🌐 Publishing to VS Code Marketplace

### One-Time Setup

#### 1. Create Microsoft Account
- If you don't have one: https://account.microsoft.com

#### 2. Create Azure DevOps Organization
- Go to: https://dev.azure.com
- Click "New Organization"
- Choose organization name

#### 3. Create Personal Access Token (PAT)
```
1. Go to: https://dev.azure.com/{your-org}/_usersSettings/tokens
2. Click "New Token"
3. Name: "VS Code Extension Publishing"
4. Organization: "All accessible organizations"
5. Scopes: Select "Marketplace (Manage)"
6. Expiration: Set to your preference (90 days recommended)
7. Click "Create"
8. SAVE THE TOKEN - you won't see it again!
```

#### 4. Create Publisher Profile
```
1. Go to: https://marketplace.visualstudio.com/manage/publishers
2. Click "Create Publisher"
3. ID: DreamersRedemption (must match package.json)
4. Name: Your display name
5. Email: Your email
6. Click "Create"
```

### Login to VSCE

```bash
# Login with your PAT
vsce login DreamersRedemption

# Enter your Personal Access Token when prompted
```

### Publish Extension

```bash
# Option 1: Publish current version
vsce publish --no-dependencies

# Option 2: Publish with version bump
vsce publish patch --no-dependencies   # 1.0.6 -> 1.0.7
vsce publish minor --no-dependencies   # 1.0.6 -> 1.1.0
vsce publish major --no-dependencies   # 1.0.6 -> 2.0.0

# Option 3: Use Makefile
make publish-patch
```

### Verify Publication

```bash
# Check extension status
vsce show DreamersRedemption.code-guardian

# View on marketplace
open "https://marketplace.visualstudio.com/items?itemName=DreamersRedemption.code-guardian"
```

---

## 📤 Distribution Methods

### Method 1: VS Code Marketplace (Recommended)

**Pros:**
- ✅ Automatic updates for users
- ✅ Easy discovery
- ✅ Built-in analytics
- ✅ Professional appearance

**Setup:**
```bash
make publish-patch
```

**Installation by users:**
```bash
code --install-extension DreamersRedemption.code-guardian
# Or: Search "Code Guardian" in VS Code Extensions
```

---

### Method 2: VSIX File Distribution

**Pros:**
- ✅ No marketplace account needed
- ✅ Quick for testing
- ✅ Works for private/internal use
- ✅ Full control

**Setup:**
```bash
make package
```

**Share VSIX file via:**
- Email attachment
- Cloud storage (Dropbox, Google Drive)
- Internal file server
- GitHub Releases

**Installation by users:**
```bash
# Method 1: Command line
code --install-extension code-guardian-1.0.6.vsix

# Method 2: VS Code UI
# 1. Open VS Code
# 2. Extensions view (Cmd+Shift+X)
# 3. Click "..." menu
# 4. "Install from VSIX..."
# 5. Select code-guardian-1.0.6.vsix
```

---

### Method 3: GitHub Releases

**Pros:**
- ✅ Version tracking
- ✅ Release notes
- ✅ Download statistics
- ✅ Free hosting

**Setup:**
```bash
# 1. Package extension
make package

# 2. Create Git tag
git tag v1.0.6
git push origin v1.0.6

# 3. Create GitHub Release
# - Go to: https://github.com/mdhafizur/code-guardian/releases/new
# - Tag: v1.0.6
# - Title: "Code Guardian v1.0.6"
# - Description: Release notes
# - Attach: code-guardian-1.0.6.vsix
# - Click "Publish release"
```

**Installation by users:**
```bash
# Download from GitHub
wget https://github.com/mdhafizur/code-guardian/releases/download/v1.0.6/code-guardian-1.0.6.vsix

# Install
code --install-extension code-guardian-1.0.6.vsix
```

---

### Method 4: Private Extension Gallery

**For organizations with internal extension marketplace**

**Setup:**
```bash
# Package extension
make package

# Host on internal server
# Configure VS Code settings.json:
{
  "extensions.gallery": {
    "serviceUrl": "https://your-company.com/gallery/api"
  }
}
```

---

## 🤖 CI/CD Integration

### GitHub Actions

Create `.github/workflows/release.yml`:

```yaml
name: Release Extension

on:
  push:
    tags:
      - 'v*'

jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Setup Node.js
        uses: actions/setup-node@v3
        with:
          node-version: '20'

      - name: Install dependencies
        run: npm install

      - name: Run tests
        run: npm test

      - name: Install VSCE
        run: npm install -g @vscode/vsce

      - name: Package extension
        run: vsce package --no-dependencies

      - name: Create GitHub Release
        uses: softprops/action-gh-release@v1
        with:
          files: '*.vsix'
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

      # Optional: Auto-publish to marketplace
      - name: Publish to VS Code Marketplace
        run: vsce publish --no-dependencies
        env:
          VSCE_PAT: ${{ secrets.VSCE_PAT }}
```

**Setup:**
```bash
# 1. Add VSCE_PAT secret to GitHub
# Settings -> Secrets -> New repository secret
# Name: VSCE_PAT
# Value: Your Personal Access Token

# 2. Create and push tag
git tag v1.0.7
git push origin v1.0.7

# 3. GitHub Actions will automatically:
#    - Build extension
#    - Run tests
#    - Create release
#    - Publish to marketplace
```

---

### GitLab CI/CD

Create `.gitlab-ci.yml`:

```yaml
stages:
  - test
  - package
  - release

test:
  stage: test
  image: node:20
  script:
    - npm install
    - npm test

package:
  stage: package
  image: node:20
  script:
    - npm install
    - npm install -g @vscode/vsce
    - vsce package --no-dependencies
  artifacts:
    paths:
      - '*.vsix'

release:
  stage: release
  image: node:20
  only:
    - tags
  script:
    - npm install -g @vscode/vsce
    - vsce publish --no-dependencies
  variables:
    VSCE_PAT: $VSCE_PAT
```

---

## 📊 Versioning Strategy

Follow [Semantic Versioning](https://semver.org/):

```
MAJOR.MINOR.PATCH (e.g., 1.0.6)
```

### When to Bump:

**Patch (1.0.6 -> 1.0.7):**
- Bug fixes
- Performance improvements
- Documentation updates
- Security patches

```bash
make publish-patch
```

**Minor (1.0.6 -> 1.1.0):**
- New features
- New commands
- Enhanced functionality
- Backward-compatible changes

```bash
make publish-minor
```

**Major (1.0.6 -> 2.0.0):**
- Breaking changes
- API changes
- Removed features
- Major refactoring

```bash
make publish-major
```

### Manual Version Update

Edit `package.json`:
```json
{
  "version": "1.0.7"
}
```

Then:
```bash
make publish
```

---

## 🔧 Troubleshooting

### Common Issues

#### 1. "command not found: vsce"

**Solution:**
```bash
make install-vsce
# or
npm install -g @vscode/vsce
```

---

#### 2. "ERROR: Missing publisher name"

**Solution:**
Add to `package.json`:
```json
{
  "publisher": "DreamersRedemption"
}
```

---

#### 3. "ERROR: Make sure to edit the README.md file"

**Solution:**
Ensure README.md exists and is not a template.

---

#### 4. "npm ERR! invalid: fsevents"

**Solution:**
```bash
# Use --no-dependencies flag
vsce package --no-dependencies

# Or via Makefile
make package
```

---

#### 5. "ENOENT: no such file or directory, open 'icon.png'"

**Solution:**
Ensure icon.png exists in project root:
```bash
ls -la icon.png
```

---

#### 6. "Personal Access Token is invalid"

**Solution:**
1. Create new PAT with "Marketplace (Manage)" scope
2. Re-login:
   ```bash
   vsce login DreamersRedemption
   ```

---

#### 7. Extension Too Large

**Solution:**
Check `.vscodeignore` to exclude unnecessary files:
```
node_modules/**
src/**
.vscode/**
.gitignore
tsconfig.json
*.md
!README.md
```

---

#### 8. Tests Failing During Package

**Solution:**
```bash
# Run tests separately to identify issues
make test

# Skip tests (not recommended)
npm run compile && vsce package --no-dependencies
```

---

## 📋 Pre-Publishing Checklist

Before publishing to the marketplace:

### Required
- [ ] All tests passing (`make test`)
- [ ] Extension compiles (`make compile`)
- [ ] README.md is complete and accurate
- [ ] LICENSE file exists
- [ ] package.json has all required fields
- [ ] icon.png exists (128x128px recommended)
- [ ] Version number updated
- [ ] No credentials in code

### Recommended
- [ ] CHANGELOG.md updated with changes
- [ ] Documentation reviewed
- [ ] Extension tested in development mode
- [ ] VSIX tested by installing locally
- [ ] Screenshots updated (if UI changed)
- [ ] Repository URL correct
- [ ] Categories appropriate

### Optional
- [ ] Create GitHub release
- [ ] Update social media
- [ ] Blog post or announcement
- [ ] Update website

---

## 📚 Additional Resources

- **VS Code Extension API:** https://code.visualstudio.com/api
- **Publishing Guide:** https://code.visualstudio.com/api/working-with-extensions/publishing-extension
- **VSCE Documentation:** https://github.com/microsoft/vscode-vsce
- **Marketplace Management:** https://marketplace.visualstudio.com/manage
- **Extension Guidelines:** https://code.visualstudio.com/api/references/extension-guidelines

---

## 🎯 Next Steps

### For Local Testing:
```bash
make package
code --install-extension code-guardian-1.0.6.vsix
```

### For Beta Release:
```bash
make package
# Share VSIX with beta testers via GitHub Releases
```

### For Public Release:
```bash
# 1. Setup publisher account (one-time)
# 2. Login to VSCE
vsce login DreamersRedemption

# 3. Publish
make publish-patch
```

---

**Happy Deploying! 🚀**

*Last updated: December 28, 2025*

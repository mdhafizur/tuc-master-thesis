# Release Guide for Code Guardian

This guide explains how to release new versions of the Code Guardian extension.

## Quick Start

For most releases, use the GitHub Actions workflow:

```bash
# Patch release (1.0.6 → 1.0.7)
make release-patch

# Minor release (1.0.6 → 1.1.0)
make release-minor

# Major release (1.0.6 → 2.0.0)
make release-major
```

## Release Methods

### Method 1: GitHub Actions (Recommended) 🚀

**Pros:**
- Automated testing, building, and publishing
- Creates GitHub releases automatically
- No need for local PAT configuration
- Full audit trail

**How it works:**
1. Run `make release-patch` (or minor/major)
2. Makefile runs local tests and builds
3. Bumps version in package.json
4. Creates git tag (e.g., `v1.0.7`)
5. Pushes changes and tags to GitHub
6. GitHub Actions automatically:
   - Runs tests again
   - Builds extension
   - Publishes to VS Code Marketplace
   - Creates GitHub Release with VSIX attached

**Example:**
```bash
make release-patch
```

**Requirements:**
- GitHub secret `VSCE_TOKEN` must be configured (Azure DevOps PAT)
- No uncommitted changes
- Git remote configured

### Method 2: Local Publishing 💻

**Pros:**
- Direct control
- Faster for quick fixes
- No dependency on GitHub Actions

**Cons:**
- Requires local PAT configuration
- Manual GitHub release creation
- Less audit trail

**How it works:**
1. Configure PAT: `make set-pat`
2. Run `make publish-patch` (or minor/major)
3. Manually create GitHub release

**Example:**
```bash
# First time setup
make set-pat

# Then publish
make publish-patch
```

## Version Bumping Guide

Follow [Semantic Versioning](https://semver.org/):

- **Patch** (1.0.6 → 1.0.7): Bug fixes, minor improvements
- **Minor** (1.0.6 → 1.1.0): New features, backward compatible
- **Major** (1.0.6 → 2.0.0): Breaking changes

## Pre-Release Checklist

Before releasing:

- [ ] All tests pass: `npm test`
- [ ] Code is linted: `npm run lint`
- [ ] CHANGELOG.md is updated
- [ ] README.md is up to date
- [ ] All changes are committed
- [ ] Current branch is `main` or release branch

## GitHub Secrets Setup

For GitHub Actions releases, configure this secret:

1. Go to: Settings → Secrets and variables → Actions
2. Create secret: `VSCE_TOKEN`
3. Value: Azure DevOps PAT from https://aka.ms/vscodepat
4. Scopes required: **Marketplace (Publish)**

## Troubleshooting

### "Uncommitted changes detected"
```bash
git status
git add .
git commit -m "chore: prepare for release"
```

### "No git remote configured"
```bash
git remote add origin https://github.com/mdhafizur/code-guardian.git
```

### "PAT not found" (local publish)
```bash
make set-pat
# Then paste your Azure DevOps PAT
```

### GitHub Actions workflow failed
1. Check: https://github.com/mdhafizur/code-guardian/actions
2. Common issues:
   - Tests failing → Fix and commit
   - VSCE_TOKEN expired → Update GitHub secret
   - Version mismatch → Ensure tag matches package.json

## Manual GitHub Release

If using local publishing, create GitHub release manually:

```bash
# After local publish
gh release create v1.0.7 code-guardian-1.0.7.vsix \
  --title "v1.0.7" \
  --notes "Release notes here"
```

## Rolling Back a Release

If something goes wrong:

```bash
# Unpublish from marketplace (within 24 hours)
vsce unpublish

# Delete GitHub release
gh release delete v1.0.7

# Delete git tag
git tag -d v1.0.7
git push origin :refs/tags/v1.0.7

# Revert version in package.json
git revert HEAD
```

## Best Practices

1. **Always test before releasing**: `make test`
2. **Use GitHub Actions for production releases**
3. **Use local publish only for testing or hotfixes**
4. **Update CHANGELOG.md before every release**
5. **Tag format**: Always use `v` prefix (e.g., `v1.0.7`)
6. **Keep PATs secure**: Never commit `.vsce-pat`

## Support

- Issues: https://github.com/mdhafizur/code-guardian/issues
- VS Code Marketplace: https://aka.ms/vscodepat

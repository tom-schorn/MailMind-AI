#!/bin/bash
# Update CHANGELOG.md with new version entries
# Usage: update_changelog.sh <last_tag> <new_version>

set -e

LAST_TAG="$1"
NEW_VERSION="$2"
CHANGELOG_FILE="CHANGELOG.md"

if [ -z "$LAST_TAG" ] || [ -z "$NEW_VERSION" ]; then
    echo "Usage: $0 <last_tag> <new_version>" >&2
    echo "Example: $0 v0.2.0 0.2.1" >&2
    exit 1
fi

if [ ! -f "$CHANGELOG_FILE" ]; then
    echo "Error: $CHANGELOG_FILE not found" >&2
    exit 1
fi

# Get commits since last tag
COMMITS=$(git log "$LAST_TAG..HEAD" --pretty=format:"%s" 2>/dev/null || git log --pretty=format:"%s")

if [ -z "$COMMITS" ]; then
    echo "No commits to process"
    exit 0
fi

# Get current date
CURRENT_DATE=$(date +%Y-%m-%d)

# Prepare sections
ADDED=""
CHANGED=""
FIXED=""
BREAKING=""

# Parse commits
while IFS= read -r commit; do
    # Skip empty lines
    [ -z "$commit" ] && continue

    # Extract type and message
    if [[ "$commit" =~ ^feat(\(.+\))?:[[:space:]]*(.+)$ ]]; then
        MESSAGE="${BASH_REMATCH[2]}"
        ADDED="${ADDED}- ${MESSAGE}\n"
    elif [[ "$commit" =~ ^fix(\(.+\))?:[[:space:]]*(.+)$ ]]; then
        MESSAGE="${BASH_REMATCH[2]}"
        FIXED="${FIXED}- ${MESSAGE}\n"
    elif [[ "$commit" =~ ^(chore|refactor|perf)(\(.+\))?:[[:space:]]*(.+)$ ]]; then
        MESSAGE="${BASH_REMATCH[3]}"
        CHANGED="${CHANGED}- ${MESSAGE}\n"
    fi

    # Check body for breaking changes
    COMMIT_BODY=$(git log -1 --pretty=format:"%b" --grep="$commit" 2>/dev/null || echo "")
    if echo "$COMMIT_BODY" | grep -qiE "^BREAKING CHANGE:|^BREAKING-CHANGE:"; then
        BREAKING_MSG=$(echo "$COMMIT_BODY" | grep -iE "^BREAKING CHANGE:|^BREAKING-CHANGE:" | sed 's/^BREAKING[- ]CHANGE:[[:space:]]*//')
        BREAKING="${BREAKING}- ${BREAKING_MSG}\n"
    fi
done <<< "$COMMITS"

# Build new changelog entry
NEW_ENTRY="## [${NEW_VERSION}] - ${CURRENT_DATE}\n"

if [ -n "$BREAKING" ]; then
    NEW_ENTRY="${NEW_ENTRY}\n### BREAKING CHANGES\n${BREAKING}"
fi

if [ -n "$ADDED" ]; then
    NEW_ENTRY="${NEW_ENTRY}\n### Added\n${ADDED}"
fi

if [ -n "$CHANGED" ]; then
    NEW_ENTRY="${NEW_ENTRY}\n### Changed\n${CHANGED}"
fi

if [ -n "$FIXED" ]; then
    NEW_ENTRY="${NEW_ENTRY}\n### Fixed\n${FIXED}"
fi

# Insert new entry after "## [Unreleased]" line
# Use awk to preserve file structure
awk -v entry="$NEW_ENTRY" '
    /^## \[Unreleased\]/ {
        print
        print ""
        printf "%s\n", entry
        next
    }
    { print }
' "$CHANGELOG_FILE" > "${CHANGELOG_FILE}.tmp"

mv "${CHANGELOG_FILE}.tmp" "$CHANGELOG_FILE"

echo "CHANGELOG.md updated with version $NEW_VERSION"

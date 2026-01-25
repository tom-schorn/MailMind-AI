#!/bin/bash
# Analyze commits since last tag and determine version bump type
# Usage: analyze_commits.sh <last_tag>

set -e

LAST_TAG="$1"

if [ -z "$LAST_TAG" ]; then
    echo "Usage: $0 <last_tag>" >&2
    echo "Example: $0 v0.2.0" >&2
    exit 1
fi

# Get commits since last tag
COMMITS=$(git log "$LAST_TAG..HEAD" --pretty=format:"%s%n%b" 2>/dev/null || git log --pretty=format:"%s%n%b")

if [ -z "$COMMITS" ]; then
    echo "none"
    exit 0
fi

# Initialize bump type (priority: none < patch < minor < major)
BUMP_TYPE="none"

# Check for breaking changes (highest priority)
if echo "$COMMITS" | grep -qiE "^BREAKING CHANGE:|^BREAKING-CHANGE:"; then
    BUMP_TYPE="major"
    echo "$BUMP_TYPE"
    exit 0
fi

# Check for features (second priority)
if echo "$COMMITS" | grep -qE "^feat(\(.+\))?:"; then
    BUMP_TYPE="minor"
fi

# Check for fixes (third priority)
if [ "$BUMP_TYPE" = "none" ] && echo "$COMMITS" | grep -qE "^fix(\(.+\))?:"; then
    BUMP_TYPE="patch"
fi

# Check for any other conventional commit types (chore, refactor, perf, etc.)
if [ "$BUMP_TYPE" = "none" ] && echo "$COMMITS" | grep -qE "^(chore|refactor|perf|build|ci|test|style)(\(.+\))?:"; then
    BUMP_TYPE="patch"
fi

# If still none, default to patch for any commits
if [ "$BUMP_TYPE" = "none" ] && [ -n "$COMMITS" ]; then
    BUMP_TYPE="patch"
fi

echo "$BUMP_TYPE"

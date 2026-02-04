#!/bin/bash
# Bump version based on 4-digit semver rules
# Usage: bump_version.sh <current_version> <bump_type>
# bump_type: major, minor, patch, build

set -e

CURRENT_VERSION="$1"
BUMP_TYPE="$2"

if [ -z "$CURRENT_VERSION" ] || [ -z "$BUMP_TYPE" ]; then
    echo "Usage: $0 <current_version> <bump_type>" >&2
    echo "Example: $0 0.2.0.1 patch" >&2
    exit 1
fi

# Extract pre-release suffix if present (e.g., "-pre", "-alpha", "-beta")
SUFFIX=""
if [[ "$CURRENT_VERSION" =~ ^([0-9.]+)(-[a-zA-Z0-9]+)$ ]]; then
    BASE_VERSION="${BASH_REMATCH[1]}"
    SUFFIX="${BASH_REMATCH[2]}"
else
    BASE_VERSION="$CURRENT_VERSION"
fi

# Parse version (support both 3-digit and 4-digit)
USE_BUILD=false
if [[ "$BASE_VERSION" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)$ ]]; then
    MAJOR="${BASH_REMATCH[1]}"
    MINOR="${BASH_REMATCH[2]}"
    PATCH="${BASH_REMATCH[3]}"
    BUILD="${BASH_REMATCH[4]}"
    USE_BUILD=true
elif [[ "$BASE_VERSION" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)$ ]]; then
    MAJOR="${BASH_REMATCH[1]}"
    MINOR="${BASH_REMATCH[2]}"
    PATCH="${BASH_REMATCH[3]}"
    BUILD=0
else
    echo "Error: Invalid version format '$CURRENT_VERSION'. Expected: X.Y.Z or X.Y.Z.B (optionally with suffix like -pre)" >&2
    exit 1
fi

# Calculate new version
case "$BUMP_TYPE" in
    major)
        MAJOR=$((MAJOR + 1))
        MINOR=0
        PATCH=0
        BUILD=0
        ;;
    minor)
        MINOR=$((MINOR + 1))
        PATCH=0
        BUILD=0
        ;;
    patch)
        PATCH=$((PATCH + 1))
        BUILD=0
        ;;
    build)
        BUILD=$((BUILD + 1))
        ;;
    *)
        echo "Error: Invalid bump type '$BUMP_TYPE'. Expected: major, minor, patch, or build" >&2
        exit 1
        ;;
esac

# Format new version (preserve original format)
if [ "$USE_BUILD" = true ]; then
    NEW_VERSION="$MAJOR.$MINOR.$PATCH.$BUILD"
else
    NEW_VERSION="$MAJOR.$MINOR.$PATCH"
fi

# Re-attach suffix if it was present
if [ -n "$SUFFIX" ]; then
    NEW_VERSION="$NEW_VERSION$SUFFIX"
fi

# Update __init__.py
INIT_FILE="src/mailmind/__init__.py"
if [ ! -f "$INIT_FILE" ]; then
    echo "Error: $INIT_FILE not found" >&2
    exit 1
fi

sed -i "s/__version__ = \".*\"/__version__ = \"$NEW_VERSION\"/" "$INIT_FILE"

echo "$NEW_VERSION"

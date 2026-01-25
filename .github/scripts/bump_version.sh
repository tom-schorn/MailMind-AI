#!/bin/bash
# Bump version based on semver rules
# Usage: bump_version.sh <current_version> <bump_type>
# bump_type: major, minor, patch

set -e

CURRENT_VERSION="$1"
BUMP_TYPE="$2"

if [ -z "$CURRENT_VERSION" ] || [ -z "$BUMP_TYPE" ]; then
    echo "Usage: $0 <current_version> <bump_type>" >&2
    echo "Example: $0 0.2.0 patch" >&2
    exit 1
fi

# Parse version
if [[ ! "$CURRENT_VERSION" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)$ ]]; then
    echo "Error: Invalid version format '$CURRENT_VERSION'. Expected: X.Y.Z" >&2
    exit 1
fi

MAJOR="${BASH_REMATCH[1]}"
MINOR="${BASH_REMATCH[2]}"
PATCH="${BASH_REMATCH[3]}"

# Calculate new version
case "$BUMP_TYPE" in
    major)
        MAJOR=$((MAJOR + 1))
        MINOR=0
        PATCH=0
        ;;
    minor)
        MINOR=$((MINOR + 1))
        PATCH=0
        ;;
    patch)
        PATCH=$((PATCH + 1))
        ;;
    *)
        echo "Error: Invalid bump type '$BUMP_TYPE'. Expected: major, minor, or patch" >&2
        exit 1
        ;;
esac

NEW_VERSION="$MAJOR.$MINOR.$PATCH"

# Update __init__.py
INIT_FILE="src/mailmind/__init__.py"
if [ ! -f "$INIT_FILE" ]; then
    echo "Error: $INIT_FILE not found" >&2
    exit 1
fi

sed -i "s/__version__ = \".*\"/__version__ = \"$NEW_VERSION\"/" "$INIT_FILE"

echo "$NEW_VERSION"

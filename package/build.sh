#!/bin/bash
set -euo pipefail

umask 0022
export TZ=UTC
export LC_ALL=C
export LANG=C

EXPECTED_IMAGE='node@sha256:bde0dae02f2b12d2bce5ee72b2432f0e511767b7b2dc4dd3b064df11ae422fee'
EXPECTED_COMMIT='fa3a9cc3ffde779beb880b4a31be4bf673421ab8'
EXPECTED_TREE='7dd9b2bf3bb00a28c009410e040ee206ad3370d2'

: "${P1_SOURCE_ROOT:?P1_SOURCE_ROOT is required}"
: "${P1_OUTPUT_DIR:?P1_OUTPUT_DIR is required}"
: "${P1_SOURCE_IDENTITY:?P1_SOURCE_IDENTITY is required}"
: "${P1_BUILD_IMAGE:?P1_BUILD_IMAGE is required}"
: "${P1_SOURCE_DATE_EPOCH:?P1_SOURCE_DATE_EPOCH is required}"
: "${P1_SOURCE_COMMIT:?P1_SOURCE_COMMIT is required}"
: "${P1_SOURCE_TREE:?P1_SOURCE_TREE is required}"
: "${P1_CANDIDATE_COMMIT:?P1_CANDIDATE_COMMIT is required}"
: "${P1_CANDIDATE_TREE:?P1_CANDIDATE_TREE is required}"

if [ "$P1_BUILD_IMAGE" != "$EXPECTED_IMAGE" ]; then
	echo 'P1 build failure: unapproved or mutable build image' >&2
	exit 1
fi
if [ "$P1_SOURCE_COMMIT" != "$EXPECTED_COMMIT" ] || [ "$P1_SOURCE_TREE" != "$EXPECTED_TREE" ]; then
	echo 'P1 build failure: source base mismatch' >&2
	exit 1
fi
case "$P1_CANDIDATE_COMMIT:$P1_CANDIDATE_TREE" in
	*[!0-9a-f:]*) echo 'P1 build failure: invalid candidate source identity' >&2; exit 1 ;;
esac
if [ "${#P1_CANDIDATE_COMMIT}" -ne 40 ] || [ "${#P1_CANDIDATE_TREE}" -ne 40 ]; then
	echo 'P1 build failure: invalid candidate source identity' >&2
	exit 1
fi
case "$P1_SOURCE_DATE_EPOCH" in
	''|*[!0-9]*) echo 'P1 build failure: invalid source epoch' >&2; exit 1 ;;
esac

ROOT=$(cd "$P1_SOURCE_ROOT" && pwd -P)
OUTPUT=$(cd "$P1_OUTPUT_DIR" && pwd -P)
IDENTITY=$(cd "$(dirname "$P1_SOURCE_IDENTITY")" && pwd -P)/$(basename "$P1_SOURCE_IDENTITY")
POLICY="$ROOT/package/p1_policy.py"
ALLOWLIST="$ROOT/package/p1-allowlist.json"
APP_DIR="$ROOT/app"

if [ ! -f "$POLICY" ] || [ ! -f "$ALLOWLIST" ] || [ ! -f "$IDENTITY" ]; then
	echo 'P1 build failure: required policy input missing' >&2
	exit 1
fi
if [ "$OUTPUT" = "$ROOT" ] || [[ "$OUTPUT" == "$ROOT/"* ]]; then
	echo 'P1 build failure: output must be outside source export' >&2
	exit 1
fi

DIST_DIR="$APP_DIR/dist"
if [ -L "$DIST_DIR" ] || { [ -e "$DIST_DIR" ] && [ ! -d "$DIST_DIR" ]; }; then
	echo 'P1 build failure: generated-output path is not a regular directory' >&2
	exit 1
fi
mkdir -p "$DIST_DIR"
find "$DIST_DIR" -mindepth 1 -delete
if [ -n "$(find "$DIST_DIR" -mindepth 1 -print -quit)" ]; then
	echo 'P1 build failure: generated-output cleanup incomplete' >&2
	exit 1
fi

cd "$APP_DIR"
npm ci --ignore-scripts --no-audit --no-fund
npm run build
npm run eslint
python3 "$POLICY" validate-compiled --root "$ROOT" --allowlist "$ALLOWLIST"

VERSION=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["version"])' "$APP_DIR/package.json")
case "$VERSION" in
	*[!0-9A-Za-z.+:~-]*|'') echo 'P1 build failure: invalid package version' >&2; exit 1 ;;
esac

BUILD_TMP=$(mktemp -d /tmp/casanode-api-p1-package.XXXXXX)
trap 'find "$BUILD_TMP" -depth -delete 2>/dev/null || true' EXIT HUP INT TERM
STAGE="$BUILD_TMP/stage"
DEB="$OUTPUT/casanode-api_${VERSION}_all.deb"
MANIFEST="$OUTPUT/casanode-api_${VERSION}_all.members.json"
RESULT="$OUTPUT/casanode-api_${VERSION}_all.build-result.json"

for candidate in "$DEB" "$MANIFEST" "$RESULT"; do
	if [ -e "$candidate" ] || [ -L "$candidate" ]; then
		echo 'P1 build failure: output already exists' >&2
		exit 1
	fi
done

python3 "$POLICY" stage \
	--root "$ROOT" \
	--stage "$STAGE" \
	--allowlist "$ALLOWLIST" \
	--version "$VERSION" \
	--source-identity "$IDENTITY" \
	--build-image "$P1_BUILD_IMAGE" \
	--source-date-epoch "$P1_SOURCE_DATE_EPOCH" \
	--expected-candidate-commit "$P1_CANDIDATE_COMMIT" \
	--expected-candidate-tree "$P1_CANDIDATE_TREE"

export SOURCE_DATE_EPOCH="$P1_SOURCE_DATE_EPOCH"
dpkg-deb -Zxz -z9 --root-owner-group --build "$STAGE" "$DEB"
python3 "$POLICY" validate-deb \
	--deb "$DEB" \
	--allowlist "$ALLOWLIST" \
	--source-date-epoch "$P1_SOURCE_DATE_EPOCH" \
	--output "$MANIFEST"
python3 "$POLICY" build-result --deb "$DEB" --manifest "$MANIFEST" --output "$RESULT"

echo "P1 package built: $(basename "$DEB")"

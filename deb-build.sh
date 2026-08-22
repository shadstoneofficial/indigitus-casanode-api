#!/bin/bash
set -euo pipefail

EXPECTED_IMAGE='node@sha256:bde0dae02f2b12d2bce5ee72b2432f0e511767b7b2dc4dd3b064df11ae422fee'
EXPECTED_COMMIT='fa3a9cc3ffde779beb880b4a31be4bf673421ab8'
EXPECTED_TREE='7dd9b2bf3bb00a28c009410e040ee206ad3370d2'
SOURCE_DATE_EPOCH='1780346568'

: "${P1_EXPECTED_CANDIDATE_COMMIT:?P1_EXPECTED_CANDIDATE_COMMIT is required}"
: "${P1_EXPECTED_CANDIDATE_TREE:?P1_EXPECTED_CANDIDATE_TREE is required}"

if [ "$#" -ne 1 ]; then
	echo 'usage: ./deb-build.sh /absolute/output/directory' >&2
	exit 2
fi

REPOSITORY=$(cd "$(dirname "$0")" && pwd -P)
OUTPUT=$1
case "$OUTPUT" in
	/*) ;;
	*) echo 'P1 build failure: output path must be absolute' >&2; exit 1 ;;
esac
if [ -L "$OUTPUT" ]; then
	echo 'P1 build failure: output directory must not be a symlink' >&2
	exit 1
fi
mkdir -p "$OUTPUT"
OUTPUT=$(cd "$OUTPUT" && pwd -P)
if [ -n "$(find "$OUTPUT" -mindepth 1 -print -quit)" ]; then
	echo 'P1 build failure: output directory must be empty' >&2
	exit 1
fi
if [ "$OUTPUT" = "$REPOSITORY" ] || [[ "$OUTPUT" == "$REPOSITORY/"* ]]; then
	echo 'P1 build failure: output directory must be outside the repository' >&2
	exit 1
fi

if ! docker image inspect "$EXPECTED_IMAGE" >/dev/null 2>&1; then
	echo 'P1 build failure: verified immutable build image is unavailable; refusing to pull or resolve a tag' >&2
	exit 1
fi

BUILD_TMP=$(mktemp -d "$(dirname "$REPOSITORY")/.casanode-api-p1-host.XXXXXX")
BUILD_TMP=$(cd "$BUILD_TMP" && pwd -P)
trap 'find "$BUILD_TMP" -depth -delete 2>/dev/null || true' EXIT HUP INT TERM
SOURCE_EXPORT="$BUILD_TMP/source"
IDENTITY="$BUILD_TMP/source-identity.json"

python3 "$REPOSITORY/package/p1_policy.py" export-source \
	--repository "$REPOSITORY" \
	--destination "$SOURCE_EXPORT" \
	--identity-output "$IDENTITY" \
	--expected-commit "$P1_EXPECTED_CANDIDATE_COMMIT" \
	--expected-tree "$P1_EXPECTED_CANDIDATE_TREE"

if [ "${P1_SEED_STALE:-0}" = '1' ]; then
	mkdir -p "$SOURCE_EXPORT/app/dist/characteristics"
	printf '%s\n' 'harmless-p1-stale-sentinel' > "$SOURCE_EXPORT/app/dist/characteristics/stale.js"
elif [ "${P1_SEED_STALE:-0}" != '0' ]; then
	echo 'P1 build failure: invalid stale-seed selector' >&2
	exit 1
fi

docker run --rm \
	--name "casanode-api-p1-${P1_BUILD_ID:-candidate}" \
	--read-only \
	--tmpfs /tmp:rw,nosuid,nodev,noexec,mode=1777 \
	--tmpfs /root/.npm:rw,nosuid,nodev,noexec,mode=0700 \
	--volume "$SOURCE_EXPORT:/workspace:rw" \
	--volume "$IDENTITY:/p1/source-identity.json:ro" \
	--volume "$OUTPUT:/output:rw" \
	--workdir /workspace \
	--env P1_SOURCE_ROOT=/workspace \
	--env P1_OUTPUT_DIR=/output \
	--env P1_SOURCE_IDENTITY=/p1/source-identity.json \
	--env P1_BUILD_IMAGE="$EXPECTED_IMAGE" \
	--env P1_SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
	--env P1_SOURCE_COMMIT="$EXPECTED_COMMIT" \
	--env P1_SOURCE_TREE="$EXPECTED_TREE" \
	--env P1_CANDIDATE_COMMIT="$P1_EXPECTED_CANDIDATE_COMMIT" \
	--env P1_CANDIDATE_TREE="$P1_EXPECTED_CANDIDATE_TREE" \
	"$EXPECTED_IMAGE" \
	/bin/bash /workspace/package/build.sh

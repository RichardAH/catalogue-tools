#!/bin/sh
# Download the canonical Xahau catalogue set with plain curl (resumable).
# Prefer `catl fetch`, which also checks each file's SHA-512 as it streams.
#
#   scripts/fetch-canonical.sh /data/cat            # every finished file
#   scripts/fetch-canonical.sh /data/cat 18000001   # files from that ledger on
set -eu
DEST=${1:-.}
FROM=${2:-0}
URL=${CATL_URL:-https://cat.xahau.network/}
mkdir -p "$DEST"
curl -fsSL "$URL" | grep -o 'href="cat\.[0-9]*-[0-9]*"' | sed 's/href="//; s/"$//' | sort -u |
while read -r name; do
    hi=${name#*-}; hi=$(echo "$hi" | sed 's/^0*//')
    [ "${hi:-0}" -ge "$FROM" ] || continue
    echo ">> $name"
    curl -fL -C - -o "$DEST/$name" "$URL$name"
done
echo "done. Verify with:  catl verify '$DEST' --remote"

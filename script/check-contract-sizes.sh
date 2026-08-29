#!/usr/bin/env bash
set -euo pipefail

MAX_SIZE=24576
SRC_DIR="src"

failed=0
checked=0

echo "Checking deployed bytecode sizes for contracts in ${SRC_DIR}/..."
echo ""

while IFS= read -r -d '' source; do
    filename="${source##*/}"
    contract="${filename%.sol}"

    # Find the Foundry artifact by contract name.
    artifact=$(find out -type f -path "*/${contract}.json" | head -n 1)

    if [ -z "$artifact" ]; then
        echo "WARNING: artifact not found for ${source}"
        continue
    fi

    size=$(python - "$artifact" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as f:
    artifact = json.load(f)

bytecode = artifact.get("deployedBytecode", {}).get("object", "")

if not bytecode or bytecode == "0x":
    print("-1")
else:
    print((len(bytecode) - 2) // 2)
PY
)

    # Skip interfaces/abstract contracts without runtime bytecode.
    if [ "$size" -lt 0 ]; then
        continue
    fi

    margin=$((MAX_SIZE - size))
    checked=$((checked + 1))

    if [ "$size" -gt "$MAX_SIZE" ]; then
        echo "FAIL: ${contract} = ${size} bytes"
        echo "      Artifact: ${artifact}"
        echo "      EIP-170 limit: ${MAX_SIZE} bytes"
        echo "      Over limit by: $((-margin)) bytes"
        failed=1
    else
        echo "PASS: ${contract} = ${size} bytes"
        echo "      Artifact: ${artifact}"
        echo "      Margin: ${margin} bytes"
    fi
done < <(find "$SRC_DIR" -type f -name "*.sol" -print0)

echo ""

if [ "$checked" -eq 0 ]; then
    echo "ERROR: no deployable contracts found under ${SRC_DIR}/"
    exit 1
fi

if [ "$failed" -ne 0 ]; then
    echo "ERROR: one or more project contracts exceed the EIP-170 runtime size limit."
    exit 1
fi

echo "All ${checked} project contracts are within the EIP-170 limit."

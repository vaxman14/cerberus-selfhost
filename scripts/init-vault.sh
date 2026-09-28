#!/bin/sh
set -eu

echo "scripts/init-vault.sh is retained for compatibility." >&2
echo "Use ./scripts/setup.sh; it validates the key and initializes every private volume." >&2
exec ./scripts/setup.sh

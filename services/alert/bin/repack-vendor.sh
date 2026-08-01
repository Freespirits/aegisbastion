#!/usr/bin/env bash
# Refresh the vendored build inputs for services/alert:
#   - vendor/*.tgz           (npm pack of sdks/ts + gen/ts — the Docker build
#                             context cannot reach those sibling paths)
#   - schemas/alert/v1/*.json (mirror of the ratified schemas/alert/v1)
# Run from the repo root after changing sdks/ts, gen/ts, or schemas/alert/v1,
# then re-run `npm install` in services/alert.
set -euo pipefail
cd "$(dirname "$0")/../../.."

(cd sdks/ts && cmd //c "npm pack --pack-destination ..\\..\\services\\alert\\vendor" >/dev/null)
(cd gen/ts && cmd //c "npm pack --pack-destination ..\\..\\services\\alert\\vendor" >/dev/null)
cp schemas/alert/v1/*.json services/alert/schemas/alert/v1/
echo "vendor tarballs + schema copies refreshed"

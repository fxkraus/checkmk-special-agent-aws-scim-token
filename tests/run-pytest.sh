#!/bin/bash
# Run the pytest suite with the Checkmk Python interpreter and libraries.
# Intended to run inside the Checkmk image (see `make test`).
set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PYTHON="/omd/versions/default/bin/python3"
DEPS_DIR="$(mktemp -d)"

# Hash-pinned "test" dependency group, exported from uv.lock by the caller
# (`make test`, CI) because the Checkmk image has no uv:
#   uv export --locked --only-group test --no-emit-project --format requirements-txt
TEST_REQUIREMENTS="${TEST_REQUIREMENTS:-/test-requirements.txt}"
if [[ ! -r "${TEST_REQUIREMENTS}" ]]; then
    echo "ERROR: ${TEST_REQUIREMENTS} not found; mount the exported test requirements there" >&2
    exit 1
fi
"${PYTHON}" -m pip install --quiet --disable-pip-version-check --root-user-action=ignore \
    --require-hashes --no-deps --target "${DEPS_DIR}" -r "${TEST_REQUIREMENTS}"

# Fail loudly instead of letting the test modules skip themselves
"${PYTHON}" -c "import boto3, pydantic, cmk.agent_based.v2, cmk.rulesets.v1, cmk.server_side_calls.v1, cmk.utils.password_store"

cd "${REPO_DIR}"
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="${DEPS_DIR}:${REPO_DIR}" \
    "${PYTHON}" -m pytest -p no:cacheprovider "$@" tests/

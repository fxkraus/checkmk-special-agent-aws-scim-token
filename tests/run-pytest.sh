#!/bin/bash
# Run the pytest suite with the Checkmk Python interpreter and libraries.
# Intended to run inside the Checkmk image (see `make test`).
set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PYTHON="/omd/versions/default/bin/python3"
DEPS_DIR="$(mktemp -d)"

# The "test" dependency group from pyproject.toml (kept current by Dependabot).
# Read with tomllib because the Checkmk image has no uv.
TEST_DEPS_LINES="$("${PYTHON}" -c \
    'import sys, tomllib; print("\n".join(tomllib.load(open(sys.argv[1], "rb"))["dependency-groups"]["test"]))' \
    "${REPO_DIR}/pyproject.toml")"
mapfile -t TEST_DEPS <<< "${TEST_DEPS_LINES}"
"${PYTHON}" -m pip install --quiet --disable-pip-version-check --target "${DEPS_DIR}" "${TEST_DEPS[@]}"

# Fail loudly instead of letting the test modules skip themselves
"${PYTHON}" -c "import boto3, pydantic, cmk.agent_based.v2, cmk.rulesets.v1, cmk.server_side_calls.v1, cmk.graphing.v1, cmk.utils.password_store"

cd "${REPO_DIR}"
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="${DEPS_DIR}:${REPO_DIR}" \
    "${PYTHON}" -m pytest -p no:cacheprovider "$@" tests/

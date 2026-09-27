#!/usr/bin/env bash
# Build entrypoint: packages the AWS SCIM token special agent as an MKP extension.
# Runs inside the Checkmk Docker container.
# See https://docs.checkmk.com/latest/en/mkps.html

set -euo pipefail

SOURCE=/source
CMK=/omd/sites/cmk
PLUGIN_DIR="${CMK}/local/lib/python3/cmk_addons/plugins/aws_scim_token"

# Copy the plugin family into the site's local hierarchy, without caches
mkdir -p "$(dirname "${PLUGIN_DIR}")"
cp -R "${SOURCE}/cmk_addons/plugins/aws_scim_token" "${PLUGIN_DIR}"
find "${PLUGIN_DIR}" -name __pycache__ -type d -prune -exec rm -rf {} +
chmod 0755 "${PLUGIN_DIR}/libexec/agent_aws_scim_token"

# Create the MKP manifest template (must be run as site user).
# Since Checkmk 2.5 the template is printed to stdout instead of written to a file.
MANIFEST="${CMK}/tmp/aws_scim_token.manifest"
su - cmk -c "/omd/sites/cmk/bin/mkp template aws_scim_token" > "${MANIFEST}"

# Allow git operations on the mounted source directory
git config --global --add safe.directory "${SOURCE}"

# Derive package version from git tags
TAG=$(git -C "${SOURCE}" describe --exact-match --tags HEAD 2>/dev/null || true)
if [[ -n "${TAG}" ]]; then
  VERSION="${TAG#v}"
else
  SHORT_SHA=$(git -C "${SOURCE}" rev-parse --short=8 HEAD)
  VERSION=$(printf '0.0.%d' "0x${SHORT_SHA}")
fi
echo "Derived version: ${VERSION}"

# Checkmk crashes parsing non-standard versions such as 1.2.3-alpha.1
if [[ ! "${VERSION}" =~ ^[0-9]+\.[0-9]+\.[0-9]+([ipb][0-9]+)?$ ]]; then
  echo "ERROR: '${VERSION}' is not a valid Checkmk version (e.g. 1.2.3, 1.2.3p1, 1.2.3i1, 1.2.3b1)" >&2
  exit 1
fi

# Inject version number and metadata into the manifest
/build-modify-extension.py "${VERSION}" "${MANIFEST}"

# mkp runs as the site user and must own the files; never ship world-writable files
chown -R cmk:cmk "${PLUGIN_DIR}"
chmod -R u=rwX,go=rX "${PLUGIN_DIR}"

# Package the MKP (must be run as site user)
su - cmk -c "/omd/sites/cmk/bin/mkp package ${MANIFEST}"

# Copy the built MKP back to the mounted source volume
cp "${CMK}/var/check_mk/packages_local/"*.mkp "${SOURCE}"

# Let the CI runner user read the created MKP file
chmod go+r "${SOURCE}/"*.mkp

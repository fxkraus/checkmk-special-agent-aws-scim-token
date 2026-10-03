# aws_scim_token — Checkmk Special Agent

Monitors the expiration date of AWS IAM Identity Center **SCIM access tokens** and reports them as a Checkmk service. Sends WARN/CRIT alerts before a token expires so it can be rotated in time.

## How it works

AWS raises the AWS Health event `AWS_IAMIDENTITYCENTER_SCIM_BEARER_TOKEN_EXPIRY_NOTIFICATION`
(service `IAMIDENTITYCENTER`, category `accountNotification`) once a SCIM access token is
**90 days or less** from expiry
([AWS docs](https://docs.aws.amazon.com/singlesignon/latest/userguide/provision-automatically.html)).
The special agent reports every open event; the check plugin turns them into a single
`AWS SCIM Token` service:

- No open event → **OK** (no token expires within 90 days).
- One result line per token, with WARN/CRIT based on the configured thresholds.
- The expiry date is parsed from the event description. If no date can be found, the token is reported as **WARN** ("expires within 90 days").
- AWS API errors (missing permissions, no support plan, no credentials) → **CRIT**.

There is no public AWS API that lists SCIM access tokens directly, so AWS Health is the only data source.

## Requirements

| Component | Minimum version |
|-----------|----------------|
| Checkmk | 2.4.0 |
| Python | 3.12 (ships with Checkmk 2.4) |
| boto3 | 1.34 (ships with Checkmk) |
| AWS Support plan | Business, Enterprise On-Ramp, or Enterprise (required by the AWS Health API) |

## Installation

### Via MKP package (recommended)

```bash
# On the Checkmk site
mkp add aws_scim_token-1.0.0.mkp   # from the GitHub Releases page
mkp enable aws_scim_token 1.0.0
```

### Manual

Copy the plugin directory into the site and make the agent executable:

```bash
cp -r cmk_addons/plugins/aws_scim_token ~/local/lib/python3/cmk_addons/plugins/
chmod +x ~/local/lib/python3/cmk_addons/plugins/aws_scim_token/libexec/agent_aws_scim_token
```

## IAM Permissions

Minimum IAM policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "health:DescribeEvents",
        "health:DescribeEventDetails",
        "health:DescribeAffectedEntities"
      ],
      "Resource": "*"
    }
  ]
}
```

When using **Assume Role**, additionally attach `sts:AssumeRole` on the calling principal and the appropriate trust policy on the target role.

## Configuration

### 1. Add the special agent rule

In Checkmk: **Setup → Agents → Other integrations → Cloud → AWS SCIM Token Monitor**

Create a rule for the host that represents the AWS account.

| Field | Description |
|-------|-------------|
| **AWS Region** | Region for STS calls (AWS Health always uses `us-east-1`) |
| **Static access key** | Access Key ID + Secret Access Key. Leave unset to use the instance profile or environment. The secret is passed to the agent as a password store reference, never in plain text on the command line. |
| **Assume Role → Role ARN** | IAM role to assume before querying AWS (cross-account or least-privilege) |
| **Assume Role → External ID** | Required if the role's trust policy has an `sts:ExternalId` condition |
| **Assume Role → Session Name** | STS session name (default: `checkmk-scim-monitor`) |
| **Override AWS Health event type codes** | Only needed if AWS renames the event (default: `AWS_IAMIDENTITYCENTER_SCIM_BEARER_TOKEN_EXPIRY_NOTIFICATION`) |

### 2. Set check parameters (optional)

In Checkmk: **Setup → Services → Service monitoring rules → AWS SCIM Token Expiration**

| Parameter | Default | Description |
|-----------|---------|-------------|
| **Warning threshold** | 30 days | WARN when N days or fewer remain |
| **Critical threshold** | 14 days | CRIT when N days or fewer remain |

## Assume Role

Assume Role is useful for **cross-account monitoring** or enforcing **least-privilege** on the Checkmk server credentials.

```
Checkmk server
  └─ STS AssumeRole ──► arn:aws:iam::TARGET_ACCOUNT:role/CheckmkScimMonitor
                            └─ health:DescribeEvents …
```

Example role trust policy (attach to the target role):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::MONITORING_ACCOUNT:role/CheckmkInstanceRole"
      },
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringEquals": {
          "sts:ExternalId": "checkmk-scim-monitor"
        }
      }
    }
  ]
}
```

Enter the same value (`checkmk-scim-monitor` here) as **External ID** in the special agent rule.

## Testing

Run the agent manually as the site user:

```bash
AGENT=~/local/lib/python3/cmk_addons/plugins/aws_scim_token/libexec/agent_aws_scim_token

# Instance profile / environment credentials
$AGENT --region eu-central-1

# With Assume Role and External ID
$AGENT --region eu-central-1 \
  --role-arn arn:aws:iam::123456789012:role/CheckmkScimMonitor \
  --external-id checkmk-scim-monitor
```

Expected output:

```
<<<aws_scim_token:sep(0)>>>
{"name": "<affected entity>", "expiry": "2026-12-31T00:00:00+00:00", "source": "arn:aws:health:...", "detail": "..."}
```

No lines after the header means there is no open expiry notification.

## Checkmk service output examples

| State | Summary |
|-------|---------|
| OK | `No SCIM token expiry notifications (no token expires within 90 days)` |
| OK | `<token>: expires in 45.2 days (2026-12-31 00:00 UTC) [arn:aws:health:…]` |
| WARN | `<token>: expires in 22.1 days (2026-12-31 00:00 UTC) [arn:aws:health:…]` |
| WARN | `<token>: expires within 90 days, date not found in AWS Health event [arn:aws:health:…]` |
| CRIT | `<token>: expires in 7.0 days (2026-12-31 00:00 UTC) [arn:aws:health:…]` |
| CRIT | `<token>: EXPIRED on 2026-01-01 00:00 UTC [arn:aws:health:…]` |
| CRIT | `Error querying AWS: AWS Health API requires Business, Enterprise On-Ramp, or Enterprise Support` |

## Repository layout

```
checkmk-special-agent-aws-scim-token/
├── cmk_addons/plugins/aws_scim_token/
│   ├── agent_based/aws_scim_token.py           # Check plugin
│   ├── libexec/agent_aws_scim_token            # Special agent executable (thin wrapper)
│   ├── special_agents/agent_aws_scim_token.py  # Special agent implementation
│   ├── server_side_calls/special_agent.py      # Rule parameters → agent command line
│   └── rulesets/
│       ├── special_agent.py                    # Setup: agent configuration
│       └── check_parameters.py                 # Setup: warn/crit thresholds
├── build/
│   ├── Dockerfile                              # Checkmk 2.5 image used to package the MKP
│   ├── build-entrypoint.sh                     # Packages the MKP inside the container
│   └── build-modify-extension.py               # Injects git version + metadata into the manifest
├── tests/
│   ├── run-pytest.sh                           # Runs pytest with the Checkmk interpreter
│   └── test_*.py                               # Unit tests (real Checkmk libraries, mocked AWS)
├── .github/
│   ├── dependabot.yml                          # Weekly uv, pre-commit and Actions updates
│   └── workflows/
│       ├── ci.yml                              # Lint, secret scan, image digests, tests (CMK 2.4 + 2.5), MKP build, release
│       ├── pr-title.yml                        # PR title must be a Conventional Commit
│       └── dependabot-auto-merge.yml           # Auto-merge minor/patch uv + pre-commit updates
├── .pre-commit-config.yaml                     # Linters + secret scan (local and CI)
├── Makefile                                    # lint / secrets / test / build
├── pyproject.toml                              # uv dependency groups + commitizen, ruff, mypy config
└── uv.lock                                     # Reproducible dev env
```

## Development

Python dev dependencies (pytest, ruff, mypy, pre-commit, commitizen) are declared in
`pyproject.toml` and pinned in `uv.lock`. Create the local `.venv` and enable
the hooks in your clone before the first commit:

```bash
uv sync
uv run pre-commit install
```

| Command | Description |
|---------|-------------|
| `make lint` | Run all pre-commit hooks (same as the CI `lint` job) |
| `make secrets` | Scan the full git history for secrets (gitleaks, Docker) |
| `make format` | Format and autofix Python code with ruff |
| `make test` | Run pytest with the real Checkmk libraries inside the build image (hash-pinned test deps from `uv.lock`) |
| `make build` | Build the MKP (`./aws_scim_token-<version>.mkp`) in the Checkmk image |

The tests import the real `cmk` libraries, so they run inside a Checkmk image,
not in a plain virtualenv. CI runs them against Checkmk 2.4 and 2.5; all AWS
API calls are mocked.

### Pre-commit hooks

All linters and the secret scan are defined in `.pre-commit-config.yaml`.
CI runs exactly the same hooks, so a clean local run means a clean CI run.

| Hook | Checks |
|------|--------|
| commitizen | commit message is a [Conventional Commit](https://www.conventionalcommits.org/) (`commit-msg` stage) |
| gitleaks, detect-private-key | secrets and private keys in staged changes |
| ruff (check + format) | Python lint and formatting |
| mypy | type checks for the plugin and build script |
| shellcheck | shell scripts |
| hadolint | `build/Dockerfile` |
| actionlint | GitHub Actions workflows |
| pre-commit-hooks | YAML/TOML/JSON syntax, large files, merge conflicts, whitespace, shebangs |

## CI

Every push to `main` and every pull request runs `lint`, `secrets`,
`pytest (Checkmk 2.4)`, `pytest (Checkmk 2.5)` and `mkp`; pull requests also
run `pr-title`. For Dependabot auto-merge to wait for them, enable
**Settings → General → Allow auto-merge** and add a branch ruleset on `main`
that requires these checks.

Supply-chain hardening:

- The `images` job resolves the floating `checkmk/*:2.x.0-latest` tags to
  digests once per run; tests, MKP build and release all use these digests
  (printed as `Image: …@sha256:…` in the logs).
- The test dependencies are installed with `pip --require-hashes` from
  `uv export` of `uv.lock`, including all transitive packages.
- No checkout keeps the `GITHUB_TOKEN` in `.git/config`, and only the final
  `release` job has `contents: write`; it runs no repository or dependency
  code.
- Dependabot waits 7 days after an upstream release before proposing it.
- The tag ruleset "release tags immutable" (`refs/tags/v*`: deletion, update,
  force push; no bypass) keeps published release tags from being moved or
  deleted, also by the CI token. Creating tags cannot be limited to GitHub
  Actions in a user-owned repository (app bypass actors need an organization),
  so tag creation is limited only by `contents: write`, which CI grants
  solely to the `release` job.

## Release

Releases are fully automatic. Pull requests are squash-merged with only the
PR title as the commit message (the PR body is not included), and the PR
title must be a [Conventional Commit](https://www.conventionalcommits.org/).
Mark a breaking change in a PR title with `!`, e.g. `feat!: …`. After every push
to `main`, once all CI jobs pass, the `release` job derives the next version
from the commits since the last `v*` tag:

| Commit | Release |
|--------|---------|
| `fix:`, `perf:`, `refactor:` | patch (`1.0.0` → `1.0.1`) |
| `feat:` | minor (`1.0.0` → `1.1.0`) |
| `feat!:`, `fix!:` or a `BREAKING CHANGE:` footer | major (`1.0.0` → `2.0.0`) |
| `docs:`, `ci:`, `build:`, `chore:`, `style:`, `test:` | no release |

It then builds the MKP with the real `mkp` tool in the same Checkmk 2.5
image the other jobs tested (`release-build`, read-only), and the `release`
job tags the commit and publishes a GitHub Release with the MKP and release
notes generated from the commits. The version exists only as the git tag;
nothing is committed back. The [Releases](https://github.com/fxkraus/checkmk-special-agent-aws-scim-token/releases)
page is the changelog. Untagged builds get a numeric version derived from the
commit hash.

## License

Copyright (C) 2026 Felix Kraus

This project is licensed under the GNU General Public License v2.0, see
[LICENSE](LICENSE). Security issues: see [SECURITY.md](SECURITY.md).

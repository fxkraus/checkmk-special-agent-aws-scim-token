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
- AWS renews the event until the token expires. Recently closed events (last updated within 30 days)
  are reported as well if AWS tracked the token until its expiry date and that date has passed, so an
  expired token stays **CRIT** for 30 days instead of turning OK once AWS stops renewing the event.
  Closed events of rotated or deleted tokens are ignored.
- Renewed events of the same token and expiry date are reported once.
- One result line per token, with WARN/CRIT based on the configured thresholds. The long output shows the
  start of the AWS Health event description, to check the parsed expiry date against.
- The expiry date is parsed from the event description: the first date that follows "expires"/"expiry"/"expiration", otherwise the first future date in the text (a past date without that keyword is more likely the notification date). A date without a time of day counts as its end (23:59:59 UTC). If no date can be found, the token is reported as **WARN** ("expires within 90 days").
- AWS API errors (missing permissions, no support plan, no credentials) → **CRIT**. ARNs and account IDs in
  AWS error messages are replaced by `<arn>` / `<account>`, so they do not end up in service output and notifications.

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
| **AWS Region** | Region for STS calls. Its partition selects the AWS Health endpoint: `us-east-1` (failover `us-east-2`), `cn-northwest-1` for China, `us-gov-west-1` for GovCloud. Other partitions (e.g. ISO) have no AWS Health endpoint and are reported as an error |
| **Static access key** | Access Key ID + Secret Access Key. Leave unset to use the instance profile or environment. The secret is passed to the agent as a password store reference, never in plain text on the command line. |
| **Assume Role → Role ARN** | IAM role to assume before querying AWS (cross-account or least-privilege) |
| **Assume Role → External ID** | Required if the role's trust policy has an `sts:ExternalId` condition |
| **Assume Role → Session Name** | STS session name, 2–64 characters of `A-Za-z0-9_+=,.@-` (default: `checkmk-scim-monitor`) |
| **Override AWS Health event type codes** | Only needed if AWS renames the event (default: `AWS_IAMIDENTITYCENTER_SCIM_BEARER_TOKEN_EXPIRY_NOTIFICATION`); at most 10 codes |

AWS Health data changes at most daily, so a longer check interval for this host
(e.g. **Setup → Services → Service monitoring rules → Normal check interval for
service checks**, 30–60 min for `Check_MK`) saves API calls. Every AWS call
times out after 5 s (connect) / 15 s (read), with up to 3 attempts per call.
If the primary AWS Health endpoint is unreachable, times out, returns a server error or
throttles, the agent fails over to the partition's secondary endpoint (`us-east-2`).

### 2. Set check parameters (optional)

In Checkmk: **Setup → Services → Service monitoring rules → AWS SCIM Token Expiration**

| Parameter | Default | Description |
|-----------|---------|-------------|
| **Lower levels for the remaining token lifetime** | Fixed: warn 30 / crit 14 days | WARN/CRIT when N days or fewer remain. "No levels" turns the service CRIT only once a token has expired. |

The warning level must not be lower than the critical level; negative values are rejected.
Rules created with older versions (separate warning/critical fields) are migrated automatically.

The service records the metric `aws_scim_token_days_remaining` (soonest expiring token) with the
levels as threshold lines in the graph, plus a perfometer (0–90 days).

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
{"name": "<affected entity>", "expiry": "2026-12-31T23:59:59+00:00", "source": "arn:aws:health:...", "detail": "..."}
```

No lines after the header means there is no open expiry notification.

## Checkmk service output examples

| State | Summary |
|-------|---------|
| OK | `No SCIM token expiry notifications (no token expires within 90 days)` |
| OK | `<token>: expires in 45.2 days (2026-12-31 23:59 UTC) [arn:aws:health:…]` |
| WARN | `<token>: expires in 22.1 days (2026-12-31 23:59 UTC) (warn/crit at 30/14 days or fewer) [arn:aws:health:…]` |
| WARN | `<token>: expires within 90 days, date not found in AWS Health event [arn:aws:health:…]` |
| CRIT | `<token>: expires in 7.0 days (2026-12-31 23:59 UTC) (warn/crit at 30/14 days or fewer) [arn:aws:health:…]` |
| CRIT | `<token>: EXPIRED on 2026-01-01 23:59 UTC [arn:aws:health:…]` |
| CRIT | `Error querying AWS: AWS Health API requires Business, Enterprise On-Ramp, or Enterprise Support` |

## Repository layout

```
checkmk-special-agent-aws-scim-token/
├── cmk_addons/plugins/aws_scim_token/
│   ├── agent_based/aws_scim_token.py           # Check plugin
│   ├── libexec/agent_aws_scim_token            # Special agent executable (thin wrapper)
│   ├── special_agents/agent_aws_scim_token.py  # Special agent implementation
│   ├── server_side_calls/special_agent.py      # Rule parameters → agent command line
│   ├── graphing/aws_scim_token.py              # Metric and perfometer definitions
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

Python dev dependencies (pytest, ruff, pre-commit, commitizen) are declared in
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
| mypy | type checks for the plugin and build script (pre-commit only; its version is the hook `rev`, pydantic matches the oldest supported Checkmk) |
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
- The pre-commit hook repos are pinned to commit SHAs (`# frozen: vX.Y.Z`
  names the release) and `make secrets` runs the gitleaks image by digest,
  so moved upstream tags cannot change the code that runs on commit.
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

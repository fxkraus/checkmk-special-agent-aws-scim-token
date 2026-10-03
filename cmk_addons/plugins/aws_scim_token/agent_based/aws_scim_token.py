"""Checkmk check plugin: AWS SCIM Token expiration.

Section format (one JSON object per line, possibly none):
  {"name": "my-token", "expiry": "2026-12-31T23:59:59+00:00", "source": "<event arn>", "detail": "..."}
  {"name": "my-token", "expiry": null, "source": "<event arn>", "detail": "..."}
  {"error": "AccessDenied ..."}

AWS only raises an expiry event once a token is 90 days or less from expiry,
so an empty section is the healthy state.
"""

import json
from datetime import UTC, datetime

from cmk.agent_based.v2 import (
    AgentSection,
    CheckPlugin,
    CheckResult,
    DiscoveryResult,
    Metric,
    Result,
    Service,
    State,
    StringTable,
)


def _parse_expiry(expiry_str: str) -> datetime | None:
    try:
        dt = datetime.fromisoformat(expiry_str)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def parse_aws_scim_token(string_table: StringTable) -> list[dict]:
    records: list[dict] = []
    for row in string_table:
        try:
            record = json.loads(row[0])
        except (json.JSONDecodeError, IndexError):
            continue
        if isinstance(record, dict):
            records.append(record)
    return records


agent_section_aws_scim_token = AgentSection(
    name="aws_scim_token",
    parse_function=parse_aws_scim_token,
)


def discover_aws_scim_token(section: list[dict]) -> DiscoveryResult:
    yield Service()


def _check_token(token: dict, now: datetime, levels: tuple[float, float] | None) -> tuple[Result, float | None]:
    name = token.get("name", "unknown")
    source = f" [{token['source']}]" if token.get("source") else ""
    expiry_str = token.get("expiry")
    if not expiry_str:
        return Result(state=State.WARN, summary=f"{name}: expires within 90 days, date not found in AWS Health event{source}"), None

    expiry_dt = _parse_expiry(expiry_str)
    if expiry_dt is None:
        return Result(state=State.UNKNOWN, summary=f"{name}: cannot parse expiry date {expiry_str!r}{source}"), None

    days = (expiry_dt - now).total_seconds() / 86400.0
    expiry_fmt = expiry_dt.astimezone(UTC).strftime("%Y-%m-%d %H:%M UTC")
    if days <= 0:
        return Result(state=State.CRIT, summary=f"{name}: EXPIRED on {expiry_fmt}{source}"), days
    state = State.OK
    levels_text = ""
    if levels is not None:
        warn_days, crit_days = levels
        if days <= crit_days:
            state = State.CRIT
        elif days <= warn_days:
            state = State.WARN
        if state is not State.OK:
            levels_text = f" (warn/crit at {warn_days:g}/{crit_days:g} days or fewer)"
    return Result(state=state, summary=f"{name}: expires in {days:.1f} days ({expiry_fmt}){levels_text}{source}"), days


def check_aws_scim_token(params: dict, section: list[dict]) -> CheckResult:
    levels_type, levels = params["levels"]
    if levels_type != "fixed":
        levels = None
    now = datetime.now(UTC)

    errors = [r["error"] for r in section if "error" in r]
    tokens = [r for r in section if "error" not in r]

    for error in errors:
        yield Result(state=State.CRIT, summary=f"Error querying AWS: {error}")

    remaining: list[float] = []
    for token in tokens:
        result, days = _check_token(token, now, levels)
        if detail := token.get("detail"):
            result = Result(state=result.state, summary=result.summary, details=f"{result.summary}\nAWS Health event: {detail}")
        yield result
        if days is not None:
            remaining.append(days)

    if remaining:
        # Lower levels: Checkmk draws them as threshold lines in the graph
        yield Metric("aws_scim_token_days_remaining", min(remaining), levels=levels, boundaries=(0.0, None))

    if not errors and not tokens:
        yield Result(state=State.OK, summary="No SCIM token expiry notifications (no token expires within 90 days)")


check_plugin_aws_scim_token = CheckPlugin(
    name="aws_scim_token",
    service_name="AWS SCIM Token",
    discovery_function=discover_aws_scim_token,
    check_function=check_aws_scim_token,
    check_default_parameters={
        "levels": ("fixed", (30, 14)),
    },
    check_ruleset_name="aws_scim_token",
)

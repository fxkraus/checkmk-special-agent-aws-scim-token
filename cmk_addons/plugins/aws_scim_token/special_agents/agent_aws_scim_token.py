"""Checkmk special agent: AWS IAM Identity Center SCIM token expiration.

AWS raises the AWS Health event
``AWS_IAMIDENTITYCENTER_SCIM_BEARER_TOKEN_EXPIRY_NOTIFICATION`` (service
``IAMIDENTITYCENTER``, category ``accountNotification``) once a SCIM access
token is 90 days or less from expiry. This agent reports every open event.

Notes:
  - The AWS Health API requires a Business, Enterprise On-Ramp, or Enterprise
    Support plan.
  - The Health API is served from us-east-1 regardless of ``--region``.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

import boto3
from botocore.exceptions import BotoCoreError, ClientError

if TYPE_CHECKING:
    from collections.abc import Sequence

SECTION_HEADER = "<<<aws_scim_token:sep(0)>>>"
DEFAULT_EVENT_TYPE_CODE = "AWS_IAMIDENTITYCENTER_SCIM_BEARER_TOKEN_EXPIRY_NOTIFICATION"
HEALTH_REGION = "us-east-1"
DETAILS_BATCH_SIZE = 10  # DescribeEventDetails accepts at most 10 ARNs

_ISO_RE = re.compile(r"\b(\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)?)\b")
_MONTHS = ("jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec")
_MONTH = r"\b(" + "|".join(_MONTHS) + r")[a-z]*\.?"
_MONTH_DAY_YEAR_RE = re.compile(_MONTH + r"\s+(\d{1,2}),?\s+(\d{4})\b", re.IGNORECASE)
_DAY_MONTH_YEAR_RE = re.compile(r"\b(\d{1,2})\s+" + _MONTH + r",?\s+(\d{4})\b", re.IGNORECASE)
_EXPIRY_KEYWORD_RE = re.compile(r"\bexpir\w*", re.IGNORECASE)
EXPIRY_DATE_WINDOW = 80  # max. characters between "expires" and the date it refers to


def _parse_dt(value: str) -> datetime | None:
    for candidate in (value, value[:10]):
        try:
            dt = datetime.fromisoformat(candidate)
        except ValueError:
            continue
        return dt if dt.tzinfo else dt.replace(tzinfo=UTC)
    return None


def _date(year: str, month: str, day: str) -> datetime | None:
    try:
        return datetime(int(year), _MONTHS.index(month[:3].lower()) + 1, int(day), tzinfo=UTC)
    except ValueError:
        return None


def _dates_in_text(text: str) -> list[tuple[int, datetime]]:
    """Return every recognisable date in the text with its position, in text order."""
    found = [(m.start(), _parse_dt(m.group(1))) for m in _ISO_RE.finditer(text)]
    found += [(m.start(), _date(m.group(3), m.group(1), m.group(2))) for m in _MONTH_DAY_YEAR_RE.finditer(text)]
    found += [(m.start(), _date(m.group(3), m.group(2), m.group(1))) for m in _DAY_MONTH_YEAR_RE.finditer(text)]
    return sorted((pos, dt) for pos, dt in found if dt)


def _dt_from_text(text: str) -> datetime | None:
    """Return the expiry date from free-form event description text.

    Prefers the first date shortly after an "expire(s|d)/expiry/expiration"
    keyword, so that other dates in the text (notification or creation date)
    are skipped. Falls back to the first date anywhere in the text.
    """
    dates = _dates_in_text(text)
    for keyword in _EXPIRY_KEYWORD_RE.finditer(text):
        for pos, dt in dates:
            if keyword.end() <= pos <= keyword.end() + EXPIRY_DATE_WINDOW:
                return dt
    return dates[0][1] if dates else None


def _dt_to_str(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S+00:00")


def _lookup_secret(reference: str) -> str:
    """Resolve a Checkmk password store reference of the form ``<id>:<file>``."""
    from cmk.utils import password_store  # noqa: PLC0415 - only available inside a Checkmk site

    pw_id, pw_file = reference.split(":", 1)
    return str(password_store.lookup(Path(pw_file), pw_id))


def build_session(args: argparse.Namespace) -> boto3.Session:
    kwargs: dict[str, str] = {"region_name": args.region}
    if args.access_key_id:
        kwargs["aws_access_key_id"] = args.access_key_id
        kwargs["aws_secret_access_key"] = _lookup_secret(args.secret_access_key_reference)
    session = boto3.Session(**kwargs)

    if not args.role_arn:
        return session

    assume_kwargs = {"RoleArn": args.role_arn, "RoleSessionName": args.session_name}
    if args.external_id:
        assume_kwargs["ExternalId"] = args.external_id
    creds = session.client("sts").assume_role(**assume_kwargs)["Credentials"]
    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
        region_name=args.region,
    )


def _token_name(client: Any, arn: str) -> str:
    try:
        entities = client.describe_affected_entities(filter={"eventArns": [arn]}).get("entities", [])
    except ClientError:
        entities = []
    if entities and (name := entities[0].get("entityValue") or entities[0].get("entityUrl")):
        return str(name)
    return arn.rsplit("/", 1)[-1]


def fetch_token_events(session: boto3.Session, event_type_codes: list[str]) -> list[dict[str, Any]]:
    """Return one record per open SCIM token expiry event, or an error record."""
    client = session.client("health", region_name=HEALTH_REGION)
    results: list[dict[str, Any]] = []
    try:
        events: list[dict[str, Any]] = []
        paginator = client.get_paginator("describe_events")
        event_filter = {"eventTypeCodes": event_type_codes, "eventStatusCodes": ["open", "upcoming"]}
        for page in paginator.paginate(filter=event_filter):
            events.extend(page.get("events", []))

        for offset in range(0, len(events), DETAILS_BATCH_SIZE):
            chunk = events[offset : offset + DETAILS_BATCH_SIZE]
            resp = client.describe_event_details(eventArns=[e["arn"] for e in chunk], locale="en")
            details = {d["event"]["arn"]: d for d in resp.get("successfulSet", [])}
            results.extend({"error": f"DescribeEventDetails failed for {failed.get('eventArn')}: {failed.get('errorMessage')}"} for failed in resp.get("failedSet", []))

            for event in chunk:
                arn = event["arn"]
                if arn not in details:
                    continue
                description = details[arn].get("eventDescription", {}).get("latestDescription", "")
                expiry = _dt_from_text(description)
                results.append(
                    {
                        "name": _token_name(client, arn),
                        "expiry": _dt_to_str(expiry) if expiry else None,
                        "source": arn,
                        "detail": " ".join(description.split())[:200],
                    }
                )
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "SubscriptionRequiredException":
            results.append({"error": "AWS Health API requires Business, Enterprise On-Ramp, or Enterprise Support"})
        else:
            results.append({"error": str(exc)})
    except BotoCoreError as exc:
        results.append({"error": str(exc)})
    return results


def parse_arguments(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--region", default="us-east-1", help="Region for STS (Health always uses us-east-1)")
    parser.add_argument("--access-key-id", help="Static access key ID; omit to use the default credential chain")
    parser.add_argument("--secret-access-key-reference", help="Checkmk password store reference (<id>:<file>)")
    parser.add_argument("--role-arn", help="IAM role to assume before querying AWS")
    parser.add_argument("--external-id", help="External ID required by the role's trust policy")
    parser.add_argument("--session-name", default="checkmk-scim-monitor")
    parser.add_argument(
        "--event-type-codes",
        nargs="+",
        default=[DEFAULT_EVENT_TYPE_CODE],
        help=f"AWS Health event type codes to report (default: {DEFAULT_EVENT_TYPE_CODE})",
    )
    args = parser.parse_args(argv)
    if bool(args.access_key_id) != bool(args.secret_access_key_reference):
        parser.error("--access-key-id and --secret-access-key-reference must be given together")
    return args


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_arguments(argv)
    try:
        session = build_session(args)
    except (ClientError, BotoCoreError, ValueError) as exc:
        sys.stderr.write(f"ERROR: Failed to create AWS session: {exc}\n")
        return 1

    print(SECTION_HEADER)
    for record in fetch_token_events(session, args.event_type_codes):
        print(json.dumps(record))
    return 0

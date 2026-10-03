"""Checkmk special agent: AWS IAM Identity Center SCIM token expiration.

AWS raises the AWS Health event
``AWS_IAMIDENTITYCENTER_SCIM_BEARER_TOKEN_EXPIRY_NOTIFICATION`` (service
``IAMIDENTITYCENTER``, category ``accountNotification``) once a SCIM access
token is 90 days or less from expiry. This agent reports every open event.

Notes:
  - The AWS Health API requires a Business, Enterprise On-Ramp, or Enterprise
    Support plan.
  - The Health API is served from one endpoint per partition (us-east-1 with
    failover to us-east-2 for the commercial partition), regardless of
    ``--region``; only the partition of ``--region`` is used.
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
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError
from botocore.exceptions import ConnectionError as BotoConnectionError

if TYPE_CHECKING:
    from collections.abc import Sequence

SECTION_HEADER = "<<<aws_scim_token:sep(0)>>>"
DEFAULT_EVENT_TYPE_CODE = "AWS_IAMIDENTITYCENTER_SCIM_BEARER_TOKEN_EXPIRY_NOTIFICATION"
HEALTH_REGIONS = {
    "aws": ("us-east-1", "us-east-2"),
    "aws-cn": ("cn-northwest-1",),
    "aws-us-gov": ("us-gov-west-1",),
}
BATCH_SIZE = 10  # DescribeEventDetails and DescribeAffectedEntities accept at most 10 event ARNs
CLIENT_CONFIG = Config(connect_timeout=5, read_timeout=15, retries={"mode": "standard", "max_attempts": 3})

_ISO_RE = re.compile(r"\b(\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}:\d{2}(?:Z|[+-]\d{2}:?\d{2})?)?)\b")
_MONTHS = ("jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec")
_MONTH = r"(" + "|".join(_MONTHS) + r")[a-z]*\.?"
_MONTH_DAY_YEAR_RE = re.compile(_MONTH + r"\s+(\d{1,2}),?\s+(\d{4})\b", re.IGNORECASE)
_DAY_MONTH_YEAR_RE = re.compile(r"\b(\d{1,2})\s+" + _MONTH + r",?\s+(\d{4})\b", re.IGNORECASE)
_PARSE_FMTS = (
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%d %H:%M:%S%z",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d",
)


def _parse_dt(value: str) -> datetime | None:
    for fmt in _PARSE_FMTS:
        try:
            dt = datetime.strptime(value, fmt)
        except ValueError:
            continue
        return dt if dt.tzinfo else dt.replace(tzinfo=UTC)
    return None


def _date(year: str, month: str, day: str) -> datetime | None:
    try:
        return datetime(int(year), _MONTHS.index(month[:3].lower()) + 1, int(day), tzinfo=UTC)
    except ValueError:
        return None


def _dt_from_text(text: str) -> datetime | None:
    """Return the first recognisable date in free-form event description text."""
    if (m := _ISO_RE.search(text)) and (dt := _parse_dt(m.group(1))):
        return dt
    if m := _MONTH_DAY_YEAR_RE.search(text):
        return _date(m.group(3), m.group(1), m.group(2))
    if m := _DAY_MONTH_YEAR_RE.search(text):
        return _date(m.group(3), m.group(2), m.group(1))
    return None


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
    creds = session.client("sts", config=CLIENT_CONFIG).assume_role(**assume_kwargs)["Credentials"]
    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
        region_name=args.region,
    )


def _health_regions(session: boto3.Session) -> tuple[str, ...]:
    partition = session.get_partition_for_region(session.region_name)
    return HEALTH_REGIONS.get(partition, HEALTH_REGIONS["aws"])


def _token_names(client: Any, arns: list[str]) -> dict[str, str]:
    """Map event ARNs to the name of their first affected entity (the SCIM token)."""
    names: dict[str, str] = {}
    try:
        for page in client.get_paginator("describe_affected_entities").paginate(filter={"eventArns": arns}):
            for entity in page.get("entities", []):
                if name := entity.get("entityValue") or entity.get("entityUrl"):
                    names.setdefault(entity["eventArn"], str(name))
    except ClientError:
        pass
    return names


def _describe_token_events(client: Any, event_type_codes: list[str]) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    event_filter = {"eventTypeCodes": event_type_codes, "eventStatusCodes": ["open", "upcoming"]}
    for page in client.get_paginator("describe_events").paginate(filter=event_filter):
        events.extend(page.get("events", []))

    results: list[dict[str, Any]] = []
    for offset in range(0, len(events), BATCH_SIZE):
        arns = [e["arn"] for e in events[offset : offset + BATCH_SIZE]]
        resp = client.describe_event_details(eventArns=arns, locale="en")
        details = {d["event"]["arn"]: d for d in resp.get("successfulSet", [])}
        results.extend({"error": f"DescribeEventDetails failed for {failed.get('eventArn')}: {failed.get('errorMessage')}"} for failed in resp.get("failedSet", []))
        names = _token_names(client, [arn for arn in arns if arn in details])

        for arn in arns:
            if arn not in details:
                continue
            description = details[arn].get("eventDescription", {}).get("latestDescription", "")
            expiry = _dt_from_text(description)
            results.append(
                {
                    "name": names.get(arn, arn.rsplit("/", 1)[-1]),
                    "expiry": _dt_to_str(expiry) if expiry else None,
                    "source": arn,
                    "detail": " ".join(description.split())[:200],
                }
            )
    return results


def fetch_token_events(session: boto3.Session, event_type_codes: list[str]) -> list[dict[str, Any]]:
    """Return one record per open SCIM token expiry event, or an error record.

    Fails over to the next Health endpoint of the partition if one cannot be reached.
    """
    regions = _health_regions(session)
    for region in regions:
        client = session.client("health", region_name=region, config=CLIENT_CONFIG)
        try:
            return _describe_token_events(client, event_type_codes)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "SubscriptionRequiredException":
                return [{"error": "AWS Health API requires Business, Enterprise On-Ramp, or Enterprise Support"}]
            return [{"error": str(exc)}]
        except BotoConnectionError as exc:
            if region == regions[-1]:
                return [{"error": str(exc)}]
        except BotoCoreError as exc:
            return [{"error": str(exc)}]
    return []


def parse_arguments(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--region", default="us-east-1", help="Region for STS; its partition selects the AWS Health endpoint")
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

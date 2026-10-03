"""Checkmk special agent: AWS IAM Identity Center SCIM token expiration.

AWS raises the AWS Health event
``AWS_IAMIDENTITYCENTER_SCIM_BEARER_TOKEN_EXPIRY_NOTIFICATION`` (service
``IAMIDENTITYCENTER``, category ``accountNotification``) once a SCIM access
token is 90 days or less from expiry and renews it until the token expires.
This agent reports every open event, plus recently closed events of tokens
that AWS tracked until they expired, so an expired token does not turn OK
once AWS stops renewing its event.

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
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError, UnknownRegionError
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

_ISO_RE = re.compile(r"\b(\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)?)\b")
_MONTHS = ("jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec")
_MONTH = r"\b(" + "|".join(_MONTHS) + r")[a-z]*\.?"
_MONTH_DAY_YEAR_RE = re.compile(_MONTH + r"\s+(\d{1,2}),?\s+(\d{4})\b", re.IGNORECASE)
_DAY_MONTH_YEAR_RE = re.compile(r"\b(\d{1,2})\s+" + _MONTH + r",?\s+(\d{4})\b", re.IGNORECASE)
_EXPIRY_KEYWORD_RE = re.compile(r"\bexpir\w*", re.IGNORECASE)
# AWS error messages name the caller (account ID, role, session); keep them out of service output
_ARN_RE = re.compile(r"\barn:aws[\w-]*:[^\s,;'\"]+")
_ACCOUNT_ID_RE = re.compile(r"\b\d{12}\b")
EXPIRY_DATE_WINDOW = 80  # max. characters between "expires" and the date it refers to
CLOSED_EVENT_DAYS = 30  # report an expired token for this long after AWS closed its event
# AWS renews the event daily until expiry; a closed event updated this close to its
# expiry was tracked until the token expired rather than closed by rotation or deletion
CLOSED_EVENT_EXPIRY_GRACE = timedelta(days=2)
# A date without a time of day expires at its end, not at its start
END_OF_DAY = timedelta(hours=23, minutes=59, seconds=59)


def _parse_dt(value: str) -> datetime | None:
    for candidate in (value, value[:10]):
        try:
            dt = datetime.fromisoformat(candidate)
        except ValueError:
            continue
        if len(candidate) == 10:
            dt += END_OF_DAY
        return dt if dt.tzinfo else dt.replace(tzinfo=UTC)
    return None


def _date(year: str, month: str, day: str) -> datetime | None:
    try:
        return datetime(int(year), _MONTHS.index(month[:3].lower()) + 1, int(day), tzinfo=UTC) + END_OF_DAY
    except ValueError:
        return None


def _dates_in_text(text: str) -> list[tuple[int, datetime]]:
    """Return every recognisable date in the text with its position, in text order."""
    found = [(m.start(), _parse_dt(m.group(1))) for m in _ISO_RE.finditer(text)]
    found += [(m.start(), _date(m.group(3), m.group(1), m.group(2))) for m in _MONTH_DAY_YEAR_RE.finditer(text)]
    found += [(m.start(), _date(m.group(3), m.group(2), m.group(1))) for m in _DAY_MONTH_YEAR_RE.finditer(text)]
    return sorted((pos, dt) for pos, dt in found if dt)


def _dt_from_text(text: str, now: datetime) -> datetime | None:
    """Return the expiry date from free-form event description text.

    Prefers the first date shortly after an "expire(s|d)/expiry/expiration"
    keyword, so that other dates in the text (notification or creation date)
    are skipped. Falls back to the first future date anywhere in the text; a
    past date without that keyword is more likely the notification date than
    the expiry, and would be reported as an expired token.
    """
    dates = _dates_in_text(text)
    for keyword in _EXPIRY_KEYWORD_RE.finditer(text):
        for pos, dt in dates:
            if keyword.end() <= pos <= keyword.end() + EXPIRY_DATE_WINDOW:
                return dt
    return next((dt for _, dt in dates if dt > now), None)


def _redact(text: str) -> str:
    return _ACCOUNT_ID_RE.sub("<account>", _ARN_RE.sub("<arn>", text))


def _dt_to_str(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S+00:00")


def _lookup_secret(reference: str) -> str:
    """Resolve a Checkmk password store reference of the form ``<id>:<file>``.

    Uses the public password store API of Checkmk 2.5+ and falls back to the
    internal one of Checkmk 2.4. Both are only available inside a Checkmk site.

    Raises:
        ValueError: If the reference cannot be resolved.
    """
    try:
        from cmk.password_store.v1_unstable import PasswordStoreError, dereference_secret  # noqa: PLC0415
    except ImportError:
        from cmk.utils import password_store  # noqa: PLC0415

        pw_id, pw_file = reference.split(":", 1)
        return str(password_store.lookup(Path(pw_file), pw_id))
    try:
        return str(dereference_secret(reference).reveal())
    except PasswordStoreError as exc:
        raise ValueError(str(exc)) from exc


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
    """Return the AWS Health endpoints of the session region's partition.

    Raises:
        ValueError: If the region is unknown or AWS Health is not available in its partition.
    """
    try:
        partition = session.get_partition_for_region(session.region_name)
    except UnknownRegionError as exc:
        raise ValueError(f"Unknown AWS region {session.region_name!r}") from exc
    if partition not in HEALTH_REGIONS:
        raise ValueError(f"AWS Health is not supported in partition {partition!r} (region {session.region_name!r})")
    return HEALTH_REGIONS[partition]


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


def _list_events(client: Any, event_filter: dict[str, Any]) -> list[dict[str, Any]]:
    return [event for page in client.get_paginator("describe_events").paginate(filter=event_filter) for event in page.get("events", [])]


def _is_reportable(event: dict[str, Any], expiry: datetime | None, now: datetime) -> bool:
    """Open events are always reported; closed ones only if AWS tracked the token until it expired."""
    if event.get("statusCode") != "closed":
        return True
    last_updated = event.get("lastUpdatedTime")
    return expiry is not None and last_updated is not None and last_updated >= expiry - CLOSED_EVENT_EXPIRY_GRACE and expiry <= now


def _describe_token_events(client: Any, event_type_codes: list[str]) -> list[dict[str, Any]]:
    now = datetime.now(UTC)
    events = _list_events(client, {"eventTypeCodes": event_type_codes, "eventStatusCodes": ["open", "upcoming"]})
    closed_since = now - timedelta(days=CLOSED_EVENT_DAYS)
    events += _list_events(client, {"eventTypeCodes": event_type_codes, "eventStatusCodes": ["closed"], "lastUpdatedTimes": [{"from": closed_since}]})
    events_by_arn = {event["arn"]: event for event in events}

    results: list[dict[str, Any]] = []
    reported: set[tuple[str, datetime | None]] = set()
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
            expiry = _dt_from_text(description, now)
            name = names.get(arn, arn.rsplit("/", 1)[-1])
            # Renewed events repeat the same token and expiry
            if not _is_reportable(events_by_arn[arn], expiry, now) or (name, expiry) in reported:
                continue
            reported.add((name, expiry))
            results.append(
                {
                    "name": name,
                    "expiry": _dt_to_str(expiry) if expiry else None,
                    "source": arn,
                    "detail": " ".join(description.split())[:200],
                }
            )
    return results


def fetch_token_events(session: boto3.Session, event_type_codes: list[str]) -> list[dict[str, Any]]:
    """Return one record per SCIM token with an expiry event, or an error record.

    Fails over to the next Health endpoint of the partition if one cannot be reached.
    """
    try:
        regions = _health_regions(session)
    except ValueError as exc:
        return [{"error": str(exc)}]
    for region in regions:
        client = session.client("health", region_name=region, config=CLIENT_CONFIG)
        try:
            return _describe_token_events(client, event_type_codes)
        except ClientError as exc:
            no_subscription = exc.response.get("Error", {}).get("Code") == "SubscriptionRequiredException"
            return [{"error": "AWS Health API requires Business, Enterprise On-Ramp, or Enterprise Support" if no_subscription else str(exc)}]
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
        sys.stderr.write(f"ERROR: Failed to create AWS session: {_redact(str(exc))}\n")
        return 1

    print(SECTION_HEADER)
    for record in fetch_token_events(session, args.event_type_codes):
        if "error" in record:
            record["error"] = _redact(record["error"])
        print(json.dumps(record))
    return 0

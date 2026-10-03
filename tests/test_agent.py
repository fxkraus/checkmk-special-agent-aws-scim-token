"""Unit tests for the special agent module."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError, NoCredentialsError

from cmk_addons.plugins.aws_scim_token.special_agents import agent_aws_scim_token as agent

ARN = "arn:aws:health:us-east-1::event/IAMIDENTITYCENTER/AWS_IAMIDENTITYCENTER_SCIM_BEARER_TOKEN_EXPIRY_NOTIFICATION/abc"


class TestDateHelpers:
    def test_parse_dt_iso_with_z(self):
        assert agent._parse_dt("2026-12-31T23:59:59Z") == datetime(2026, 12, 31, 23, 59, 59, tzinfo=UTC)

    def test_parse_dt_naive_gets_utc(self):
        assert agent._parse_dt("2026-01-15") == datetime(2026, 1, 15, tzinfo=UTC)

    def test_parse_dt_invalid(self):
        assert agent._parse_dt("not a date") is None

    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            ("2026-09-01T12:00:00", datetime(2026, 9, 1, 12, tzinfo=UTC)),
            ("2026-09-01T12:00:00.000Z", datetime(2026, 9, 1, 12, tzinfo=UTC)),
            ("2026-09-01T12:00:00.123+02:00", datetime(2026, 9, 1, 10, 0, 0, 123000, tzinfo=UTC)),
            ("2026-09-01 12:00:00+0200", datetime(2026, 9, 1, 10, tzinfo=UTC)),
            ("2026-09-01T25:00:00", datetime(2026, 9, 1, tzinfo=UTC)),
        ],
    )
    def test_parse_dt_iso_variants(self, value, expected):
        assert agent._parse_dt(value) == expected

    @pytest.mark.parametrize(
        ("text", "expected"),
        [
            ("expires on 2026-06-30T12:00:00Z, please rotate", datetime(2026, 6, 30, 12, tzinfo=UTC)),
            ("expires 2026-09-01T12:00:00.000Z", datetime(2026, 9, 1, 12, tzinfo=UTC)),
            ("will expire on June 30, 2026", datetime(2026, 6, 30, tzinfo=UTC)),
            ("will expire on Jun 30 2026", datetime(2026, 6, 30, tzinfo=UTC)),
            ("will expire on 30 June 2026", datetime(2026, 6, 30, tzinfo=UTC)),
            ("will expire on Tue, 30 Jun 2026", datetime(2026, 6, 30, tzinfo=UTC)),
            ("See the Summary 5, 2026 report. Token expires on December 1, 2026", datetime(2026, 12, 1, tzinfo=UTC)),
            ("Notice sent 2026-06-01. Your token expires on 2026-09-01.", datetime(2026, 9, 1, tzinfo=UTC)),
            ("Token created on March 3, 2025 expires on June 1, 2026", datetime(2026, 6, 1, tzinfo=UTC)),
            ("Expiration date: 1 June 2026 (notified 2026-03-03)", datetime(2026, 6, 1, tzinfo=UTC)),
            ("Rotate the token before 2026-09-01.", datetime(2026, 9, 1, tzinfo=UTC)),
        ],
    )
    def test_dt_from_text(self, text, expected):
        assert agent._dt_from_text(text) == expected

    def test_dt_from_text_ignores_month_names_inside_words(self):
        assert agent._dt_from_text("Summary 5, 2026") is None

    def test_dt_from_text_no_match(self):
        assert agent._dt_from_text("no date here") is None

    def test_dt_to_str_converts_to_utc(self):
        from datetime import timedelta, timezone

        dt = datetime(2026, 1, 2, 5, 4, 5, tzinfo=timezone(timedelta(hours=2)))
        assert agent._dt_to_str(dt) == "2026-01-02T03:04:05+00:00"


class TestParseArguments:
    def test_defaults(self):
        args = agent.parse_arguments([])
        assert args.region == "us-east-1"
        assert args.event_type_codes == [agent.DEFAULT_EVENT_TYPE_CODE]
        assert args.role_arn is None

    def test_access_key_requires_secret_reference(self):
        with pytest.raises(SystemExit):
            agent.parse_arguments(["--access-key-id", "AKIA"])


def _health_client(events, details=None, failed=None, entities=None):
    client = MagicMock()
    paginator = MagicMock()
    paginator.paginate.return_value = [{"events": events}]
    client.get_paginator.return_value = paginator
    client.describe_event_details.return_value = {"successfulSet": details or [], "failedSet": failed or []}
    client.describe_affected_entities.return_value = {"entities": entities or []}
    session = MagicMock()
    session.client.return_value = client
    return session, client, paginator


class TestFetchTokenEvents:
    def test_no_events_is_empty(self):
        session, _, _ = _health_client([])
        assert agent.fetch_token_events(session, [agent.DEFAULT_EVENT_TYPE_CODE]) == []

    def test_filters_by_event_type_code_on_global_endpoint(self):
        session, _, paginator = _health_client([])
        agent.fetch_token_events(session, ["X"])
        session.client.assert_called_once_with("health", region_name="us-east-1")
        assert paginator.paginate.call_args.kwargs["filter"] == {"eventTypeCodes": ["X"], "eventStatusCodes": ["open", "upcoming"]}

    def test_expiry_from_description_not_end_time(self):
        event = {"arn": ARN, "endTime": datetime(2030, 1, 1, tzinfo=UTC)}
        detail = {"event": event, "eventDescription": {"latestDescription": "Your SCIM token\nexpires on 2026-09-01."}}
        session, _, _ = _health_client([event], details=[detail], entities=[{"entityValue": "tok-1"}])

        [record] = agent.fetch_token_events(session, ["X"])
        assert record == {"name": "tok-1", "expiry": "2026-09-01T00:00:00+00:00", "source": ARN, "detail": "Your SCIM token expires on 2026-09-01."}

    def test_no_date_in_description_yields_null_expiry(self):
        event = {"arn": ARN}
        detail = {"event": event, "eventDescription": {"latestDescription": "Rotate soon."}}
        session, _, _ = _health_client([event], details=[detail])

        [record] = agent.fetch_token_events(session, ["X"])
        assert record["expiry"] is None
        assert record["name"] == "abc"

    def test_failed_details_reported_once(self):
        event = {"arn": ARN}
        session, _, _ = _health_client([event], failed=[{"eventArn": ARN, "errorMessage": "boom"}])

        records = agent.fetch_token_events(session, ["X"])
        assert len(records) == 1
        assert "boom" in records[0]["error"]

    def test_details_batched_by_ten(self):
        events = [{"arn": f"{ARN}{i}"} for i in range(11)]
        session, client, _ = _health_client(events)
        agent.fetch_token_events(session, ["X"])
        assert [len(c.kwargs["eventArns"]) for c in client.describe_event_details.call_args_list] == [10, 1]

    def test_subscription_required(self):
        session, _, paginator = _health_client([])
        paginator.paginate.side_effect = ClientError({"Error": {"Code": "SubscriptionRequiredException", "Message": "no"}}, "DescribeEvents")
        [record] = agent.fetch_token_events(session, ["X"])
        assert "Business" in record["error"]

    def test_botocore_error_is_reported(self):
        session, _, paginator = _health_client([])
        paginator.paginate.side_effect = NoCredentialsError()
        [record] = agent.fetch_token_events(session, ["X"])
        assert "credentials" in record["error"].lower()


class TestBuildSession:
    def test_static_credentials_resolved_from_password_store(self):
        args = agent.parse_arguments(["--region", "eu-west-1", "--access-key-id", "AKIA", "--secret-access-key-reference", "pw:/store"])
        with patch.object(agent, "_lookup_secret", return_value="s3cret") as lookup, patch.object(agent.boto3, "Session") as session_cls:
            agent.build_session(args)
        lookup.assert_called_once_with("pw:/store")
        session_cls.assert_called_once_with(region_name="eu-west-1", aws_access_key_id="AKIA", aws_secret_access_key="s3cret")

    def test_assume_role_passes_external_id(self):
        sts = MagicMock()
        sts.assume_role.return_value = {"Credentials": {"AccessKeyId": "AK", "SecretAccessKey": "SK", "SessionToken": "TOK"}}
        initial = MagicMock()
        initial.client.return_value = sts
        args = agent.parse_arguments(["--role-arn", "arn:aws:iam::1:role/R", "--external-id", "ext"])
        with patch.object(agent.boto3, "Session", side_effect=[initial, MagicMock()]):
            agent.build_session(args)
        sts.assume_role.assert_called_once_with(RoleArn="arn:aws:iam::1:role/R", RoleSessionName="checkmk-scim-monitor", ExternalId="ext")

    def test_assume_role_without_external_id(self):
        sts = MagicMock()
        sts.assume_role.return_value = {"Credentials": {"AccessKeyId": "AK", "SecretAccessKey": "SK", "SessionToken": "TOK"}}
        initial = MagicMock()
        initial.client.return_value = sts
        with patch.object(agent.boto3, "Session", side_effect=[initial, MagicMock()]):
            agent.build_session(agent.parse_arguments(["--role-arn", "arn:aws:iam::1:role/R"]))
        assert "ExternalId" not in sts.assume_role.call_args.kwargs


class TestMain:
    def test_emits_header_even_without_events(self, capsys):
        with patch.object(agent, "build_session"), patch.object(agent, "fetch_token_events", return_value=[]):
            assert agent.main([]) == 0
        assert capsys.readouterr().out == "<<<aws_scim_token:sep(0)>>>\n"

    def test_emits_one_json_line_per_record(self, capsys):
        record = {"name": "t", "expiry": "2026-01-01T00:00:00+00:00"}
        with patch.object(agent, "build_session"), patch.object(agent, "fetch_token_events", return_value=[record]):
            agent.main([])
        assert json.loads(capsys.readouterr().out.splitlines()[1]) == record

    def test_session_failure_exits_non_zero(self, capsys):
        error = ClientError({"Error": {"Code": "AccessDenied", "Message": "no"}}, "AssumeRole")
        with patch.object(agent, "build_session", side_effect=error):
            assert agent.main([]) == 1
        assert "AccessDenied" in capsys.readouterr().err

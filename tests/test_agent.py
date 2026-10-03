"""Unit tests for the special agent module."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch

import boto3
import pytest
from botocore.exceptions import ClientError, EndpointConnectionError, NoCredentialsError, ReadTimeoutError

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


def _health_client(events, details=None, failed=None, entities=None, closed=None):
    client = MagicMock()
    paginators = {"describe_events": MagicMock(), "describe_affected_entities": MagicMock()}
    paginators["describe_events"].paginate.side_effect = lambda filter: [{"events": (closed or []) if filter["eventStatusCodes"] == ["closed"] else events}]
    paginators["describe_affected_entities"].paginate.return_value = [{"entities": entities or []}]
    client.get_paginator.side_effect = paginators.__getitem__
    client.describe_event_details.return_value = {"successfulSet": details or [], "failedSet": failed or []}
    session = MagicMock()
    session.region_name = "eu-west-1"
    session.get_partition_for_region.return_value = "aws"
    session.client.return_value = client
    return session, client, paginators["describe_events"]


def _detail(arn, description="Rotate soon."):
    return {"event": {"arn": arn}, "eventDescription": {"latestDescription": description}}


class TestFetchTokenEvents:
    def test_no_events_is_empty(self):
        session, _, _ = _health_client([])
        assert agent.fetch_token_events(session, [agent.DEFAULT_EVENT_TYPE_CODE]) == []

    def test_filters_by_event_type_code_on_global_endpoint(self):
        session, _, paginator = _health_client([])
        agent.fetch_token_events(session, ["X"])
        session.client.assert_called_once_with("health", region_name="us-east-1", config=agent.CLIENT_CONFIG)
        open_call, closed_call = paginator.paginate.call_args_list
        assert open_call.kwargs["filter"] == {"eventTypeCodes": ["X"], "eventStatusCodes": ["open", "upcoming"]}
        closed_filter = closed_call.kwargs["filter"]
        assert closed_filter["eventStatusCodes"] == ["closed"]
        [time_range] = closed_filter["lastUpdatedTimes"]
        assert datetime.now(UTC) - time_range["from"] == pytest.approx(timedelta(days=agent.CLOSED_EVENT_DAYS), abs=timedelta(minutes=1))

    def test_client_config_sets_timeouts_and_standard_retries(self):
        assert agent.CLIENT_CONFIG.connect_timeout == 5
        assert agent.CLIENT_CONFIG.read_timeout == 15
        assert agent.CLIENT_CONFIG.retries == {"mode": "standard", "max_attempts": 3}

    @pytest.mark.parametrize(
        ("region", "expected"),
        [("eu-central-1", ("us-east-1", "us-east-2")), ("cn-north-1", ("cn-northwest-1",)), ("us-gov-east-1", ("us-gov-west-1",))],
    )
    def test_health_region_follows_partition(self, region, expected):
        assert agent._health_regions(boto3.Session(region_name=region)) == expected

    def test_unknown_region_is_reported(self):
        [record] = agent.fetch_token_events(boto3.Session(region_name="eu-central"), ["X"])
        assert record == {"error": "Unknown AWS region 'eu-central'"}

    def test_partition_without_health_endpoint_is_reported(self):
        [record] = agent.fetch_token_events(boto3.Session(region_name="us-iso-east-1"), ["X"])
        assert "not supported in partition 'aws-iso'" in record["error"]

    def test_fails_over_to_secondary_endpoint(self):
        session, _, paginator = _health_client([])
        paginator.paginate.side_effect = [EndpointConnectionError(endpoint_url="https://health.us-east-1.amazonaws.com"), [{"events": []}], [{"events": []}]]
        assert agent.fetch_token_events(session, ["X"]) == []
        assert [c.kwargs["region_name"] for c in session.client.call_args_list] == ["us-east-1", "us-east-2"]

    def test_connection_error_on_all_endpoints_is_reported(self):
        session, _, paginator = _health_client([])
        paginator.paginate.side_effect = EndpointConnectionError(endpoint_url="https://health.amazonaws.com")
        [record] = agent.fetch_token_events(session, ["X"])
        assert "Could not connect" in record["error"]

    def test_expiry_from_description_not_end_time(self):
        event = {"arn": ARN, "endTime": datetime(2030, 1, 1, tzinfo=UTC)}
        detail = {"event": event, "eventDescription": {"latestDescription": "Your SCIM token\nexpires on 2026-09-01."}}
        session, _, _ = _health_client([event], details=[detail], entities=[{"eventArn": ARN, "entityValue": "tok-1"}])

        [record] = agent.fetch_token_events(session, ["X"])
        assert record == {"name": "tok-1", "expiry": "2026-09-01T00:00:00+00:00", "source": ARN, "detail": "Your SCIM token expires on 2026-09-01."}

    def test_no_date_in_description_yields_null_expiry(self):
        session, _, _ = _health_client([{"arn": ARN}], details=[_detail(ARN)])

        [record] = agent.fetch_token_events(session, ["X"])
        assert record["expiry"] is None
        assert record["name"] == "abc"

    def test_entity_lookup_failure_falls_back_to_arn_suffix(self):
        session, client, _ = _health_client([{"arn": ARN}], details=[_detail(ARN)])
        client.get_paginator("describe_affected_entities").paginate.side_effect = ClientError({"Error": {"Code": "AccessDenied", "Message": "no"}}, "DescribeAffectedEntities")

        [record] = agent.fetch_token_events(session, ["X"])
        assert record["name"] == "abc"

    def test_failed_details_reported_once(self):
        event = {"arn": ARN}
        session, _, _ = _health_client([event], failed=[{"eventArn": ARN, "errorMessage": "boom"}])

        records = agent.fetch_token_events(session, ["X"])
        assert len(records) == 1
        assert "boom" in records[0]["error"]

    def test_details_and_entities_batched_by_ten(self):
        arns = [f"{ARN}{i}" for i in range(11)]
        entities = [{"eventArn": arn, "entityValue": f"tok-{i}"} for i, arn in enumerate(arns)]
        session, client, _ = _health_client([{"arn": arn} for arn in arns], details=[_detail(arn) for arn in arns], entities=entities)

        records = agent.fetch_token_events(session, ["X"])
        assert [len(c.kwargs["eventArns"]) for c in client.describe_event_details.call_args_list] == [10, 1]
        entity_calls = client.get_paginator("describe_affected_entities").paginate.call_args_list
        assert [len(c.kwargs["filter"]["eventArns"]) for c in entity_calls] == [10, 1]
        assert [r["name"] for r in records] == [f"tok-{i}" for i in range(11)]

    def _closed_event(self, expiry: datetime, last_updated: datetime) -> tuple:
        event = {"arn": ARN, "statusCode": "closed", "lastUpdatedTime": last_updated}
        return _health_client([], details=[_detail(ARN, f"Your SCIM token expires on {expiry:%Y-%m-%d}.")], closed=[event])

    def test_closed_event_of_expired_token_is_reported(self):
        expiry = datetime(2026, 1, 10, tzinfo=UTC)
        session, _, _ = self._closed_event(expiry, last_updated=expiry - timedelta(days=1))
        [record] = agent.fetch_token_events(session, ["X"])
        assert record["expiry"] == "2026-01-10T00:00:00+00:00"

    def test_closed_event_of_unexpired_token_is_skipped(self):
        expiry = datetime.now(UTC) + timedelta(days=40)
        session, _, _ = self._closed_event(expiry, last_updated=datetime.now(UTC))
        assert agent.fetch_token_events(session, ["X"]) == []

    def test_closed_event_abandoned_long_before_expiry_is_skipped(self):
        expiry = datetime(2026, 1, 10, tzinfo=UTC)
        session, _, _ = self._closed_event(expiry, last_updated=expiry - timedelta(days=20))
        assert agent.fetch_token_events(session, ["X"]) == []

    def test_closed_event_without_date_is_skipped(self):
        event = {"arn": ARN, "statusCode": "closed", "lastUpdatedTime": datetime.now(UTC)}
        session, _, _ = _health_client([], details=[_detail(ARN)], closed=[event])
        assert agent.fetch_token_events(session, ["X"]) == []

    def test_renewed_events_of_one_token_are_reported_once(self):
        arns = [f"{ARN}{i}" for i in range(3)]
        details = [_detail(arn, "Your SCIM token expires on 2026-09-01.") for arn in arns]
        entities = [{"eventArn": arn, "entityValue": "tok-1"} for arn in arns]
        session, _, _ = _health_client([{"arn": arn} for arn in arns], details=details, entities=entities)
        [record] = agent.fetch_token_events(session, ["X"])
        assert record["source"] == arns[0]

    def test_subscription_required(self):
        session, _, paginator = _health_client([])
        paginator.paginate.side_effect = ClientError({"Error": {"Code": "SubscriptionRequiredException", "Message": "no"}}, "DescribeEvents")
        [record] = agent.fetch_token_events(session, ["X"])
        assert "Business" in record["error"]

    def test_access_denied_is_reported(self):
        session, _, paginator = _health_client([])
        paginator.paginate.side_effect = ClientError({"Error": {"Code": "AccessDenied", "Message": "not authorized"}}, "DescribeEvents")
        [record] = agent.fetch_token_events(session, ["X"])
        assert "AccessDenied" in record["error"]
        assert "DescribeEvents" in record["error"]

    def test_read_timeout_is_reported(self):
        session, _, paginator = _health_client([])
        paginator.paginate.side_effect = ReadTimeoutError(endpoint_url="https://health.us-east-1.amazonaws.com")
        [record] = agent.fetch_token_events(session, ["X"])
        assert "Read timeout" in record["error"]

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
        initial.client.assert_called_once_with("sts", config=agent.CLIENT_CONFIG)

    def test_assume_role_without_external_id(self):
        sts = MagicMock()
        sts.assume_role.return_value = {"Credentials": {"AccessKeyId": "AK", "SecretAccessKey": "SK", "SessionToken": "TOK"}}
        initial = MagicMock()
        initial.client.return_value = sts
        with patch.object(agent.boto3, "Session", side_effect=[initial, MagicMock()]):
            agent.build_session(agent.parse_arguments(["--role-arn", "arn:aws:iam::1:role/R"]))
        assert "ExternalId" not in sts.assume_role.call_args.kwargs


@pytest.fixture
def password_store_file(tmp_path, monkeypatch):
    """A real password store file written with the Checkmk API, keyed by a temporary secret."""
    from cmk.utils import password_store, paths

    secret_file = tmp_path / "password_store.secret"
    monkeypatch.setattr(paths, "password_store_secret_file", secret_file)
    monkeypatch.setenv("PASSWORD_STORE_SECRET_FILE", str(secret_file))  # read by the Checkmk 2.5 API
    store = tmp_path / "stored_passwords"
    password_store.save({"aws_secret": "s3cret"}, store)
    return store


class TestLookupSecret:
    def test_resolves_reference_from_real_store(self, password_store_file):
        assert agent._lookup_secret(f"aws_secret:{password_store_file}") == "s3cret"

    def test_unknown_id_raises_value_error(self, password_store_file):
        with pytest.raises(ValueError, match="unknown"):
            agent._lookup_secret(f"unknown:{password_store_file}")

    def test_unresolvable_reference_fails_session_setup(self, password_store_file, capsys):
        argv = ["--access-key-id", "AKIA", "--secret-access-key-reference", f"unknown:{password_store_file}"]
        assert agent.main(argv) == 1
        assert "Failed to create AWS session" in capsys.readouterr().err


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

    def test_error_records_hide_caller_arn_and_account_id(self, capsys):
        message = "An error occurred (AccessDenied) when calling the DescribeEvents operation: User: arn:aws:sts::123456789012:assumed-role/Mon/s is not authorized"
        with patch.object(agent, "build_session"), patch.object(agent, "fetch_token_events", return_value=[{"error": message}]):
            agent.main([])
        error = json.loads(capsys.readouterr().out.splitlines()[1])["error"]
        assert error == "An error occurred (AccessDenied) when calling the DescribeEvents operation: User: <arn> is not authorized"

    def test_token_records_are_not_redacted(self, capsys):
        record = {"name": "t", "expiry": None, "source": ARN, "detail": "account 123456789012"}
        with patch.object(agent, "build_session"), patch.object(agent, "fetch_token_events", return_value=[dict(record)]):
            agent.main([])
        assert json.loads(capsys.readouterr().out.splitlines()[1]) == record

    def test_session_failure_hides_account_id(self, capsys):
        error = ClientError({"Error": {"Code": "AccessDenied", "Message": "not authorized to assume arn:aws:iam::123456789012:role/R in 123456789012"}}, "AssumeRole")
        with patch.object(agent, "build_session", side_effect=error):
            assert agent.main([]) == 1
        err = capsys.readouterr().err
        assert "123456789012" not in err
        assert "assume <arn> in <account>" in err

    def test_session_failure_exits_non_zero(self, capsys):
        error = ClientError({"Error": {"Code": "AccessDenied", "Message": "no"}}, "AssumeRole")
        with patch.object(agent, "build_session", side_effect=error):
            assert agent.main([]) == 1
        assert "AccessDenied" in capsys.readouterr().err

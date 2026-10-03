"""Unit tests for the special agent module."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

import boto3
import pytest
from botocore.exceptions import ClientError, EndpointConnectionError, NoCredentialsError

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
        ("text", "expected"),
        [
            ("expires on 2026-06-30T12:00:00Z, please rotate", datetime(2026, 6, 30, 12, tzinfo=UTC)),
            ("will expire on June 30, 2026", datetime(2026, 6, 30, tzinfo=UTC)),
            ("will expire on Jun 30 2026", datetime(2026, 6, 30, tzinfo=UTC)),
            ("will expire on 30 June 2026", datetime(2026, 6, 30, tzinfo=UTC)),
            ("will expire on Tue, 30 Jun 2026", datetime(2026, 6, 30, tzinfo=UTC)),
        ],
    )
    def test_dt_from_text(self, text, expected):
        assert agent._dt_from_text(text) == expected

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
    paginators = {"describe_events": MagicMock(), "describe_affected_entities": MagicMock()}
    paginators["describe_events"].paginate.return_value = [{"events": events}]
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
        assert paginator.paginate.call_args.kwargs["filter"] == {"eventTypeCodes": ["X"], "eventStatusCodes": ["open", "upcoming"]}

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

    def test_fails_over_to_secondary_endpoint(self):
        session, _, paginator = _health_client([])
        paginator.paginate.side_effect = [EndpointConnectionError(endpoint_url="https://health.us-east-1.amazonaws.com"), [{"events": []}]]
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
        initial.client.assert_called_once_with("sts", config=agent.CLIENT_CONFIG)

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

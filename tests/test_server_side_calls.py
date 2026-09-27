"""Unit tests for the special agent server-side call."""

from __future__ import annotations

from cmk.server_side_calls.v1 import HostConfig, Secret
from cmk_addons.plugins.aws_scim_token.server_side_calls.special_agent import special_agent_aws_scim_token as config

HOST = HostConfig(name="aws-account")


def _args(raw_params):
    [command] = config(raw_params, HOST)
    assert command.stdin is None
    return list(command.command_arguments)


def test_minimal():
    assert _args({"region": "eu-central-1"}) == ["--region", "eu-central-1"]


def test_secret_is_passed_as_password_store_reference():
    secret = Secret(7)
    args = _args({"region": "us-east-1", "access_key": {"access_key_id": "AKIA", "secret_access_key": secret}})
    assert args == ["--region", "us-east-1", "--access-key-id", "AKIA", "--secret-access-key-reference", secret]
    assert secret.pass_safely


def test_assume_role_and_event_codes():
    args = _args(
        {
            "region": "us-east-1",
            "assume_role": {"role_arn": "arn:aws:iam::1:role/R", "external_id": "ext", "session_name": "s"},
            "event_type_codes": ["A", "B"],
        }
    )
    assert args == [
        "--region",
        "us-east-1",
        "--role-arn",
        "arn:aws:iam::1:role/R",
        "--external-id",
        "ext",
        "--session-name",
        "s",
        "--event-type-codes",
        "A",
        "B",
    ]

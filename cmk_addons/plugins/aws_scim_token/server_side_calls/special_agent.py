"""Server-side call: turn the special agent rule into an agent command line."""

from collections.abc import Iterable

from pydantic import BaseModel

from cmk.server_side_calls.v1 import HostConfig, Secret, SpecialAgentCommand, SpecialAgentConfig


class AccessKey(BaseModel):
    access_key_id: str
    secret_access_key: Secret


class AssumeRole(BaseModel):
    role_arn: str
    external_id: str | None = None
    session_name: str | None = None


class Params(BaseModel):
    region: str
    access_key: AccessKey | None = None
    assume_role: AssumeRole | None = None
    event_type_codes: list[str] | None = None


def commands_function(params: Params, host_config: HostConfig) -> Iterable[SpecialAgentCommand]:
    args: list[str | Secret] = ["--region", params.region]
    if params.access_key:
        args += [
            "--access-key-id",
            params.access_key.access_key_id,
            "--secret-access-key-reference",
            params.access_key.secret_access_key,
        ]
    if role := params.assume_role:
        args += ["--role-arn", role.role_arn]
        if role.external_id:
            args += ["--external-id", role.external_id]
        if role.session_name:
            args += ["--session-name", role.session_name]
    if params.event_type_codes:
        args += ["--event-type-codes", *params.event_type_codes]
    yield SpecialAgentCommand(command_arguments=args)


special_agent_aws_scim_token = SpecialAgentConfig(
    name="aws_scim_token",
    parameter_parser=Params.model_validate,
    commands_function=commands_function,
)

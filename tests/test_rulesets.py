"""Unit tests for the Setup rulesets."""

from __future__ import annotations

from cmk.rulesets.v1.form_specs import Dictionary
from cmk_addons.plugins.aws_scim_token.agent_based.aws_scim_token import check_plugin_aws_scim_token
from cmk_addons.plugins.aws_scim_token.rulesets.check_parameters import rule_spec_aws_scim_token_params
from cmk_addons.plugins.aws_scim_token.rulesets.special_agent import rule_spec_aws_scim_token
from cmk_addons.plugins.aws_scim_token.server_side_calls.special_agent import AccessKey, AssumeRole, Params


def _keys(form: Dictionary) -> set[str]:
    return set(form.elements)


def _sub_form(form: Dictionary, key: str) -> Dictionary:
    sub = form.elements[key].parameter_form
    assert isinstance(sub, Dictionary)
    return sub


def test_special_agent_form_matches_server_side_call_model():
    form = rule_spec_aws_scim_token.parameter_form()
    assert _keys(form) == set(Params.model_fields)
    assert _keys(_sub_form(form, "access_key")) == set(AccessKey.model_fields)
    assert _keys(_sub_form(form, "assume_role")) == set(AssumeRole.model_fields)


def test_check_parameters_match_plugin_defaults():
    form = rule_spec_aws_scim_token_params.parameter_form()
    assert rule_spec_aws_scim_token_params.name == check_plugin_aws_scim_token.check_ruleset_name
    assert _keys(form) == set(check_plugin_aws_scim_token.check_default_parameters)

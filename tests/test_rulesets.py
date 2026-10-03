"""Unit tests for the Setup rulesets."""

from __future__ import annotations

import pytest

from cmk.rulesets.v1.form_specs import Dictionary, SimpleLevels, validators
from cmk_addons.plugins.aws_scim_token.agent_based.aws_scim_token import check_plugin_aws_scim_token
from cmk_addons.plugins.aws_scim_token.rulesets.check_parameters import migrate_check_parameters, rule_spec_aws_scim_token_params
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


def _levels_form() -> SimpleLevels:
    levels = rule_spec_aws_scim_token_params.parameter_form().elements["levels"].parameter_form
    assert isinstance(levels, SimpleLevels)
    return levels


def test_migrates_warn_crit_days_rules():
    assert migrate_check_parameters({"warn_days": 45, "crit_days": 7}) == {"levels": ("fixed", (45, 7))}
    assert migrate_check_parameters({"warn_days": 30, "crit_days": 14}) == check_plugin_aws_scim_token.check_default_parameters


def test_migration_keeps_current_rules():
    current = {"levels": ("no_levels", None)}
    assert migrate_check_parameters(current) == current


@pytest.mark.parametrize("levels", [("fixed", (30, 14)), ("fixed", (14, 14)), ("no_levels", None)])
def test_valid_levels_are_accepted(levels):
    for validate in _levels_form().custom_validate or ():
        validate(levels)


def test_warn_below_crit_is_rejected():
    [validate] = _levels_form().custom_validate or ()
    with pytest.raises(validators.ValidationError):
        validate(("fixed", (10, 20)))


def test_negative_days_are_rejected():
    [validate] = _levels_form().form_spec_template.custom_validate or ()
    with pytest.raises(validators.ValidationError):
        validate(-1)


def _validate(form_spec, value) -> None:
    for validate in form_spec.custom_validate or ():
        validate(value)


@pytest.mark.parametrize("region", ["us-east-1", "eu-central-1", "us-gov-west-1", "cn-northwest-1", "eusc-de-east-1"])
def test_valid_regions_are_accepted(region):
    _validate(rule_spec_aws_scim_token.parameter_form().elements["region"].parameter_form, region)


@pytest.mark.parametrize("region", ["", "eu-central", "Frankfurt", "eu-central-1 ", "us_east_1"])
def test_invalid_regions_are_rejected(region):
    with pytest.raises(validators.ValidationError):
        _validate(rule_spec_aws_scim_token.parameter_form().elements["region"].parameter_form, region)


@pytest.mark.parametrize(("name", "valid"), [("checkmk-scim-monitor", True), ("a+b=c,d.e@f_g", True), ("x", False), ("has space", False), ("x" * 65, False)])
def test_session_name_follows_sts_constraints(name, valid):
    session_name = _sub_form(rule_spec_aws_scim_token.parameter_form(), "assume_role").elements["session_name"].parameter_form
    if valid:
        _validate(session_name, name)
    else:
        with pytest.raises(validators.ValidationError):
            _validate(session_name, name)


def test_at_most_ten_event_type_codes():
    codes = rule_spec_aws_scim_token.parameter_form().elements["event_type_codes"].parameter_form
    _validate(codes, ["X"] * 10)
    with pytest.raises(validators.ValidationError):
        _validate(codes, ["X"] * 11)

"""Setup ruleset: AWS SCIM Token check parameters (CMK 2.4+)."""

from cmk.rulesets.v1 import Help, Title
from cmk.rulesets.v1.form_specs import (
    DefaultValue,
    DictElement,
    Dictionary,
    Integer,
)
from cmk.rulesets.v1.rule_specs import CheckParameters, HostCondition, Topic


def _check_parameters_form() -> Dictionary:
    return Dictionary(
        title=Title("AWS SCIM Token Expiration Thresholds"),
        elements={
            "warn_days": DictElement(
                required=True,
                parameter_form=Integer(
                    title=Title("Warning threshold"),
                    help_text=Help("Warn if the token expires in fewer than this many days."),
                    unit_symbol="days",
                    prefill=DefaultValue(30),
                ),
            ),
            "crit_days": DictElement(
                required=True,
                parameter_form=Integer(
                    title=Title("Critical threshold"),
                    help_text=Help("Critical if the token expires in fewer than this many days."),
                    unit_symbol="days",
                    prefill=DefaultValue(14),
                ),
            ),
        },
    )


rule_spec_aws_scim_token_params = CheckParameters(
    name="aws_scim_token",
    title=Title("AWS SCIM Token Expiration"),
    topic=Topic.CLOUD,
    condition=HostCondition(),
    parameter_form=_check_parameters_form,
)

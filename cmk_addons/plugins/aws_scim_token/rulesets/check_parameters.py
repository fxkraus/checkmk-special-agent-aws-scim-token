"""Setup ruleset: AWS SCIM Token check parameters (CMK 2.4+)."""

from cmk.rulesets.v1 import Help, Message, Title
from cmk.rulesets.v1.form_specs import (
    DefaultValue,
    DictElement,
    Dictionary,
    Integer,
    LevelDirection,
    SimpleLevels,
    SimpleLevelsConfigModel,
    validators,
)
from cmk.rulesets.v1.rule_specs import CheckParameters, HostCondition, Topic


def _validate_levels(levels: SimpleLevelsConfigModel[int]) -> None:
    match levels:
        case ("fixed", (warn, crit)) if warn < crit:
            raise validators.ValidationError(Message("The warning level must not be lower than the critical level."))


def migrate_check_parameters(value: object) -> dict[str, object]:
    """Convert rules of versions before SimpleLevels ({"warn_days": 30, "crit_days": 14})."""
    if not isinstance(value, dict):
        raise TypeError(value)
    if "warn_days" in value:
        return {"levels": ("fixed", (value["warn_days"], value["crit_days"]))}
    return value


def _check_parameters_form() -> Dictionary:
    return Dictionary(
        title=Title("AWS SCIM Token Expiration Thresholds"),
        elements={
            "levels": DictElement(
                required=True,
                parameter_form=SimpleLevels(
                    title=Title("Lower levels for the remaining token lifetime"),
                    help_text=Help("WARN or CRIT if the token expires in this many days or fewer."),
                    level_direction=LevelDirection.LOWER,
                    form_spec_template=Integer(unit_symbol="days", custom_validate=(validators.NumberInRange(min_value=0),)),
                    prefill_fixed_levels=DefaultValue((30, 14)),
                    custom_validate=(_validate_levels,),
                ),
            ),
        },
        migrate=migrate_check_parameters,
    )


rule_spec_aws_scim_token_params = CheckParameters(
    name="aws_scim_token",
    title=Title("AWS SCIM Token Expiration"),
    topic=Topic.CLOUD,
    condition=HostCondition(),
    parameter_form=_check_parameters_form,
)

"""Setup ruleset: AWS SCIM Token special agent configuration (CMK 2.4+)."""

from cmk.rulesets.v1 import Help, Title
from cmk.rulesets.v1.form_specs import (
    DefaultValue,
    DictElement,
    Dictionary,
    FieldSize,
    List,
    Password,
    String,
    validators,
)
from cmk.rulesets.v1.rule_specs import SpecialAgent, Topic

_NON_EMPTY = (validators.LengthInRange(min_value=1),)


def _parameter_form() -> Dictionary:
    return Dictionary(
        title=Title("AWS SCIM Token Monitor"),
        help_text=Help("Monitors the expiration date of AWS IAM Identity Center SCIM access tokens using AWS Health events. Requires a Business, Enterprise On-Ramp, or Enterprise Support plan."),
        elements={
            "region": DictElement(
                required=True,
                parameter_form=String(
                    title=Title("AWS Region"),
                    help_text=Help("Region used for STS calls. AWS Health is queried at the endpoint of this region's partition (us-east-1 for commercial regions)."),
                    prefill=DefaultValue("us-east-1"),
                    field_size=FieldSize.SMALL,
                    custom_validate=_NON_EMPTY,
                ),
            ),
            "access_key": DictElement(
                required=False,
                parameter_form=Dictionary(
                    title=Title("Static access key"),
                    help_text=Help("Leave unset to use the instance profile or environment credentials of the Checkmk server."),
                    elements={
                        "access_key_id": DictElement(
                            required=True,
                            parameter_form=String(
                                title=Title("Access Key ID"),
                                field_size=FieldSize.MEDIUM,
                                custom_validate=_NON_EMPTY,
                            ),
                        ),
                        "secret_access_key": DictElement(
                            required=True,
                            parameter_form=Password(title=Title("Secret Access Key")),
                        ),
                    },
                ),
            ),
            "assume_role": DictElement(
                required=False,
                parameter_form=Dictionary(
                    title=Title("Assume Role"),
                    help_text=Help("Assume an IAM role before querying AWS, e.g. for cross-account access."),
                    elements={
                        "role_arn": DictElement(
                            required=True,
                            parameter_form=String(
                                title=Title("Role ARN"),
                                help_text=Help("Example: arn:aws:iam::123456789012:role/CheckmkScimMonitor"),
                                field_size=FieldSize.LARGE,
                                custom_validate=_NON_EMPTY,
                            ),
                        ),
                        "external_id": DictElement(
                            required=False,
                            parameter_form=String(
                                title=Title("External ID"),
                                help_text=Help("Required if the role's trust policy has an sts:ExternalId condition."),
                                field_size=FieldSize.MEDIUM,
                                custom_validate=_NON_EMPTY,
                            ),
                        ),
                        "session_name": DictElement(
                            required=False,
                            parameter_form=String(
                                title=Title("Session Name"),
                                prefill=DefaultValue("checkmk-scim-monitor"),
                                field_size=FieldSize.MEDIUM,
                                custom_validate=_NON_EMPTY,
                            ),
                        ),
                    },
                ),
            ),
            "event_type_codes": DictElement(
                required=False,
                parameter_form=List(
                    title=Title("Override AWS Health event type codes"),
                    help_text=Help("Default: AWS_IAMIDENTITYCENTER_SCIM_BEARER_TOKEN_EXPIRY_NOTIFICATION. Only change this if AWS renames the event."),
                    element_template=String(field_size=FieldSize.LARGE, custom_validate=_NON_EMPTY),
                    custom_validate=(validators.LengthInRange(min_value=1),),
                ),
            ),
        },
    )


rule_spec_aws_scim_token = SpecialAgent(
    name="aws_scim_token",
    title=Title("AWS SCIM Token Monitor"),
    topic=Topic.CLOUD,
    parameter_form=_parameter_form,
    help_text=Help("Monitors AWS IAM Identity Center SCIM access token expiry via AWS Health events."),
)

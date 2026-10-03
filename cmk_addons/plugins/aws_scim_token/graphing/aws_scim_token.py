"""Graphing: metric and perfometer for the AWS SCIM Token service (CMK 2.4+)."""

from cmk.graphing.v1 import Title
from cmk.graphing.v1.metrics import Color, DecimalNotation, Metric, Unit
from cmk.graphing.v1.perfometers import Closed, FocusRange, Open, Perfometer

metric_aws_scim_token_days_remaining = Metric(
    name="aws_scim_token_days_remaining",
    title=Title("SCIM token days remaining"),
    unit=Unit(DecimalNotation("days")),
    color=Color.BLUE,
)

perfometer_aws_scim_token_days_remaining = Perfometer(
    name="aws_scim_token_days_remaining",
    focus_range=FocusRange(Closed(0), Open(90)),
    segments=["aws_scim_token_days_remaining"],
)

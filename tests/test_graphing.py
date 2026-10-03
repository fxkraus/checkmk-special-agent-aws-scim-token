"""Unit tests for the graphing definitions."""

from __future__ import annotations

from cmk.graphing.v1.metrics import Metric
from cmk.graphing.v1.perfometers import Perfometer
from cmk_addons.plugins.aws_scim_token.graphing import aws_scim_token as graphing


def test_metric_matches_check_plugin_metric_name():
    assert isinstance(graphing.metric_aws_scim_token_days_remaining, Metric)
    assert graphing.metric_aws_scim_token_days_remaining.name == "aws_scim_token_days_remaining"


def test_perfometer_shows_the_metric():
    assert isinstance(graphing.perfometer_aws_scim_token_days_remaining, Perfometer)
    assert graphing.perfometer_aws_scim_token_days_remaining.segments == ["aws_scim_token_days_remaining"]

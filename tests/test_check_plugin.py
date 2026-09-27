"""Unit tests for the aws_scim_token check plugin."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from cmk.agent_based.v2 import Metric, Result, Service, State
from cmk_addons.plugins.aws_scim_token.agent_based import aws_scim_token as check

NOW = datetime(2026, 6, 1, 12, 0, 0, tzinfo=UTC)
PARAMS = {"warn_days": 30, "crit_days": 14}


class _FrozenDateTime(datetime):
    @classmethod
    def now(cls, tz=None):
        return NOW.astimezone(tz) if tz else NOW.replace(tzinfo=None)


@pytest.fixture(autouse=True)
def _freeze_now(monkeypatch):
    monkeypatch.setattr(check, "datetime", _FrozenDateTime)


def _expiry(days: float) -> str:
    return (NOW + timedelta(days=days)).isoformat()


def _run(section):
    return list(check.check_aws_scim_token(PARAMS, section))


def _states(results):
    return [r.state for r in results if isinstance(r, Result)]


class TestParse:
    def test_skips_malformed_rows(self):
        rows = [['{"name": "t1", "expiry": null}'], ["not-json"], [], ['"a string"'], ['{"error": "boom"}']]
        assert check.parse_aws_scim_token(rows) == [{"name": "t1", "expiry": None}, {"error": "boom"}]

    def test_empty_section_is_present(self):
        assert check.parse_aws_scim_token([]) == []


class TestDiscovery:
    @pytest.mark.parametrize("section", [[], [{"name": "a", "expiry": None}], [{"error": "x"}]])
    def test_single_itemless_service(self, section):
        assert list(check.discover_aws_scim_token(section)) == [Service()]


class TestCheck:
    def test_no_events_is_ok(self):
        results = _run([])
        assert _states(results) == [State.OK]
        assert "No SCIM token expiry" in results[0].summary

    @pytest.mark.parametrize(
        ("days", "state"),
        [(60, State.OK), (30, State.WARN), (20, State.WARN), (14, State.CRIT), (5, State.CRIT), (-1, State.CRIT)],
    )
    def test_thresholds(self, days, state):
        assert _states(_run([{"name": "t", "expiry": _expiry(days)}])) == [state]

    def test_expired_summary(self):
        [result, _] = _run([{"name": "t", "expiry": _expiry(-1)}])
        assert "EXPIRED" in result.summary

    def test_metric_is_soonest_expiry(self):
        results = _run([{"name": "a", "expiry": _expiry(60)}, {"name": "b", "expiry": _expiry(20)}])
        [metric] = [r for r in results if isinstance(r, Metric)]
        assert metric.value == pytest.approx(20)
        assert _states(results) == [State.OK, State.WARN]

    def test_duplicate_names_are_all_reported(self):
        results = _run([{"name": "t", "expiry": _expiry(60)}, {"name": "t", "expiry": _expiry(5)}])
        assert _states(results) == [State.OK, State.CRIT]

    def test_missing_expiry_warns(self):
        assert _states(_run([{"name": "t", "expiry": None}])) == [State.WARN]

    def test_unparseable_expiry_is_unknown(self):
        assert _states(_run([{"name": "t", "expiry": "tomorrow"}])) == [State.UNKNOWN]

    def test_naive_expiry_treated_as_utc(self):
        assert _states(_run([{"name": "t", "expiry": "2026-09-01T00:00:00"}])) == [State.OK]

    def test_error_is_crit_and_not_masked_by_ok_placeholder(self):
        results = _run([{"error": "AccessDenied"}])
        assert _states(results) == [State.CRIT]
        assert "AccessDenied" in results[0].summary

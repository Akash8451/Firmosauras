"""Task 14/15 — analyst_feedback schema bootstrap tests."""
from __future__ import annotations

from services.integration import schema


class _FakeCursor:
    def __init__(self, sink):
        self.sink = sink

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def execute(self, sql, params=None):
        self.sink.append(sql)


class _FakeConn:
    def __init__(self, sink):
        self.sink = sink

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def cursor(self):
        return _FakeCursor(self.sink)


def test_ddl_is_idempotent_and_matches_schema():
    assert "CREATE TABLE IF NOT EXISTS analyst_feedback" in schema.FEEDBACK_DDL
    for col in ("feedback_id", "job_id", "cve_id", "verdict", "submitted_by", "submitted_at"):
        assert col in schema.FEEDBACK_DDL


def test_ensure_feedback_schema_executes_ddl():
    sink: list[str] = []
    ok = schema.ensure_feedback_schema(dsn="ignored", connect_factory=lambda _dsn: _FakeConn(sink))
    assert ok is True
    assert any("analyst_feedback" in s for s in sink)
    assert any("analyst_feedback_job_idx" in s for s in sink)  # index too


def test_ensure_feedback_schema_is_best_effort_on_failure():
    def _boom(_dsn):
        raise RuntimeError("db down")

    assert schema.ensure_feedback_schema(dsn="x", connect_factory=_boom) is False

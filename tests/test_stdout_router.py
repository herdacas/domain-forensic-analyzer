"""Unit tests for ThreadAwareStdoutRouter."""

import io
import pytest
from src.core.stdout_router import ThreadAwareStdoutRouter, ModuleExecutionResult


class TestThreadAwareStdoutRouter:

    @pytest.fixture
    def router(self):
        buf = io.StringIO()
        return ThreadAwareStdoutRouter(buf), buf

    def test_write_passes_through_when_not_muted(self, router):
        r, buf = router
        r.write("hello")
        assert buf.getvalue() == "hello"

    def test_write_suppressed_when_muted(self, router):
        r, buf = router
        r.mute_current_thread()
        r.write("hidden")
        assert buf.getvalue() == ""

    def test_unmute_restores_output(self, router):
        r, buf = router
        r.mute_current_thread()
        r.write("hidden")
        r.unmute_current_thread()
        r.write("visible")
        assert buf.getvalue() == "visible"

    def test_write_returns_len_when_muted(self, router):
        r, buf = router
        r.mute_current_thread()
        result = r.write("12345")
        assert result == 5

    def test_flush_works_when_not_muted(self, router):
        r, buf = router
        r.write("data")
        r.flush()  # should not raise

    def test_flush_suppressed_when_muted(self, router):
        r, buf = router
        r.mute_current_thread()
        r.flush()  # should not raise

    def test_getattr_delegates_to_target(self, router):
        r, buf = router
        assert r.getvalue() == buf.getvalue()


class TestModuleExecutionResult:

    def test_success_result(self):
        result = ModuleExecutionResult(success=True, result={"key": "val"}, execution_time=1.5)
        assert result.success is True
        assert result.execution_time == 1.5
        assert result.error_message is None
        assert result.timeout_occurred is False

    def test_failed_result_with_error(self):
        result = ModuleExecutionResult(
            success=False,
            result={},
            execution_time=30.0,
            error_message="Timeout",
            timeout_occurred=True,
        )
        assert result.success is False
        assert result.timeout_occurred is True

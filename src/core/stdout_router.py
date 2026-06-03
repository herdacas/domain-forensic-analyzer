"""Thread-aware stdout router and module result dataclass."""

import sys
import threading
from dataclasses import dataclass
from typing import Any, Dict, Optional


@dataclass
class ModuleExecutionResult:
    """Stores the result and performance data for each analyzer module"""

    success: bool
    result: Dict[str, Any]
    execution_time: float
    error_message: Optional[str] = None
    timeout_occurred: bool = False


class ThreadAwareStdoutRouter:
    """Route stdout per thread so worker output can be muted safely."""

    def __init__(self, target):
        self._target = target
        self._local = threading.local()

    def mute_current_thread(self) -> None:
        self._local.muted = True

    def unmute_current_thread(self) -> None:
        self._local.muted = False

    def write(self, data):
        if getattr(self._local, "muted", False):
            return len(data)
        return self._target.write(data)

    def flush(self) -> None:
        if getattr(self._local, "muted", False):
            return
        self._target.flush()

    def __getattr__(self, name):
        return getattr(self._target, name)


if not isinstance(sys.stdout, ThreadAwareStdoutRouter):
    sys.stdout = ThreadAwareStdoutRouter(sys.stdout)

from __future__ import annotations

import functools
import random
import socket
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any


@dataclass
class RetryConfig:
    max_retries: int = 3
    base_delay: float = 1.0
    backoff_factor: float = 2.0
    retry_on: tuple[type[Exception], ...] = (
        TimeoutError,
        ConnectionError,
        ConnectionResetError,
        ConnectionRefusedError,
        socket.timeout,
        OSError,
    )
    # Not enforced by the decorator — scanners pass this to their network calls directly
    timeout_per_attempt: float = 10.0


def with_retry(config: RetryConfig | None = None):
    if config is None:
        config = RetryConfig()

    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            last_exception = None

            for attempt in range(config.max_retries + 1):
                try:
                    return func(*args, **kwargs)
                except config.retry_on as exc:
                    last_exception = exc
                    if attempt < config.max_retries:
                        delay = config.base_delay * (config.backoff_factor**attempt)
                        jitter = random.uniform(0, delay * 0.25)
                        time.sleep(delay + jitter)

            raise last_exception  # type: ignore[misc]

        wrapper._retry_config = config  # type: ignore[attr-defined]
        return wrapper

    return decorator

import time
import pytest
from domain_audit.retry import RetryConfig, with_retry


class TestWithRetry:
    def test_succeeds_on_first_try(self):
        call_count = 0

        @with_retry(config=RetryConfig(max_retries=3, base_delay=0.01))
        def fn():
            nonlocal call_count
            call_count += 1
            return "ok"

        assert fn() == "ok"
        assert call_count == 1

    def test_retries_on_matching_exception(self):
        call_count = 0

        @with_retry(config=RetryConfig(max_retries=2, base_delay=0.01, retry_on=(ValueError,)))
        def fn():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise ValueError("fail")
            return "ok"

        assert fn() == "ok"
        assert call_count == 3

    def test_raises_after_max_retries(self):
        @with_retry(config=RetryConfig(max_retries=2, base_delay=0.01, retry_on=(ValueError,)))
        def fn():
            raise ValueError("always fails")

        with pytest.raises(ValueError, match="always fails"):
            fn()

    def test_no_retry_on_non_matching_exception(self):
        call_count = 0

        @with_retry(config=RetryConfig(max_retries=3, base_delay=0.01, retry_on=(ValueError,)))
        def fn():
            nonlocal call_count
            call_count += 1
            raise TypeError("wrong type")

        with pytest.raises(TypeError):
            fn()
        assert call_count == 1

    def test_exponential_backoff(self):
        call_count = 0

        @with_retry(config=RetryConfig(max_retries=2, base_delay=0.1, backoff_factor=2.0, retry_on=(ValueError,)))
        def fn():
            nonlocal call_count
            call_count += 1
            raise ValueError("fail")

        start = time.time()
        with pytest.raises(ValueError):
            fn()
        elapsed = time.time() - start

        # Should have delays: ~0.1s + ~0.2s = ~0.3s minimum
        assert elapsed >= 0.2
        assert call_count == 3

### Vulnerability List

- **Vulnerability Name:** Race Condition in Limiter Release Mechanism

- **Description:**
    - A race condition exists in the `Limiter._release()` method.
    - When multiple tasks are waiting on a `Limiter` and one task releases the limiter, the `_release` method iterates through `_waiters` to find a non-cancelled future to set result to.
    - If multiple tasks are simultaneously cancelled and then a release happens, the loop in `_release` might pop a cancelled future from `_waiters` and check `f.try_set_result(None)` which will return `False` because the future is cancelled.
    - In this scenario, the limiter count is decremented, but no waiting task is released, potentially leading to a deadlock or unexpected throttling behavior if all waiting tasks are cancelled concurrently just before a release.
    - This can be triggered when multiple tasks are waiting on a limiter and a cancellation signal is sent to these tasks almost at the same time as another task is releasing the limiter.

- **Impact:**
    - Incorrect concurrency control.
    - Potential deadlocks in applications using `Limiter` for resource management, especially under heavy load or cancellation scenarios.
    - Reduced performance and responsiveness of applications relying on `duet.Limiter`.

- **Vulnerability Rank:** Medium

- **Currently Implemented Mitigations:**
    - The code attempts to find a non-cancelled future in the `_waiters` queue in `Limiter._release()`.
    - It also attempts to release all `_available_waiters` in `_release()`.

- **Missing Mitigations:**
    - The `_release` method should ensure that if it decrements the count, it always releases a waiting task if available and not cancelled, or correctly handles the case where all waiting tasks are cancelled concurrently.
    - A more robust approach would be to re-evaluate the waiters after each `try_set_result(None)` failure in the loop, or use a different data structure that handles concurrent cancellations and releases more reliably.
    - Consider using a more robust queue implementation that handles concurrent operations safely, or re-evaluate the waiting tasks after each failed `try_set_result`.

- **Preconditions:**
    - An application using `duet.Limiter` to control concurrency.
    - Multiple tasks concurrently waiting to acquire the limiter.
    - A scenario where these waiting tasks are cancelled almost simultaneously, coinciding with a limiter release from another task.

- **Source Code Analysis:**
    - **File:** `/code/duet/api.py`
    - **Class:** `Limiter`
    - **Method:** `_release()`
    ```python
    def _release(self) -> None:
        self._count -= 1
        # Release the first waiter that has not yet been cancelled.
        while self._waiters:
            f = self._waiters.popleft()
            if f.try_set_result(None): # [VULNERABLE CODE] - Race condition here
                break
        if self._available_waiters:
            for f in self._available_waiters:
                f.try_set_result(None)
            self._available_waiters.clear()
    ```
    - **Vulnerability Breakdown:**
        1.  `self._count -= 1`: Limiter count is decremented, assuming a slot will be released.
        2.  `while self._waiters:`: Loop through waiting futures.
        3.  `f = self._waiters.popleft()`: Get the next waiting future.
        4.  `if f.try_set_result(None):`: Attempt to set result for the future. If the future was just cancelled by another thread concurrently, `try_set_result` will return `False`.
        5.  `break`: If `try_set_result` is successful, break the loop.
        6.  **Race Condition:** If all futures in `_waiters` are concurrently cancelled just before this loop, and `try_set_result` fails for all of them, the loop will exit without releasing any waiter, even though `self._count` has been decremented. The next task waiting to acquire the limiter might be blocked indefinitely if capacity is reached, even though a release occurred.

- **Security Test Case:**
    - **Step 1:** Create a `Limiter` with capacity 1.
    - **Step 2:** Create an async function `job(limiter, ready, cancelled)` that:
        - Takes a `limiter`, a `ready` future and a `cancelled` future as arguments.
        - Sets `ready` future when it attempts to acquire the limiter.
        - Waits to acquire the `limiter` using `async with limiter:`.
        - Sets `cancelled` future when it acquires the limiter (this should ideally not happen in the race condition scenario).
    - **Step 3:** Create a main async function `test_limiter_race_condition()`:
        - Create a scope using `async with duet.new_scope() as scope:`.
        - Create a `release_future = duet.AwaitableFuture()`.
        - Create a `limiter_acquired_future = duet.AwaitableFuture()`.
        - Create a list of `cancelled_futures = []`.
        - Spawn a task that releases the limiter after a short delay:
          ```python
          async def release_task():
              await release_future  # Wait for signal to release
              async with limiter: # Acquire and immediately release to simulate release from another task
                  pass
          scope.spawn(release_task)
          ```
        - Spawn multiple `job` tasks (e.g., 5 tasks) within the scope, passing the limiter, ready futures, and cancelled futures.
        - For each job task, create `ready_future = duet.AwaitableFuture()` and `cancelled_future = duet.AwaitableFuture()`, and append `cancelled_future` to `cancelled_futures`.
        - Set `release_future.set_result(None)` to trigger the release task.
        - Cancel all spawned `job` tasks using `scope.cancel()`.
        - Wait for a short duration (e.g., `await duet.sleep(0.1)`).
        - Assert that at least one `cancelled_future` is not set (meaning a task acquired the lock even after cancellation and release, which should ideally not happen due to race condition). Or, in the ideal race condition scenario assert that no `cancelled_future` is set, and the limiter is still blocked even after release. This scenario is hard to reliably trigger in a test.
        - A more reliable test would be to assert that the limiter count is incorrect after the operations, or that subsequent acquire attempts are unexpectedly blocked.

    - **Expected Result:** The test should ideally demonstrate a scenario where due to the race condition in `_release`, a task might be unexpectedly blocked or the limiter's internal state becomes inconsistent under concurrent cancellations and releases. Due to the probabilistic nature of race conditions, the test might need to be run multiple times to increase the likelihood of triggering the vulnerability. A more robust test might involve assertions on the limiter's internal count or queue size after the test execution.

This vulnerability highlights a potential flaw in the `Limiter`'s release mechanism under concurrent cancellation scenarios. While the current implementation attempts to handle cancellations, the race condition can lead to unexpected behavior and potentially impact the reliability of concurrency control in applications using `duet`.
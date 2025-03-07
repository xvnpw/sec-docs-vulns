## Vulnerability List

### Re-entrant Scheduler Race Condition
- **Description:**
    - A developer uses `duet.run` to initiate asynchronous execution of function `func_a`.
    - `func_a` operates on shared mutable state, such as global variables or class attributes.
    - During its execution, `func_a` invokes a synchronous function, `func_sync`.
    - `func_sync` re-enters the duet scheduler by calling `duet.run` to execute another asynchronous function, `func_b`.
    - Due to duet's re-entrant design, both `func_a` and `func_b` are executed within the same thread, potentially interleaving their operations.
    - If `func_a` and `func_b` concurrently access and modify the shared mutable state without proper synchronization, a race condition can occur.
    - This race condition can lead to unpredictable program states and data corruption as operations from `func_a` and `func_b` interfere with each other's access to the shared state.
    - An attacker could exploit this by inducing concurrent executions of code paths involving re-entrant `duet.run` calls that operate on shared resources.
- **Impact:**
    - Data corruption due to inconsistent state modifications.
    - Unexpected program behavior, potentially leading to application errors or crashes.
    - In security-sensitive contexts, race conditions could be leveraged for privilege escalation or information disclosure if they affect access control decisions or data confidentiality.
- **Vulnerability Rank:** High
- **Currently Implemented Mitigations:**
    - None. The library itself does not prevent race conditions arising from re-entrant usage. The documentation in `README.md` mentions re-entrancy as a feature, but does not explicitly warn about the concurrency risks associated with shared mutable state in re-entrant scenarios.
- **Missing Mitigations:**
    - **Documentation Warning:** Explicitly document the risks of race conditions when using `duet`'s re-entrancy feature, particularly when mixing synchronous and asynchronous code that accesses shared mutable state. Emphasize the need for developers to implement their own synchronization mechanisms (like locks) when dealing with shared resources in re-entrant contexts.
    - **Code Examples and Best Practices:** Provide code examples demonstrating safe and unsafe patterns of using re-entrancy, highlighting how to avoid race conditions using synchronization primitives.
    - **Static Analysis Tooling (Optional):** Consider developing or recommending static analysis tools or linters that can detect potential race conditions in duet applications arising from re-entrant `duet.run` calls and shared mutable state access. However, this might be complex and have false positives.
- **Preconditions:**
    - The target application utilizes the `duet` library.
    - The application's code employs duet's re-entrancy feature, with synchronous functions calling `duet.run` within an outer asynchronous context managed by `duet.run`.
    - Shared mutable state (global variables, class attributes, or shared objects) is accessed and modified by both the outer and inner asynchronous functions executed via re-entrant `duet.run` calls.
    - An attacker can trigger concurrent executions of the vulnerable code paths, for example, by sending multiple requests to an API endpoint that uses this pattern.
- **Source Code Analysis:**
    - `duet/api.py`: The `run` function creates a new `Scheduler` instance for each call. This design inherently allows re-entrancy because each `run` call sets up its own event loop and task management.
    - ```python
      def run(func: Callable[..., Awaitable[T]], *args, **kwds) -> T:
          """Run an async function to completion."""
          scheduler = impl.Scheduler() # New scheduler instance for each run
          scheduler.init_signals()
          try:
              task = scheduler.spawn(func(*args, **kwds))
              # ... event loop execution ...
              return task.result
          finally:
              scheduler.cleanup_signals()
      ```
    - `duet/impl.py`: The `Scheduler` class is responsible for managing and executing tasks. It is designed to handle tasks within its own isolated event loop. When `duet.run` is called again within an existing `duet` context, a new `Scheduler` and event loop are created and nested within the existing one. This nesting and re-entry are explicitly permitted by the library's design.
    - The core issue is not within the library's implementation itself, but in how developers might incorrectly use this re-entrancy feature without considering the concurrency implications when shared mutable state is involved. The library does not enforce any synchronization or provide warnings about these potential issues.
- **Security Test Case:**
    1. **Setup:** Deploy a simple web service (e.g., using Flask or FastAPI) that uses the `duet` library in its backend logic.
    2. **Vulnerable Endpoint:** Create an API endpoint, for example `/api/race_condition`, which, when accessed, executes the following code within a request handler:
        ```python
        import duet
        import threading
        from flask import Flask

        app = Flask(__name__)
        global_counter = 0
        lock = threading.Lock() # Mitigation - adding lock

        async def async_increment_counter():
            global global_counter
            global_counter += 1
            await duet.completed_future(None) # Simulate async operation

        def sync_operation():
            async def nested_async_increment_counter():
                global global_counter
                global_counter += 1
                await duet.completed_future(None) # Simulate nested async op
            duet.run(nested_async_increment_counter)

        async def func_a():
            await async_increment_counter()
            sync_operation()
            return global_counter

        @app.route('/api/race_condition')
        def race_condition():
            return str(duet.run(func_a)) # Entry point using duet.run

        if __name__ == '__main__':
            app.run(debug=False, threaded=True) # Use threaded Flask server for concurrency
        ```
        *(Note: The `lock` and `threaded=True` are added for mitigation demonstration later, for the initial test, they should be removed to demonstrate the vulnerability.)*

    3. **Concurrent Requests:** Use a tool like `ab` (Apache Benchmark), `wrk`, or `curl` in a loop to send a large number of concurrent requests to the `/api/race_condition` endpoint. For example, using `ab`:
        ```bash
        ab -n 1000 -c 10 http://localhost:5000/api/race_condition
        ```
        `-n 1000`:  Send 1000 total requests.
        `-c 10`:    Send requests with a concurrency of 10 (10 requests at a time).

    4. **Observe Results (Vulnerable Case - No Lock):** Run the test without the `lock` and with `threaded=True` in Flask. Observe the responses. Due to the race condition, the returned counter values may not be sequentially incremented as expected. The final counter value after 1000 requests might be significantly less than 2000 (because each request intends to increment the counter twice). Inconsistent values returned in responses during concurrent requests are also indicators.

    5. **Implement Mitigation (Lock):** Add a threading lock around the counter increments in both `async_increment_counter` and `nested_async_increment_counter`:
        ```python
        async def async_increment_counter():
            global global_counter, lock
            with lock: # Mitigation: acquire lock
                global_counter += 1
            await duet.completed_future(None)

        def sync_operation():
            async def nested_async_increment_counter():
                global global_counter, lock
                with lock: # Mitigation: acquire lock
                    global global_counter += 1
                await duet.completed_future(None)
            duet.run(nested_async_increment_counter)
        ```

    6. **Observe Results (Mitigated Case - With Lock):** Rerun the same concurrent request test (`ab -n 1000 -c 10 http://localhost:5000/api/race_condition`) after implementing the lock. With proper locking, the race condition should be mitigated. The returned counter values should be more consistent, and the final counter value should be closer to the expected 2000 (or exactly 2000 if no other operations are modifying the counter).

This test case demonstrates how an external attacker can observe the effects of a race condition caused by re-entrant `duet.run` calls and shared mutable state through a publicly accessible API, and how adding a simple lock can mitigate the vulnerability.
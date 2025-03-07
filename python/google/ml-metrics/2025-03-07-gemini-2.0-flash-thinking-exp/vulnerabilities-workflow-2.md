## Combined Vulnerability Report

This report summarizes identified vulnerabilities, combining information from multiple lists and removing duplicates, focusing on high and critical severity issues that are realistically exploitable.

### Pickle Deserialization Vulnerability in LazyFn and Courier Communication

- **Vulnerability Name:** Pickle Deserialization Vulnerability in LazyFn and Courier Communication

- **Description:**
    1. The `ml-metrics` library utilizes `cloudpickle` for serializing and deserializing Python objects, specifically within the `LazyFn` mechanism and during courier-based distributed computation.
    2. An attacker can craft a malicious pickled payload and embed it within a machine learning dataset.
    3. If an application using `ml-metrics` processes this dataset and deserializes the payload using `lazy_fns.maybe_make` or through courier communication (which internally uses pickling), arbitrary code execution can occur on the server or client processing the data.
    4. This vulnerability stems from the inherent insecurity of pickle deserialization when handling untrusted data, as it can execute arbitrary code embedded within the pickled data.

- **Impact:**
    - **Remote Code Execution (RCE):** Successful exploitation grants the attacker the ability to execute arbitrary code on the machine processing the malicious dataset. This can lead to complete system compromise, data exfiltration, or further attacks on internal networks.
    - **Data Manipulation:** Attackers can also manipulate data processed by the library, leading to incorrect metric calculations or corrupted machine learning models.

- **Vulnerability Rank:** Critical

- **Currently Implemented Mitigations:**
    - None. The project extensively uses `cloudpickle` without any input validation or sanitization measures to prevent the deserialization of malicious payloads.

- **Missing Mitigations:**
    - **Input Sanitization:** Implement robust input validation to detect and reject potentially malicious pickled payloads within datasets before deserialization.
    - **Secure Deserialization:** Replace `cloudpickle` with a safer serialization format like JSON or Protocol Buffers for data exchange, particularly when handling untrusted datasets. If pickle is necessary for internal object serialization, implement a secure deserialization mechanism that prevents code execution, such as using `pickle.safe_load` (if applicable and sufficient for the library's needs) or sandboxing the deserialization process.
    - **Content Security Policy (CSP):** If the library is used in a web application context (less likely but possible if metrics are visualized), implement a strong Content Security Policy to restrict the execution of dynamically generated code.

- **Preconditions:**
    - The application using `ml-metrics` must process untrusted machine learning datasets.
    - The untrusted dataset must be designed to include a malicious pickled object that will be deserialized by the library.

- **Source Code Analysis:**
    1. **`ml_metrics/_src/chainables/lazy_fns.py`**:
        - The `_maybe_lru_cache` decorator and `maybe_make` function use `lazy_fns.pickler.loads` to deserialize cached results. If a `LazyObject` is created with a malicious payload and cached, subsequent calls to `maybe_make` could trigger deserialization.
        - `LazyFn` and `LazyObject` themselves are serialized using `cloudpickle`, increasing the attack surface during inter-process or distributed operations.

        ```python
        # File: ml_metrics/_src/chainables/lazy_fns.py
        @_maybe_lru_cache(maxsize=_LAZY_OBJECT_CACHE_SIZE)
        def result_(self) -> _T | LazyObject[_T]:
          """Dereference the lazy object."""
          result = self.value
          if self._lazy_result:
            result = LazyObject.new(result)
          return result

        def maybe_unpickle(value: Any) -> Any:
          if isinstance(value, bytes):
            return pickler.loads(value) # Potential vulnerability: unsafe deserialization
          return value

        def maybe_make(
            maybe_lazy: types.MaybeResolvable[_T] | bytes,
        ) -> types.MaybeResolvable[_T]:
          """Dereference a lazy object or lazy function when applicable."""
          maybe_lazy = maybe_unpickle(maybe_lazy) # Potential vulnerability: unsafe deserialization
          return _maybe_make(maybe_lazy)
        ```

    2.  **`ml_metrics/_src/utils/courier_utils.py`**:
        - Courier communication relies on `lazy_fns.pickler` for serializing and deserializing data sent between workers and servers. This is a critical point of vulnerability if communication channels are not secured or if data sources are untrusted.

        ```python
        # File: ml_metrics/_src/utils/courier_utils.py
        def _maybe_pickle(obj: Any) -> Any:
          # Relying on courier's own pickler for primitives.
          if type(obj) in (str, int, float, bool, type(None)):
            return obj
          try:
            return lazy_fns.pickler.dumps(obj) # Potential vulnerability: unsafe serialization
          except Exception as e:  # pylint: disable=broad-exception-caught
            raise ValueError(f'Having issue pickling {obj}') from e

        def _result_or_exception(self, pickled: bytes) -> Any | Exception:
          result = lazy_fns.pickler.loadz(pickled) # Potential vulnerability: unsafe deserialization
          if isinstance(result, Exception):
            raise result
          if isinstance(result, lazy_fns.LazyObject):
            return RemoteObject.new(result, worker=self)
          return result
        ```

- **Security Test Case:**
    1. Create a malicious pickled payload using Python's `pickle` module that executes arbitrary code upon deserialization. For example, a payload that executes `os.system('touch /tmp/pwned')`.
    2. Craft a machine learning dataset (e.g., in CSV or NumPy format) and embed the malicious pickled payload as a value in one of the data fields.
    3. Write a Python script that uses the `ml-metrics` library to process this crafted dataset. The script should simulate a typical use case of the library, such as calculating metrics on the dataset. Ensure that the malicious payload gets deserialized, for instance, by passing it through a `LazyFn` or simulating courier communication if possible within the test setup.
    4. Run the Python script.
    5. Observe if the arbitrary code execution is successful. In this example, check if the file `/tmp/pwned` is created. If it is, the vulnerability is confirmed.
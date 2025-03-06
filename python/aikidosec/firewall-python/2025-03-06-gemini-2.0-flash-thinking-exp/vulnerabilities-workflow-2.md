## Combined Vulnerability List

This document outlines the combined list of identified vulnerabilities, consolidated from multiple reports and filtered to remove duplicates and exclude vulnerabilities not meeting the specified criteria (high or critical severity, realistic exploitability, complete description, and evidence of exploit).

### 1. Default Mode Insecurity: Detection Mode

- **Description:**
    1. The Aikido Zen firewall for Python defaults to detection mode.
    2. In detection mode, the firewall analyzes requests and reports potential attacks to Aikido Security, but it does not block malicious requests.
    3. Users deploying the application might mistakenly believe they are protected by the firewall with default settings.
    4. If the `AIKIDO_BLOCK` environment variable is not explicitly set to `true`, the application remains vulnerable as attacks are only detected and logged, but not prevented.
    5. An attacker can exploit this misconfiguration by launching web attacks against an application deployed with default settings.
    6. These attacks will be logged by Aikido Zen, but the application will still process the malicious requests, leading to potential security breaches like SQL injection, command injection, or other web vulnerabilities.

- **Impact:**
    - Applications deployed with the default configuration are vulnerable to web attacks (SQL injection, Command injection, Path traversal, SSRF, NoSQL injection) as the firewall operates in detection-only mode.
    - False sense of security for application owners who may believe they are protected by the firewall when it is not actively blocking attacks.
    - Potential data breaches, unauthorized access, or other security incidents due to unblocked attacks.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
    - Documentation explicitly states that `AIKIDO_BLOCK` environment variable must be set to `true` to enable blocking mode.
    - README.md and framework-specific documentation highlight the importance of setting `AIKIDO_BLOCK` for production environments.
    - Benchmarks and feature lists in README.md are designed to showcase the security benefits, implicitly encouraging users to use the firewall effectively, which includes blocking mode in production.

- **Missing Mitigations:**
    - **Stronger Default Configuration:**  The default mode could be changed to blocking mode, or at least a warning message could be displayed during application startup in production environments if `AIKIDO_BLOCK` is not explicitly set.
    - **Runtime Warning:**  The firewall could log a warning message at startup if it detects that it is running in detection mode (i.e., `AIKIDO_BLOCK` is not `true`) and `AIKIDO_TOKEN` is set, indicating a likely production environment where blocking is intended but not active.
    - **Configuration Check during Startup:**  The `aikido_zen.protect()` function could perform a check for the `AIKIDO_BLOCK` environment variable and issue a warning or error if it's not set to `true` in a non-development environment (e.g., when `AIKIDO_TOKEN` is set).

- **Preconditions:**
    - The user must install and integrate the Aikido Zen library into their Python web application.
    - The user must deploy the application to a production or staging environment.
    - The user must *not* set the `AIKIDO_BLOCK` environment variable to `true`.

- **Source Code Analysis:**
    - The vulnerability is not directly within the Python code that implements the firewall's detection logic.
    - The relevant part is the documentation and the absence of code that enforces or strongly encourages blocking mode in production.
    - `/code/docs/README.md`: This file clearly documents the `AIKIDO_BLOCK` variable and explains the default detection mode:
        ```markdown
        ## Running in production (blocking) mode

        By default, Zen will only detect and report attacks to Aikido.

        To block requests, set the `AIKIDO_BLOCK` environment variable to `true`.
        ```
    - `/code/aikido_zen/__init__.py`: The `protect()` function in `__init__.py` starts the background process and imports sinks/sources, but it does not enforce or check the `AIKIDO_BLOCK` variable itself. The blocking mode is handled within the middleware and sink logic, based on the configuration fetched from the background process, which in turn reads the `AIKIDO_BLOCK` environment variable.

- **Security Test Case:**
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

### 2. SQL Injection Vulnerability in create_dogpage View

- **Description:**
    1. The `create_dogpage` view in `sample_app/views.py` of Django sample applications uses raw SQL queries to insert data into the database.
    2. The view takes user input `dog_name` from the POST request without sanitization.
    3. An attacker can inject malicious SQL code into the `dog_name` parameter.
    4. This injected SQL code will be executed directly against the database when `cursor.execute(query)` is called.
    5. By crafting a malicious `dog_name` like `"Malicious dog", "Injected wrong boss name"); -- `, an attacker can inject arbitrary SQL queries.

- **Impact:**
    - An attacker can execute arbitrary SQL queries on the database.
    - This can lead to data exfiltration, modification, or deletion.
    - In the provided example, the attacker can modify the `dog_boss` field, which is not intended to be user-modifiable, demonstrating unauthorized data modification.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
    - The Aikido Zen firewall is designed to detect and block SQL injection attempts.
    - When Aikido Zen is enabled (using `aikido_zen.protect()` in `manage.py` or `app.py`), it should intercept and analyze the request, potentially blocking or reporting the SQL injection attempt.

- **Missing Mitigations:**
    - The `create_dogpage` view in `sample_app/views.py` should use parameterized queries or an ORM to prevent SQL injection instead of constructing raw SQL queries from user input.
    - Input sanitization on the `dog_name` field should be implemented in the view, even if the firewall is in place, as a defense-in-depth measure.

- **Preconditions:**
    - Aikido Zen firewall must be in non-blocking mode or bypassed to successfully exploit the vulnerability. If Aikido Zen is in blocking mode and correctly detects the payload, the attack will be blocked.
    - The Django sample application must be running and accessible.

- **Source Code Analysis:**
    - File: `/code/sample-apps/django-mysql/sample_app/views.py` and similar `views.py` in other Django sample apps.
    - ```python
      @csrf_exempt
      def create_dogpage(request):
          if request.method == 'GET':
              return render(request, 'app/create_dog.html')
          elif request.method == 'POST':
              dog_name = request.POST.get('dog_name')
              # Using custom sql to create a dog :
              with connection.cursor() as cursor:
                  query = 'INSERT INTO sample_app_dogs (dog_name, dog_boss) VALUES ("%s", "N/A")' % dog_name # Vulnerable line
                  print("QUERY : ", query)
                  cursor.execute(query)
              return HttpResponse("Dog page created")
      ```
    - The line `query = 'INSERT INTO sample_app_dogs (dog_name, dog_boss) VALUES ("%s", "N/A")' % dog_name` constructs a SQL query using string formatting with user-provided `dog_name`. This is a classic SQL injection vulnerability.

- **Security Test Case:**
    1. Start the `django-mysql` sample app with Aikido Zen disabled (using `make runZenDisabled` in `/code/sample-apps/django-mysql/`).
    2. Access the create dog page: `http://localhost:8081/app/create`.
    3. Submit a POST request to `http://localhost:8081/app/create` with `dog_name` set to `Malicious dog", "Injected wrong boss name"); -- `.
    4. Access the homepage: `http://localhost:8081/app`.
    5. Verify that a dog named "Malicious dog" is created and its boss name is "Injected wrong boss name"); -- " instead of "N/A", confirming successful SQL injection.
    6. Now, start the `django-mysql` sample app with Aikido Zen enabled (using `make run` in `/code/sample-apps/django-mysql/`).
    7. Repeat steps 2 and 3.
    8. Verify that the request returns a 500 error, indicating that Aikido Zen blocked the request and prevented the SQL injection when in blocking mode, or check Aikido dashboard for attack report in non-blocking mode and verify boss_name is still "N/A" in database.

### 3. Command Injection Vulnerability in shell_url View

- **Description:**
    1. The `shell_url` view in `sample_app/views.py` of Django MySQL sample application executes shell commands based on user input.
    2. The view takes user input `user_command` from the URL path without sanitization.
    3. An attacker can inject arbitrary shell commands into the `user_command` parameter.
    4. The injected command is executed using `subprocess.run(user_command, capture_output=True, text=True, shell=True)`, which is vulnerable to command injection when `shell=True`.
    5. By crafting a malicious `user_command` like `ls -la`, an attacker can execute arbitrary shell commands on the server.

- **Impact:**
    - An attacker can execute arbitrary commands on the server.
    - This can lead to complete server compromise, data exfiltration, or denial of service.

- **Vulnerability Rank:** Critical

- **Currently Implemented Mitigations:**
    - Aikido Zen firewall is designed to detect and block command injection attempts.
    - When Aikido Zen is enabled, it should intercept and analyze the request, potentially blocking or reporting the command injection attempt.

- **Missing Mitigations:**
    - The `shell_url` view should avoid using `shell=True` in `subprocess.run`.
    - Input sanitization on the `user_command` should be implemented in the view, even if the firewall is in place, as a defense-in-depth measure.
    - Ideally, avoid executing shell commands based on user input altogether. If necessary, use safer alternatives like whitelisting allowed commands or using libraries that don't involve shell execution.

- **Preconditions:**
    - Aikido Zen firewall must be in non-blocking mode or bypassed to successfully exploit the vulnerability. If Aikido Zen is in blocking mode and correctly detects the payload, the attack will be blocked.
    - The Django sample application must be running and accessible.

- **Source Code Analysis:**
    - File: `/code/sample-apps/django-mysql/sample_app/views.py` and similar `views.py` in other Django sample apps.
    - ```python
      def shell_url(request, user_command):
          result = subprocess.run(user_command, capture_output=True, text=True, shell=True) # Vulnerable line
          return HttpResponse(str(result.stdout))
      ```
    - The line `result = subprocess.run(user_command, capture_output=True, text=True, shell=True)` executes a shell command directly from user input `user_command`. This is a direct command injection vulnerability.

- **Security Test Case:**
    1. Start the `flask-mysql` sample app with Aikido Zen disabled (using `make runZenDisabled` in `/code/sample-apps/flask-mysql/`).
    2. Access the shell URL with a malicious command: `http://localhost:8087/shell` (or `http://localhost:8087/shell/<command>` for GET based command execution).
    3. In the form, enter a command like `ls -la` or `id` and submit.
    4. Verify that the output of the command (e.g., directory listing or user ID) is displayed on the page, confirming successful command injection.
    5. Now, start the `flask-mysql` sample app with Aikido Zen enabled (using `make run` in `/code/sample-apps/flask-mysql/`).
    6. Repeat steps 2 and 3.
    7. Verify that the request returns a 500 error, indicating that Aikido Zen blocked the request and prevented the command injection when in blocking mode, or check Aikido dashboard for attack report in non-blocking mode and verify command is not executed.

### 4. Server-Side Request Forgery (SSRF) in request View

- **Description:**
    1. The `request` view in `sample-apps/flask-mysql/app.py` allows users to make HTTP requests to arbitrary URLs.
    2. The view takes user input `url` from the POST request without sanitization or validation.
    3. The application uses `requests.get(url)` to fetch content from the provided URL.
    4. An attacker can supply a malicious URL, potentially targeting internal network resources or sensitive endpoints, leading to SSRF.
    5. By providing a URL like `http://localhost:3000/private`, an attacker can attempt to access resources within the server's internal network.

- **Impact:**
    - An attacker can make requests to internal services or external URLs from the server.
    - This can lead to information disclosure, access to internal resources, or further exploitation of internal systems.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
    - Aikido Zen firewall is designed to detect and block SSRF attempts in the `http` module.
    - When Aikido Zen is enabled, it should intercept and analyze the `requests.get(url)` call, potentially blocking or reporting the SSRF attempt.

- **Missing Mitigations:**
    - The `request` view should implement URL validation and sanitization to restrict the URLs that can be requested.
    - A whitelist of allowed domains or URL patterns should be used to limit the scope of allowed requests.
    - Consider disallowing requests to private IP addresses or internal networks.

- **Preconditions:**
    - Aikido Zen firewall must be in non-blocking mode or bypassed to successfully exploit the vulnerability. If Aikido Zen is in blocking mode and correctly detects the payload, the attack will be blocked.
    - The Flask sample application must be running and accessible.

- **Source Code Analysis:**
    - File: `/code/sample-apps/flask-mysql/app.py`
    - ```python
      @app.route("/request", methods=['POST'])
      def make_request():
          url = request.form['url']
          res = requests.get(url) # Vulnerable line
          return str(res)
      ```
    - The line `res = requests.get(url)` directly uses user-provided `url` to make an HTTP request without validation. This is a clear SSRF vulnerability.

- **Security Test Case:**
    1. Start the `flask-mysql` sample app with Aikido Zen disabled (using `make runZenDisabled` in `/code/sample-apps/flask-mysql/`).
    2. Access the request form page: `http://localhost:8087/request`.
    3. In the form, enter an internal URL like `http://localhost:8087/` (accessing the app itself) or `http://127.0.0.1:3306` (attempting to access the MySQL database port if running externally) and submit.
    4. Verify that the response reflects content from the internal URL, indicating successful SSRF.
    5. Now, start the `flask-mysql` sample app with Aikido Zen enabled (using `make run` in `/code/sample-apps/flask-mysql/`).
    6. Repeat steps 2 and 3.
    7. Verify that the request returns a 500 error, indicating that Aikido Zen blocked the request and prevented the SSRF when in blocking mode, or check Aikido dashboard for attack report in non-blocking mode and verify internal resource is not accessed.
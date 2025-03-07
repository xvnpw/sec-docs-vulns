- Vulnerability Name: Remote Command Execution via Configurable Script Paths
  - Description: An attacker who gains write access to the `config.json` file can modify the `exec_win` or `exec_unix` parameters within the `incident_notification` section. These parameters specify the paths to executable scripts that are intended to be used for legacy system integrations. By altering these paths to point to malicious scripts or commands, an attacker can achieve remote command execution on the server hosting the webhook. When Dynatrace sends a problem notification to the webhook and the `incident_notification.active` flag is set to `true`, the `call_integration` function, specifically `call_incident_software`, will execute the script located at the attacker-defined path. This execution happens via `subprocess.call` without sufficient sanitization or validation of the configured paths, allowing for arbitrary command execution.
  - Impact: Critical. Successful exploitation of this vulnerability allows for unauthenticated remote command execution. An attacker can gain complete control over the webhook server, potentially leading to:
    - Data breach: Access to sensitive data stored on the server or accessible from it.
    - System compromise: Installation of malware, backdoors, or ransomware.
    - Denial of Service: Shutting down or disrupting the webhook service or other services on the server.
    - Lateral movement: Using the compromised server as a stepping stone to attack other systems within the network.
  - Vulnerability Rank: Critical
  - Currently Implemented Mitigations:
    - Basic authentication is implemented for the webhook endpoint using Flask-BasicAuth. This requires users to authenticate with a username and password defined in `config.json` to access the webhook functionality. However, this mitigation does not prevent an attacker who has already gained write access to the filesystem and `config.json` from exploiting the vulnerability.
  - Missing Mitigations:
    - Input validation and sanitization: The application lacks validation for the `exec_win` and `exec_unix` paths in `config.json`. It should verify that these paths are within a safe, predefined directory and that the executables are trusted. Ideally, the application should avoid executing external scripts based on user-provided paths altogether.
    - Principle of least privilege: The webhook application should be run with minimal necessary privileges. This would restrict the scope of damage an attacker can inflict even after achieving command execution.
    - Configuration file protection: Implement proper file system permissions to restrict write access to the `config.json` file. Only the administrator or authorized processes should be able to modify this file.
    - Security Monitoring and Alerting: Implement monitoring to detect unauthorized modifications to the `config.json` file. Any change to this file should trigger an alert to the system administrators.
  - Preconditions:
    - The attacker must gain write access to the `config.json` file on the server where the webhook is deployed. This could be achieved through various methods, such as exploiting other vulnerabilities in the application or server, social engineering, or insider threat.
    - The `incident_notification.active` setting in `config.json` must be set to `true` for the vulnerable code path to be executed.
    - Dynatrace must be configured to send problem notifications to the webhook endpoint.
    - A Dynatrace problem must occur and trigger a notification to the webhook.
  - Source Code Analysis:
    - The `webhook.py` script begins by loading configuration data from `config.json` using `json.load(open('config.json'))`.
    - It retrieves the executable paths from the configuration:
      ```python
      EXEC_WIN = config['incident_notification']['exec_win']
      EXEC_UNIX = config['incident_notification']['exec_unix']
      INCIDENT_NOTIFICATION = config['incident_notification']['active']
      ```
    - The Flask route `@app.route('/', methods=['POST'])` handles incoming POST requests, which are expected to be Dynatrace problem notifications. This route is protected by basic authentication using `@basic_auth.required`.
    - Inside the `handle_post` function, after processing the notification, the `call_integration(problem_simple['PID'])` function is called.
    - The `call_integration` function checks if `INCIDENT_NOTIFICATION` is enabled and, if so, calls `call_incident_software(problem_details)`.
    - Within `call_incident_software`, the script determines the operating system and selects the corresponding executable path (`EXEC_WIN` or `EXEC_UNIX`) from the configuration:
      ```python
      if os.name == 'nt':
          EXECUTABLE = EXEC_WIN
      else:
          EXECUTABLE = EXEC_UNIX
      ```
    - Finally, the script executes the configured executable using `subprocess.call`:
      ```python
      return_code = (subprocess.call(EXECUTABLE + ' ' + argument, shell=True))
      ```
      **Vulnerability:** The vulnerability lies in the fact that `EXECUTABLE` is directly derived from the `config.json` file without any validation or sanitization. An attacker who can modify `config.json` can set `EXEC_WIN` or `EXEC_UNIX` to an arbitrary command, which will then be executed by the `subprocess.call` function when a Dynatrace notification is processed. The use of `shell=True` in `subprocess.call` is also dangerous and should be avoided, although in this specific case the primary vulnerability is the lack of path validation.

  - Security Test Case:
    1. Setup: Deploy the webhook application on a test server and ensure it is running. Configure Dynatrace to send problem notifications to this webhook. You need to simulate gaining write access to the `config.json` file on the server, for testing purposes you can directly edit the file.
    2. Modify `config.json`: Edit the `config.json` file on the webhook server. Locate the `incident_notification` section and modify `exec_unix` (if the server is Linux) or `exec_win` (if Windows) to point to a command that will create a file in a publicly accessible directory, for example:
       - For Linux:
         ```json
         "incident_notification": {
             "active": true,
             "exec_win": "legacy_script.bat",
             "exec_unix": "/bin/touch /tmp/webhook_pwned"
         },
         ```
       - For Windows:
         ```json
         "incident_notification": {
             "active": true,
             "exec_win": "C:\\Windows\\System32\\cmd.exe /c echo pwned > C:\\temp\\webhook_pwned.txt",
             "exec_unix": "legacy_script.sh"
         },
         ```
         Ensure the webserver user has permissions to write to `/tmp` or `C:\\temp`.
    3. Trigger Dynatrace Notification: In Dynatrace, trigger a problem notification to be sent to the webhook. You can usually do this by creating a test problem or using the "Send test notification" feature in Dynatrace Problem Notification settings.
    4. Verify Command Execution: After triggering the notification, access the webhook server and check for the created file.
       - For Linux, check if the file `/tmp/webhook_pwned` exists.
       - For Windows, check if the file `C:\\temp\\webhook_pwned.txt` exists and contains "pwned".
    5. Successful Exploitation: If the file has been successfully created, it confirms that the command injected via `config.json` was executed, demonstrating the Remote Command Execution vulnerability.
- Vulnerability Name: Command Injection via Legacy Executable Integration
- Description:
    - An attacker can inject arbitrary commands into the operating system by crafting a malicious Dynatrace problem notification.
    - The vulnerability exists in the 'legacy executable' integration feature, where parameters from the Dynatrace notification are passed to a shell command without proper sanitization.
    - Steps to trigger the vulnerability:
        1.  Dynatrace sends a problem notification to the webhook.
        2.  The webhook receives the notification and extracts problem details, including entity names and tags.
        3.  The `get_program_argument` function constructs command line arguments by embedding these details into a string.
        4.  The `call_incident_software` function executes a legacy script (`legacy_script.sh` or `legacy_script.bat`) using `subprocess.call` with `shell=True`, passing the constructed arguments.
        5.  If the Dynatrace problem notification contains malicious input in fields like entity names or tags, these inputs will be included in the command line arguments without sanitization.
        6.  Due to `shell=True`, the malicious input will be interpreted as shell commands and executed on the webhook server.
- Impact:
    - Successful command injection allows the attacker to execute arbitrary commands on the server hosting the webhook application.
    - This can lead to complete compromise of the server, including data theft, malware installation, denial of service, and lateral movement within the network if the server is part of a larger infrastructure.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations:
    - None. The code does not implement any input sanitization or validation for the parameters passed to the legacy executable.
- Missing Mitigations:
    - Input sanitization: Sanitize all input received from Dynatrace problem notifications before using them in shell commands. Specifically, escape or remove shell-sensitive characters from entity names, tags, and other relevant fields extracted from the notification payload.
    - Avoid `shell=True`:  When using `subprocess.call` or similar functions, avoid using `shell=True`. Instead, pass the command and arguments as a list to prevent shell injection. If `shell=True` is necessary for some reason, ensure all inputs are strictly controlled and sanitized.
    - Principle of least privilege: Run the webhook application with minimal privileges necessary to perform its functions. This limits the impact of successful command injection.
- Preconditions:
    - The 'incident_notification' feature must be active in the `config.json` file (`"active": true`).
    - Dynatrace must be configured to send problem notifications to the webhook.
    - An attacker needs to be able to influence the data within Dynatrace problem notifications, specifically fields that are used to construct the arguments for the legacy script. While direct external control over Dynatrace data might not be possible, vulnerabilities within Dynatrace or its integrations could potentially lead to malicious data being included in notifications. For the purpose of demonstrating the vulnerability in *this webhook application*, we assume that a malicious string can be present in the Dynatrace problem notification data.
- Source Code Analysis:
    - The vulnerability is located in the `call_incident_software` function in `webhook.py`.
    - Snippet from `webhook.py`:
      ```python
      def call_incident_software(problem_details):
          # ...
          argument_list = get_program_argument(problem_details)
          # ...
          for argument in argument_list:
              return_code = (subprocess.call(EXECUTABLE + ' ' + argument, shell=True)) # Vulnerable line
              logging.info('Incident Software call for [{0}] RC[{1}] Executable:[{2}] Arguments:{3}'.format(str(problem_nr), return_code, EXECUTABLE, argument))
              return_codes.append(return_code)
          # ...
      ```
    - The `subprocess.call` function is used with `shell=True`. This means that the `argument` string is passed to the shell for execution.
    - The `argument` is constructed in the `get_program_argument` function:
      ```python
      def get_program_argument(problem_details):
          # ...
          msg = "Problem [{0}]: Status={1}, Severity={2}, ImpactLevel={3}, Tags={4}".format(nr, status, severity, element, tags)
          # ...
          for element in elements:
              e_name = element['entityName'] # Potentially malicious input
              e_severity = element['severityLevel']
              e_impact = element['impactLevel']
              e_eventType = element['eventType']
              element_msg = msg
              element_msg += " Entity details: Entity={0}, impactLevel={1}, severity={2}, eventType={3}".format(e_name, e_severity, e_impact, e_eventType)
              arguments_list.append(element_msg) # arguments_list contains un-sanitized input
          return arguments_list
      ```
    - The `get_program_argument` function retrieves `entityName` and `tags` from the `problem_details` dictionary, which originates from the Dynatrace notification.
    - These values are directly incorporated into the `argument` string without any sanitization.
    - Visualization of data flow:
      ```
      Dynatrace Notification --> webhook.py (handle_post) --> call_integration --> call_incident_software --> get_program_argument --> subprocess.call(shell=True, EXECUTABLE + ' ' + argument) --> OS Command Execution
      ```
- Security Test Case:
    - Pre-requisites:
        - Deploy the webhook application.
        - Configure Dynatrace to send problem notifications to the deployed webhook.
        - Ensure 'incident_notification' is active in `config.json`.
    - Steps:
        1.  Modify the Dynatrace setup (this step is for demonstration purposes as direct control over Dynatrace notification content might not be possible in a real attack scenario against *this webhook application*. In a real scenario, the attacker would rely on vulnerabilities within Dynatrace or its integrations to inject malicious data into notifications. For this test, we simulate such a scenario by manually triggering a notification with malicious content if possible via Dynatrace API or similar). Assume you can somehow influence Dynatrace to include a malicious string in the `entityName` field of a problem notification. For example, set the name of a monitored entity in Dynatrace to: `test_entity`; touch /tmp/pwned`.
        2.  Trigger a Dynatrace problem that affects the entity with the malicious name. This should cause Dynatrace to send a problem notification to the webhook.
        3.  Observe the webhook logs. You should see the `subprocess.call` execution with the injected command in the arguments.
        4.  Check if the command `touch /tmp/pwned` was executed on the webhook server. Verify if the file `/tmp/pwned` was created.
    - Expected result:
        - The file `/tmp/pwned` should be created on the webhook server, indicating successful command injection.
        - The webhook logs should show the execution of the injected command.
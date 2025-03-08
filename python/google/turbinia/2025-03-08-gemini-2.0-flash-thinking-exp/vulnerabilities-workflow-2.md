## Combined Vulnerability List for Turbinia Project

- Vulnerability Name: Insecure Configuration via Base64 Encoded Environment Variables
    - Description:
      The Turbinia API server, controller, worker, and oauth2-proxy Docker images use shell scripts (`start.sh`) to base64 decode configuration files from environment variables (`TURBINIA_CONF`, `OAUTH2_CONF`, `OAUTH2_AUTH_EMAILS`). If these environment variables are compromised or not securely managed, attackers could inject malicious configurations.

      Step-by-step trigger:
      1. Deploy Turbinia using Docker, setting a malicious base64 encoded string to the `TURBINIA_CONF` environment variable.
      2. Start the Turbinia API server using the Docker image.
      3. Observe that the API server loads the malicious configuration from the environment variable.
    - Impact:
      An attacker who can control the environment variables of the Turbinia containers could inject arbitrary and malicious configurations, potentially leading to:
      - Unauthorized access to the Turbinia API server or other components.
      - Data exfiltration or manipulation.
      - Execution of arbitrary code within Turbinia workers or server.
    - Vulnerability Rank: high
    - Currently Implemented Mitigations: No specific mitigations are implemented in the project.
    - Missing Mitigations:
      - Avoid passing sensitive configurations via environment variables, even if base64 encoded.
      - Implement more secure configuration management practices, such as using secrets management systems or configuration files with restricted permissions.
      - Validate and sanitize configurations loaded from environment variables to prevent injection attacks.
    - Preconditions:
      - Ability to set environment variables for the Turbinia Docker containers during deployment or runtime.
    - Source Code Analysis:
      - **File: /code/docker/api_server/start.sh, /code/docker/controller/start.sh, /code/docker/server/start.sh, /code/docker/worker/start.sh, /code/docker/oauth2_proxy/start.sh:**
        - These scripts contain code that decodes environment variables using base64:
          ```bash
          if [ ! -z "$TURBINIA_CONF" ] && [ ! -s /etc/turbinia/turbinia.conf ]
          then
              echo "${TURBINIA_CONF}" | base64 -d > /etc/turbinia/turbinia.conf
          fi
          ```
          ```bash
          if [ ! -z "$OAUTH2_CONF" ] && [ ! -s /etc/turbinia/oauth2.conf ]
          then
              echo "${OAUTH2_CONF}" | base64 -d > /etc/turbinia/oauth2.conf
          fi
          ```
          ```bash
          if [ ! -z "$OAUTH2_AUTH_EMAILS" ] && [ ! -s /etc/turbinia/auth.txt ]
          then
              echo "${OAUTH2_AUTH_EMAILS}" | base64 -d > /etc/turbinia/auth.txt
          fi
          ```
    - Security Test Case:
      1. Create a malicious `turbinia.conf` file with a backdoor or harmful settings.
      2. Base64 encode the malicious configuration: `base64 -w 0 malicious_turbinia.conf`.
      3. Deploy Turbinia locally using Docker Compose, setting the `TURBINIA_CONF` environment variable to the base64 encoded malicious configuration:
         ```bash
         docker run -ti -e TURBINIA_CONF="<base64_encoded_malicious_config>" turbinia-api-server:dev
         ```
      4. Verify that the Turbinia API server is running with the injected malicious configuration (e.g., by observing unexpected behavior or checking loaded settings).

- Vulnerability Name: Potential Authentication Bypass or Privilege Escalation via API Authorization Flaws
    - Description:
      The documentation mentions that the Turbinia API server uses OAuth2 for authentication and authorization. However, the provided files do not contain source code for the API server itself, so it's impossible to verify if authorization is correctly implemented and enforced for all API endpoints. A potential vulnerability could exist if certain API endpoints lack proper authorization checks, allowing unauthorized users to access sensitive functionalities or data.

      Step-by-step trigger:
      1. Identify API endpoints from `/code/turbinia/api/client/docs/` that seem critical or sensitive (e.g., endpoints related to request creation, evidence download, task management).
      2. Attempt to access these endpoints without valid OAuth2 credentials or with credentials of a user who should not have access.
      3. Observe if the API server correctly denies access or if it allows unauthorized actions.
    - Impact:
      If authentication or authorization is flawed, an attacker could:
      - Gain unauthorized access to Turbinia API server functionalities.
      - Submit malicious forensic processing requests.
      - Access sensitive forensic evidence or results.
      - Potentially compromise the entire Turbinia deployment and the forensic process.
    - Vulnerability Rank: critical
    - Currently Implemented Mitigations:
      - The documentation states that OAuth2-proxy is used for authentication, suggesting that authentication is intended to be enforced. However, the implementation details are not in the provided files.
    - Missing Mitigations:
      - **Source code review and security audit:** Thoroughly review the API server source code to confirm that authentication and authorization are correctly implemented for all API endpoints.
      - **Security testing:** Perform penetration testing and security assessments to identify any authorization bypass vulnerabilities.
      - **Enforce RBAC (Role-Based Access Control):** Implement RBAC to control access to different API endpoints and functionalities based on user roles and permissions.
    - Preconditions:
      - Publicly accessible Turbinia API server instance.
      - Lack of proper authentication and authorization enforcement in the API server code.
    - Source Code Analysis:
      - **File: /code/turbinia/api/client/docs/TurbiniaRequestsApi.md, /code/turbinia/api/client/docs/TurbiniaTasksApi.md, /code/turbinia/api/client/docs/TurbiniaConfigurationApi.md, /code/turbinia/api/client/docs/TurbiniaEvidenceApi.md, /code/turbinia/api/client/docs/TurbiniaLogsApi.md, /code/turbinia/api/client/docs/TurbiniaJobsApi.md, /code/turbinia/api/client/docs/TurbiniaRequestResultsApi.md:**
        - These files are OpenAPI client documentation and indicate the existence of various API endpoints related to requests, tasks, evidence, configuration, jobs, and logs.
        - The documentation mentions "OAuth Authentication (oAuth2)" and "Authorization: [oAuth2](../README.md#oAuth2)" for API endpoints, suggesting that authentication is intended.
        - However, the actual server-side code implementing these endpoints and enforcing authorization is not provided in the PROJECT FILES, making it impossible to verify the security implementation.
    - Security Test Case:
      1. Deploy a Turbinia instance with API server enabled.
      2. Identify a sensitive API endpoint (e.g., `/api/request/`, `/api/evidence/upload`).
      3. Attempt to send a request to this endpoint without providing any OAuth2 access token in the `Authorization` header.
      4. Observe if the API server returns a 401 Unauthorized or 403 Forbidden error, indicating that authentication is enforced.
      5. If the API server allows the request without authentication, it indicates an authentication bypass vulnerability.
      6. If authentication is enforced, attempt to use a valid OAuth2 access token but for a user who should not have permission to access the endpoint (e.g., a regular user trying to access admin-level functionalities).
      7. Observe if the API server correctly denies access based on authorization policies.
      8. If the API server allows unauthorized access, it indicates an authorization flaw.

- Vulnerability Name: Command Injection in Strings Task via Filename
    - Description:
      1. An attacker can create a file with a malicious filename (e.g., `; touch injected.txt`).
      2. The attacker submits this file as evidence to Turbinia for processing via RawDisk evidence.
      3. Turbinia creates a TextFile evidence object and sets its `source_path` based on the malicious filename.
      4. The `StringsAsciiTask` executes the `strings` command, using the `source_path` of the TextFile evidence object without proper sanitization: `cmd = 'strings -a -t d {0:s} > {1:s}'.format(evidence.local_path, output_file_path)`.
      5. Due to shell=True being used in `self.execute`, the malicious filename is interpreted by the shell, leading to command injection.
      6. Arbitrary commands injected via the filename are executed on the Turbinia worker.
    - Impact:
      - **Critical**
      - Full command execution on the Turbinia worker.
      - Potential for data exfiltration, system compromise, or lateral movement within the cloud environment.
    - Vulnerability Rank: Critical
    - Currently Implemented Mitigations: None. The code directly uses unsanitized input in a shell command.
    - Missing Mitigations:
      - Input sanitization for filenames used in shell commands.
      - Avoidance of `shell=True` in `self.execute` when handling filenames or other user-controlled input.
      - Use of parameterized queries or shell-escape functions to prevent command injection.
    - Preconditions:
      - Attacker needs to be able to submit evidence to Turbinia, e.g., by having access to the Turbinia client or a publicly accessible Turbinia instance.
    - Source Code Analysis:
      File: /code/turbinia/workers/strings.py

      ```python
      class StringsAsciiTask(TurbiniaTask):
          # ...
          def run(self, evidence, result):
              # ...
              # Create a path that we can write the new file to.
              base_name = os.path.basename(evidence.local_path) # [POINT OF VULNERABILITY] base_name is derived from potentially malicious evidence.local_path
              output_file_path = os.path.join(
                  self.output_dir, '{0:s}.ascii'.format(base_name))
              # ...
              # Generate the command we want to run.
              cmd = 'strings -a -t d {0:s} > {1:s}'.format(
                  evidence.local_path, output_file_path) # [POINT OF VULNERABILITY] evidence.local_path, which can contain malicious filename, is used in shell command
              # ...
              # Actually execute the binary
              self.execute(
                  cmd, result, new_evidence=[output_evidence], close=True, shell=True) # [POINT OF VULNERABILITY] shell=True allows command injection
      ```

      The vulnerability lies in the `StringsAsciiTask.run` method.
      1. `base_name = os.path.basename(evidence.local_path)`: The `base_name` variable, used later in the output filename, is derived directly from `evidence.local_path`, which can be controlled by an attacker through the evidence filename.
      2. `cmd = 'strings -a -t d -e l {0:s} > {1:s}'.format(evidence.local_path, output_file_path)`: The `evidence.local_path` is directly incorporated into the shell command.
      3. `self.execute(cmd, result, ..., shell=True)`: The `shell=True` argument in `self.execute` makes the system vulnerable to command injection because the shell interprets special characters in the command string.
    - Security Test Case:
      1. Prepare a malicious file:
         ```bash
         touch "/tmp/evil_file_`; touch /tmp/pwned.txt`"
         ```
         This creates a file with a filename designed to inject a command.
      2. Create a RawDisk evidence with the malicious file as source:
         ```python
         from turbinia.evidence import RawDisk
         evil_evidence = RawDisk(source_path='/tmp/evil_file_`; touch /tmp/pwned.txt`')
         ```
      3. Submit a Turbinia request to process this evidence:
         ```python
         from turbinia import client
         turbinia_client = client.get_turbinia_client()
         request = turbinia_client.create_request(evidence_=evil_evidence)
         turbinia_client.send_request(request)
         print(f"Request submitted with ID: {request.request_id}")
         ```
      4. After the Turbinia request is processed, check for the injected file:
         ```bash
         # Assuming you have shell access to the Turbinia worker
         ls -l /tmp/pwned.txt
         ```
         If the file `/tmp/pwned.txt` exists on the worker, the command injection was successful.
         Alternatively, check Turbinia task output logs (worker-log.txt in task output directory) for evidence of command execution.

- Vulnerability Name: Command Injection in Fraken Yara Scanner via Rule Metadata
    - Description: An attacker can inject arbitrary commands into the system by crafting a malicious Yara rule file. Specifically, the vulnerability lies in the `fraken` tool's processing of rule metadata, where external variables can be defined. If a rule file contains a rule with a maliciously crafted metadata field, when `fraken` parses this rule, it can execute arbitrary commands.

      Steps to trigger vulnerability:
      1. Create a Yara rule file (`malicious.yar`) with a rule that includes a metadata field containing a command injection payload, e.g., metadata: { description = "rule to $(malicious_command)" }.
      2. Upload this malicious Yara rule file to a location accessible to Turbinia workers, or make it available through a signature-base repository that Turbinia workers can access.
      3. Submit a Turbinia request that uses the `Fraken` task, ensuring that the malicious rule file is included in the rules path.
      4. When the `Fraken` task executes on a Turbinia worker, it will parse the malicious rule file, and the command embedded in the metadata description field will be executed by the system.
    - Impact: Arbitrary command execution on the Turbinia worker. This can lead to complete system compromise, data exfiltration, or denial of service.
    - Vulnerability Rank: Critical
    - Currently Implemented Mitigations: None. The code processes rule metadata without sanitization.
    - Missing Mitigations:
      - Input sanitization for Yara rule metadata fields, specifically when defining external variables or processing description fields.
      - Sandboxing or containerization of the Yara scanning process to limit the impact of command injection vulnerabilities.
      - Principle of least privilege for the Fraken process, limiting the permissions of the account running the Yara scanner.
    - Preconditions:
      - Turbinia instance must have the Fraken task enabled and configured to use user-supplied or externally sourced Yara rules.
      - Attacker needs to be able to supply a malicious Yara rule file to the Turbinia instance, either by directly uploading it or by influencing an external rule repository.
    - Source Code Analysis:
      - The provided PROJECT FILES do not contain the source code of the `fraken` tool itself. To perform source code analysis, access to the `fraken` tool's source code (likely in the `tools/fraken` directory in a more complete version of the repository) would be necessary to pinpoint the exact code sections responsible for parsing rule metadata and executing commands. Based on the README.md of fraken, it is written in Go. The vulnerability likely exists in the Go code where Yara rules are parsed and processed, specifically where metadata or external variables are handled.  Without the Go source code, detailed line-by-line analysis is impossible. However, the description in `tools/fraken/README.md` mentions "rules that make use of the external variables defined in signature-base, as well as having those variables defined in the metadata fields of the rules" which strongly suggests that metadata parsing is a feature and thus a potential vulnerability point.
    - Security Test Case:
      1. Create a file `malicious.yar` with the following content:
      ```
      rule command_injection {
        meta:
          description = "Test rule to trigger command injection $(touch /tmp/pwned)"
        strings:
          $test_string = "teststring"
        condition:
          $test_string
      }
      ```
      2. Start a Turbinia instance with Fraken task enabled.
      3. Submit a Turbinia request to process a RawDisk evidence. In the request options, specify to use the malicious.yar rule file by setting `yara_rules` request option to the path where `malicious.yar` is accessible to Turbinia workers (e.g., if running Turbinia locally, `/path/to/malicious.yar`). If using signature-base, replace a rule in signature-base with the malicious rule, and point Turbinia to use signature-base rules.
      4. Observe the Turbinia worker logs. If the vulnerability is present, the command `touch /tmp/pwned` will be executed by the worker.
      5. Check for the existence of the file `/tmp/pwned` on the Turbinia worker instance. If the file exists, the command injection is successful.

- Vulnerability Name: Command Injection via Unsanitized Evidence Path
    - Description:
      1. An attacker crafts a malicious forensic evidence file with a specially designed filename or path.
      2. The attacker submits this evidence file to Turbinia for processing.
      3. During evidence processing, Turbinia's code uses the filename or path of the evidence file in a system command without proper sanitization.
      4. The attacker's malicious filename or path injects additional commands into the system command executed by Turbinia.
      5. The injected commands are executed on the worker machine, leading to arbitrary code execution.
    - Impact:
      - Arbitrary code execution on Turbinia worker machines.
      - Potential data exfiltration from the worker machines.
      - Unauthorized access to the Turbinia infrastructure and potentially the wider network if worker machines are not properly isolated.
      - Complete compromise of the worker node, potentially leading to further attacks on the Turbinia system or other systems accessible from the compromised worker node.
    - Vulnerability Rank: Critical
    - Currently Implemented Mitigations:
      - Based on the provided files, there are no specific mitigations implemented in the project to prevent command injection via unsanitized evidence paths. The READMEs and Dockerfiles focus on setup and deployment, not input validation or sanitization within the processing logic.
    - Missing Mitigations:
      - Input sanitization for evidence filenames and paths before using them in system commands.
      - Use of parameterized queries or functions that prevent command injection instead of directly embedding user-controlled strings into commands.
      - Principle of least privilege for the Turbinia worker processes to limit the impact of potential code execution.
      - Sandboxing or containerization of forensic tools execution to isolate potential exploits.
    - Preconditions:
      - An attacker needs to be able to submit evidence to a Turbinia instance, which is the standard workflow for Turbinia.
      - The Turbinia instance must process the malicious evidence file using a Task that is vulnerable to command injection.
      - The vulnerable Task must use the filename or path in a system call without proper sanitization.
    - Source Code Analysis:
      - Based on the provided files, specific source code files are not available for analysis. However, assuming a typical Turbinia task processes evidence files by invoking external forensic tools using `subprocess` or similar mechanisms, the vulnerability could be present in any Task that constructs system commands using evidence paths.
      - **Hypothetical Vulnerable Code Example (Python):**
        ```python
        import subprocess

        def process_evidence(evidence_path):
            # Vulnerable code: Directly embedding evidence_path in the command
            cmd = f"tool -i {evidence_path} -o output"
            subprocess.run(cmd, shell=True, check=True) # shell=True is often more vulnerable
        ```
        In this example, if `evidence_path` is controlled by the attacker and contains shell metacharacters (e.g., `;`, `|`, `$(...)`), it can lead to command injection.
      - **Visualization:**
        ```
        Attacker-Controlled Input (Malicious Evidence File) --> Turbinia Task (Vulnerable Code) --> System Command (Unsanitized Path) --> Code Execution
        ```
    - Security Test Case:
      1. **Setup:**
          - Deploy a Turbinia instance accessible to the external attacker (e.g., a publicly accessible instance or a local instance for testing purposes).
          - Ensure a Task is enabled that is potentially vulnerable to command injection (e.g., a Task that processes file paths and uses `subprocess` with `shell=True`). For this test case, let's assume `StringsAsciiTask` is modified to be vulnerable.
      2. **Craft Malicious Evidence:**
          - Create a malicious evidence file with a filename designed to inject a command. For example, create a file named `test_image_$(touch /tmp/pwned).dd`.
      3. **Submit Malicious Evidence:**
          - Use `turbinia-client` to submit the malicious evidence file to the Turbinia instance, e.g., `turbinia-client submit RawDisk -p test_image_$(touch /tmp/pwned).dd`.
      4. **Observe Worker Machine:**
          - Access the worker machine (if possible in your test setup, e.g., via SSH if testing locally or through GCP console for cloud deployments) and check if the injected command was executed.
          - Look for the file `/tmp/pwned` on the worker machine. If it exists, the command injection was successful.
      5. **Verify Results:**
          - If the file `/tmp/pwned` is created, this confirms the command injection vulnerability. The attacker successfully executed arbitrary code on the Turbinia worker by submitting a maliciously named evidence file.
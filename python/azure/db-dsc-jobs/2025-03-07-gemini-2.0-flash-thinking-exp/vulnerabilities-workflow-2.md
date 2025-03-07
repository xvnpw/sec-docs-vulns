## Combined Vulnerability List

### Credential Exposure via Insecure Storage in `params.json`

*   **Vulnerability Name:** Credential Exposure via Insecure Storage in `params.json`
*   **Description:**
    1.  The `params.json` file is designed to store sensitive authentication credentials required for accessing the Databricks workspace. These credentials include `pat_token`, `client_secret`, `private_key_file` (path), and potentially `client_id` depending on the authentication method.
    2.  The application, as designed, reads these credentials directly from the `params.json` file in plaintext when it is executed.
    3.  If the file system where `params.json` is stored has insecure permissions (e.g., world-readable, accessible to unauthorized users or processes), an attacker with read access to the file system can directly read the `params.json` file.
    4.  By reading `params.json`, the attacker can obtain the plaintext credentials such as `pat_token` or `client_secret`.
    5.  The attacker can then use these exfiltrated credentials to authenticate directly to the legitimate Databricks workspace and perform unauthorized actions, bypassing the intended security controls of the application environment.
*   **Impact:**
    -   **Complete Compromise of Databricks Access:** Successful exfiltration of credentials like `pat_token` or `client_secret` grants the attacker full control over the Databricks workspace associated with those credentials, limited only by the permissions of the authenticated identity.
    -   **Data Breach:** Attackers can access sensitive data stored in the Databricks workspace, potentially leading to data breaches and compliance violations.
    -   **Malicious Operations:** Attackers can perform any operations within the Databricks workspace that the compromised credentials allow, including creating/deleting jobs, modifying data, accessing secrets, and potentially escalating privileges if the compromised identity has sufficient permissions.
*   **Vulnerability Rank:** High
*   **Currently Implemented Mitigations:**
    -   None in the code. The application directly reads and uses credentials from `params.json` without any security measures for credential handling or storage within the application itself. The README file provides documentation on how to use different authentication methods and parameter file examples but does not include specific security warnings or mitigations against insecure storage of credentials in `params.json` beyond implicitly suggesting securing the file.
*   **Missing Mitigations:**
    -   **Secure Credential Storage:** The application should not rely on storing sensitive credentials in plaintext JSON files. Implement secure credential management practices:
        -   **Environment Variables:** Encourage or enforce the use of environment variables to pass sensitive credentials to the application at runtime, avoiding storage in files.
        -   **Secure Key Vaults/Credential Managers:** Integrate with secure key vault services (like Azure Key Vault, HashiCorp Vault, or cloud provider secret managers) to store and retrieve credentials securely.
        -   **Operating System Credential Stores:** Utilize operating system-level credential storage mechanisms where appropriate.
    -   **Warning/Error on Insecure Storage:** At the very least, the application should include a prominent warning message, either during startup or in the documentation (beyond the README), explicitly stating the security risks of storing credentials in `params.json` and recommending secure alternatives.
    -   **File Permission Hardening Guidance:** Enhance documentation to include explicit instructions on setting restrictive file permissions for `params.json` (e.g., read/write only for the user running the application) to minimize the risk of unauthorized access.
*   **Preconditions:**
    -   The attacker must have read access to the file system where the `params.json` file is stored. This access could be due to insecure file permissions, vulnerabilities in the system, or insider threats.
*   **Source Code Analysis:**
    1.  **File: `/code/job.py`**:
        ```python
        parser = argparse.ArgumentParser(description='DSC job management for Databricks')
        parser.add_argument('--params', type=str, help='your Databricks and Azure parameter file', default='params.json')
        args = parser.parse_args()

        configuration = json.load(open(args.params))
        auth_token = auth.get_auth_token(configuration)
        ```
        -   The `job.py` script loads the entire `params.json` file content into the `configuration` variable.
        -   It then passes this `configuration` dictionary directly to the `auth.get_auth_token()` function.
    2.  **File: `/code/auth.py`**:
        ```python
        def get_auth_token(paramFile):
            result = None
            auth = paramFile["authority_type"]

            if auth == "msi":
                result = json.loads(requests.get(paramFile["authority"] + "&resource=" + paramFile["resource"] + "&client_id=" + paramFile["client_id"], headers={"Metadata": "true"}).text)

            elif auth == "spn-cert" or auth == "spn-key":
                app = msal.ConfidentialClientApplication(
                    paramFile["client_id"], authority=paramFile["authority"],
                    client_credential=  {"thumbprint": paramFile["thumbprint"], "private_key": open(paramFile['private_key_file']).read()} if auth == "spn-cert" else paramFile["client_secret"]
                )
                result = app.acquire_token_for_client(scopes=[paramFile["resource"] + "/.default"])

            elif auth == "pat":
                result = {'access_token': paramFile["pat_token"]}
            ```
        -   The `auth.py` script's `get_auth_token()` function directly accesses various credential fields from the `paramFile` dictionary (which is derived from `params.json`):
            -   `paramFile["pat_token"]` for Personal Access Token authentication.
            -   `paramFile["client_secret"]` for Service Principal with Key authentication.
            -   `paramFile['private_key_file']` (path to private key file) for Service Principal with Certificate authentication (while not the key itself in `params.json`, the path is still sensitive config).
        -   These sensitive values are directly used for authentication, demonstrating that the application relies on plaintext storage of credentials in `params.json`.
*   **Security Test Case:**
    1.  **Setup:**
        -   Create a `params.json` file containing valid credentials for any of the supported authentication methods (e.g., use `pat` and include a valid `pat_token`).
        -   Set insecure file permissions on `params.json` to make it world-readable (e.g., `chmod 644 params.json` or `chmod a+r params.json` on Linux/macOS, or remove restrictive ACLs on Windows).
    2.  **Simulate Attacker Access:**
        -   As an attacker who has gained read access to the file system (e.g., through a compromised account or system vulnerability, or simply by being a user with access if permissions are too broad), read the contents of the `params.json` file. This can be done using standard file reading commands like `cat params.json` or `type params.json`.
    3.  **Verify Credential Exposure:**
        -   Examine the output of reading `params.json`. Confirm that the sensitive credentials you configured (e.g., `pat_token`, `client_secret`) are clearly visible in plaintext within the JSON file.
    4.  **Attempt Unauthorized Access (using exfiltrated PAT as example):**
        -   Extract the `pat_token` value from the `params.json` file.
        -   Use a tool like `curl` or the Databricks CLI to attempt to authenticate to the Databricks workspace using the exfiltrated `pat_token`. For example:
            ```bash
            curl -X GET -H 'Authorization: Bearer <EXFILTRATED_PAT_TOKEN>' https://<your-databricks-uri>/api/2.0/jobs/list
            ```
        -   Replace `<EXFILTRATED_PAT_TOKEN>` with the actual token from `params.json` and `<your-databricks-uri>` with your Databricks workspace URI.
    5.  **Verification of Unauthorized Access:**
        -   If the `curl` command (or similar) successfully returns a response from the Databricks API (e.g., a JSON list of jobs), it confirms that the exfiltrated credentials are valid and can be used to gain unauthorized access to the Databricks workspace. This demonstrates the vulnerability of credential exposure due to insecure storage in `params.json`.

### Jinja2 Template Injection in Job Definitions

*   **Vulnerability Name:** Jinja2 Template Injection in Job Definitions
*   **Description:**
    1.  The application reads job definitions from JSON files located in the `/jobs/` directory.
    2.  These JSON files contain job parameters, including fields that are intended to be used as values in Databricks job configurations.
    3.  The application uses Jinja2 templating to dynamically generate job definitions based on these JSON files and predefined templates (e.g., `standard.jinja2`).
    4.  The content of the JSON job definition files is directly passed to the Jinja2 `render()` function without any sanitization or input validation.
    5.  An attacker can craft a malicious JSON job definition file and embed Jinja2 template syntax within the job parameter values (e.g., in `notebookpath`, `par_sourcesystem_val`, etc.).
    6.  When the application processes this malicious JSON file, the Jinja2 engine interprets and executes the embedded template syntax.
    7.  This allows the attacker to inject arbitrary Jinja2 code, potentially leading to arbitrary code execution on the server or within the Databricks environment, depending on the accessible Jinja2 functionalities and context.
*   **Impact:**
    -   **High to Critical:** Successful template injection can lead to arbitrary code execution on the server running the `job.py` application.
    -   This could allow an attacker to:
        -   Gain unauthorized access to the Databricks workspace and potentially other connected systems.
        -   Steal sensitive credentials or data, including Databricks access tokens and data within the Databricks environment.
        -   Modify or delete Databricks jobs and configurations.
        -   Pivot to other systems or resources accessible from the server.
        -   Cause denial of service by disrupting job execution or system operations.
    -   The severity depends on the permissions of the account running the `job.py` application and the accessible Jinja2 functionalities. If the application is run with elevated privileges or if Jinja2 environment is not properly sandboxed, the impact can be critical.
*   **Vulnerability Rank:** Critical
*   **Currently Implemented Mitigations:**
    -   None. The code directly loads JSON job definitions and passes them to the Jinja2 template engine without any sanitization or validation.
*   **Missing Mitigations:**
    -   **Input Sanitization and Validation:** Implement strict input validation for all fields read from the JSON job definition files before passing them to the Jinja2 template engine. Sanitize or escape any potentially harmful characters or Jinja2 syntax.
    -   **Jinja2 Sandboxing:** Configure Jinja2 environment with sandboxing options to restrict access to dangerous functions and modules. This can limit the impact of template injection by preventing execution of arbitrary code. Consider using a restricted Jinja2 environment or disabling dangerous extensions.
    -   **Principle of Least Privilege:** Ensure that the application and the account running it have only the necessary permissions to perform job management tasks in Databricks. Avoid running the application with highly privileged accounts.
    -   **Secure File Handling:** While not directly related to template injection, ensure secure file handling practices for reading JSON job definition files and Jinja2 templates to prevent other file-based vulnerabilities.
    -   **Regular Security Audits and Penetration Testing:** Conduct regular security audits and penetration testing to identify and address potential vulnerabilities in the application and its configuration.
*   **Preconditions:**
    -   The attacker needs to be able to create or modify JSON job definition files in the `/jobs/` directory that the application processes. In a real-world scenario, this could be achieved if:
        -   The attacker has write access to the file system where the application is deployed.
        -   The application retrieves job definitions from an external, attacker-controlled source (although this is not evident in the provided code, it's a potential risk if the application's functionality is extended).
        -   There is another vulnerability that allows file manipulation or injection.
    -   For the provided code, the most realistic precondition is that an attacker could replace or add a malicious JSON file in the `jobs` directory if they can gain access to the system where this application is run.
*   **Source Code Analysis:**
    1.  **Job Definition Loading:**
        -   The `main()` function in `job.py` reads job definitions from JSON files in the `/jobs/` directory:
            ```python
            target_jobs = [json.load(open(jobcfg)) for jobcfg in os.scandir('jobs') if(jobcfg.is_file() and jobcfg.path.endswith('.json'))]
            ```
        -   This line iterates through files in the `jobs` directory, filters for `.json` files, and loads each file's content using `json.load()`. The loaded JSON data becomes the `target_jobs` list.

    2.  **Template Rendering:**
        -   The code then iterates through `target_jobs` and renders the `standard.jinja2` template for each job definition:
            ```python
            template = tplenv.get_template('standard.jinja2')
            for x in target_jobs:
                task = template.render(job=x)
                result = post_db("jobs/create", task).json()
                log("Created a new job %s" % result['job_id'])
            ```
        -   `tplenv.get_template('standard.jinja2')` retrieves the Jinja2 template.
        -   `template.render(job=x)` renders the template, passing each job definition `x` (from the JSON file) as the `job` variable in the template context.
        -   **Vulnerable Point:** The content of `x` (which comes directly from the attacker-controlled JSON file) is directly embedded into the Jinja2 template rendering process without any sanitization.

    3.  **Jinja2 Template Example (Hypothetical `standard.jinja2` based on `README.md`):**
        ```jinja
        {
          "name": "{{ job.name }}",
          "notebook_task": {
            "notebook_path": "{{ job.notebookpath }}",
            "base_parameters": {
              "sourcesystem": "{{ job.par_sourcesystem_val }}",
              "configfilepath": "{{ job.par_configfilepath_val }}"
            }
          }
        }
        ```
        -   In this example template, `{{ job.name }}`, `{{ job.notebookpath }}`, `{{ job.par_sourcesystem_val }}`, `{{ job.par_configfilepath_val }}` and other `job.*` fields are populated directly from the `x` dictionary (JSON data). If an attacker includes Jinja2 code within the values of these fields in the JSON file, it will be executed during rendering.

*   **Security Test Case:**
    1.  **Create a malicious JSON job definition file named `exploit_job.json` in the `/jobs/` directory with the following content:**
        ```json
        {
          "name": "Exploit Job",
          "notebookpath": "/Users/attacker@example.com/ExploitNotebook",
          "par_exploit": "{{ request.application.import_module('os').popen('touch /tmp/jinja2_pwned').read() }}",
          "par_exploit_val": "dummy_value"
        }
        ```
        -   **Explanation:** This JSON file defines a job named "Exploit Job". The crucial part is the `par_exploit` field, which contains a Jinja2 payload: `{{ request.application.import_module('os').popen('touch /tmp/jinja2_pwned').read() }}`. This payload attempts to use the `os.popen()` function to execute the command `touch /tmp/jinja2_pwned` on the system where `job.py` is running.  We use `touch` command as a safe way to demonstrate code execution. In a real attack, more harmful commands could be used.

    2.  **Ensure the `jobs` directory exists in the same directory as `job.py`.** If it doesn't, create it: `mkdir jobs`.

    3.  **Run the `job.py` script:**
        ```bash
        python job.py --params params.json
        ```
        -   Make sure you have a valid `params.json` file configured for your Databricks environment (even if the Databricks interaction fails due to invalid credentials, the local template injection vulnerability can still be triggered).

    4.  **Check for successful exploitation:**
        -   After running the script, check if the file `/tmp/jinja2_pwned` has been created on the system where `job.py` was executed.
        -   If the file `/tmp/jinja2_pwned` exists, it confirms that the Jinja2 template injection was successful and arbitrary code execution was achieved.

    **Expected Result:**
    -   The file `/tmp/jinja2_pwned` should be created, indicating successful execution of the injected Jinja2 payload and demonstrating the template injection vulnerability.
    -   The script output might also show errors related to Databricks API if the `params.json` is not correctly configured, but the local code execution through Jinja2 template injection should still occur.
## Combined Vulnerability List

### Unprotected HTTP Endpoint for API Enablement

- **Vulnerability Name:** Unprotected HTTP Endpoint for API Enablement
- **Description:**
    - The project includes an HTTP-triggered Cloud Function (`apiEnablerHttp`) that, if enabled, can be invoked via a public URL.
    - This function is designed to enable a predefined list of Google Cloud APIs for either all projects in the organization or a specific project.
    - An attacker who discovers this function's URL can trigger it without any authentication or authorization checks.
    - By sending a GET request to the function's URL, the attacker can enable the configured APIs.
    - If no `project_number` parameter is provided in the request, the function will enable APIs for all active projects in the organization.
    - If a `project_number` parameter is provided, the function will enable APIs for the specified project.
    - Steps to trigger the vulnerability:
        1. Enable the `apiEnablerHttp` function in `serverless.yml` by uncommenting the relevant lines.
        2. Deploy the Cloud Function using `serverless deploy -v`.
        3. Obtain the deployed function's HTTP endpoint URL from the Google Cloud Console or Serverless deployment output.
        4. Send an HTTP GET request to the function's URL. For example, using `curl <function_url>`. This will enable APIs for all projects in the organization.
        5. To target a specific project, send a GET request to the function's URL with the `project_number` parameter. For example, `curl "<function_url>?project_number=victim-project-123"`.
- **Impact:**
    - **Unauthorized API Enablement:** An attacker can enable Google Cloud APIs in the organization's projects without proper authorization.
    - **Resource Consumption and Billing Implications:** Enabling APIs can lead to the consumption of Google Cloud resources and unexpected charges to the organization's billing account, especially if compute or storage related APIs are enabled and utilized.
    - **Security Policy Violation:**  Enabling APIs without proper authorization can violate the organization's security policies and compliance requirements.
    - **Potential Data Exposure (depending on enabled APIs):** If APIs like Compute Engine or Cloud Storage are enabled, and the attacker gains further access, it could potentially lead to data exposure or unauthorized access to resources in the affected projects.
    - **Operational Disruption:** Unintended enabling of certain APIs could disrupt the intended project configuration or create conflicts with existing services.
    - **Compliance Issues:** Enabling APIs without proper authorization and auditing can lead to compliance violations, especially in regulated industries.
- **Vulnerability Rank:** High
- **Currently Implemented Mitigations:**
    - **Default Configuration:** The `apiEnablerHttp` function is commented out in the `serverless.yml` file by default. This means it is not deployed unless explicitly enabled by the user, acting as a primary mitigation. This is documented in `serverless.yml` comments: `# apiEnablerHttp: # This function will not be deployed by default since it gets publicly available. Deploy it on your own risk`.
- **Missing Mitigations:**
    - **Authentication and Authorization:** The `apiEnablerHttp` function lacks any form of authentication or authorization. Implementing authentication (e.g., requiring an API key or OAuth 2.0 token, or using Identity-Aware Proxy) and authorization (e.g., checking if the requester has the necessary permissions to enable APIs) is crucial if this endpoint is to be exposed.
    - **Rate Limiting:** Implementing rate limiting could help mitigate potential abuse by limiting the number of requests from a single source within a given timeframe.
    - **Input Validation:** While the code checks for the `project_number` parameter, it doesn't validate the format or if the user is authorized to enable APIs for that project. Input validation and authorization checks are missing.
- **Preconditions:**
    - The attacker needs to know or discover the HTTP endpoint URL of the deployed Cloud Function (if `apiEnablerHttp` is enabled).
    - The `apiEnablerHttp` function must be enabled in `serverless.yml` and deployed.
    - The Cloud Function's HTTP endpoint must be accessible from the public internet.
- **Source Code Analysis:**
    - **`main.py:api_enabler_http(request)`**
        ```python
        def api_enabler_http(request):
            """Gets triggered by simple HTTP GET request.
            :param request: flask.Request
            :return: Response
            """
            project_number = request.args.get("project_number")

            response_data = initial_response_data()

            credentials = get_credentials() # Gets application default credentials, function runs with service account PROJECT_ID@appspot.gserviceaccount.com

            if project_number:
                response_data["enabledServices"][project_number] = enable_services(
                    credentials=credentials, project_number=project_number
                )

                return json.dumps(response_data, indent=4) # Returns JSON response with enabled services for specific project

            projects = get_projects(credentials) # Gets all projects in the organization

            for project in projects:
                if project["lifecycleState"] != PROJECT_ACTIVE:
                    continue
                project_number = project["projectNumber"]
                response_data["enabledServices"][project_number] = enable_services(
                    credentials=credentials, project_number=project_number
                )

            return json.dumps(response_data, indent=4) # Returns JSON response with enabled services for all projects
        ```
        - The `api_enabler_http` function is directly accessible if deployed and triggered by HTTP GET requests.
        - It retrieves the `project_number` from the request's GET parameters, making it attacker-controlled input.
        - If `project_number` is provided, it calls `enable_services` for that specific project.
        - If `project_number` is not provided, it iterates through all projects in the organization (obtained by `get_projects`) and calls `enable_services` for each active project.
        - **Crucially, there are no checks within `api_enabler_http` to verify the identity or authorization of the caller.** Anyone who can access the function's URL can trigger this logic.
        - The function operates with the permissions of the Cloud Function's service account, which is granted the `editor` role at the organization level. This means the function, and by extension, an unauthenticated attacker invoking it, has broad permissions to enable services across the organization.

- **Security Test Case:**
    1. **Prerequisites:**
        - Ensure `apiEnablerHttp` is enabled in `serverless.yml` by uncommenting it.
        - Deploy the Cloud Function using `serverless deploy -v`.
        - Obtain the deployed function's HTTP endpoint URL (e.g., from Google Cloud Console -> Cloud Functions -> `apiEnablerHttp` -> Trigger).
        - Have a GCP organization and project where you can observe API enablement.
    2. **Steps:**
        - Open a terminal or use a tool like `curl` or a web browser.
        - Send a GET request to the obtained function URL without any parameters. For example:
          ```bash
          curl <function_url>
          ```
        - Alternatively, send a GET request to the function URL with a specific `project_number` parameter, replacing `victim-project-123` with a valid project number in your organization:
          ```bash
          curl "<function_url>?project_number=victim-project-123"
          ```
    3. **Expected Result:**
        - After sending the request, the function should execute.
        - If the request was without `project_number`, the function will attempt to enable the configured APIs in *all* projects within the organization.
        - If the request included `project_number`, the function will attempt to enable the configured APIs in the specified project.
        - You can verify the API enablement status in the Google Cloud Console for the targeted projects (APIs & Services -> Enabled APIs & services). You should see the APIs listed in the `SERVICES_TO_ENABLE` environment variable being enabled if they were not already.
    4. **Pass/Fail:**
        - **Pass:** If the APIs are successfully enabled in the targeted projects (either all or the specified project) after sending the unauthenticated HTTP request, the test case passes, confirming the vulnerability.

### Insecure Configuration of Services to Enable List

- **Vulnerability Name:** Insecure Configuration of Services to Enable List
- **Description:**
    - The list of Google Cloud APIs to be automatically enabled for new projects is stored as an environment variable named `SERVICES_TO_ENABLE`.
    - This configuration is defined in the `.env` file and deployed with the Cloud Function.
    - An attacker who gains unauthorized access to the Cloud Function's environment configuration can modify this environment variable to include additional, potentially malicious, services.
    - This unauthorized access could be achieved through compromised GCP credentials, misconfigured IAM permissions, or vulnerabilities in the deployment pipeline.
    - When the Cloud Function is triggered (either by new GCP project creation via Pub/Sub or by direct HTTP call if `apiEnablerHttp` is enabled), it reads the `SERVICES_TO_ENABLE` environment variable.
    - The function then enables all services listed in the (potentially attacker-modified) `SERVICES_TO_ENABLE` environment variable in the target GCP projects.
    - Steps to trigger the vulnerability:
        1. An attacker compromises the Google Cloud Function's service account or gains access to the GCP project with sufficient permissions to modify Cloud Function configurations.
        2. The attacker accesses the Cloud Function's configuration, for example, using the Google Cloud Console or gcloud SDK.
        3. The attacker modifies the `SERVICES_TO_ENABLE` environment variable associated with the Cloud Function, adding or replacing service names with APIs they want to enable.
        4. A new Google Cloud Project is created within the organization, triggering the Cloud Function via the configured Pub/Sub topic. Alternatively, the attacker could trigger the HTTP endpoint if enabled.
        5. The Cloud Function executes, reads the modified `SERVICES_TO_ENABLE` environment variable, and enables all services listed, including the attacker-added ones, in the newly created project (or all projects if HTTP endpoint is used without `project_number`).
- **Impact:**
    - **Unauthorized API Enablement:** An attacker can force the Cloud Function to enable arbitrary Google Cloud APIs in newly created projects across the entire GCP organization or in targeted projects.
    - **Privilege Escalation:** Enabling IAM API (`iam.googleapis.com`) could allow the attacker to manipulate project permissions and escalate their privileges within the affected projects or even the organization.
    - **Data Exfiltration:** Enabling Storage API (`storage.googleapis.com`) or Compute API (`compute.googleapis.com`) in projects where sensitive data might be stored could facilitate data exfiltration.
    - **Resource Abuse:** Enabling Compute API (`compute.googleapis.com`) or other resource-intensive APIs could allow the attacker to deploy and run malicious workloads (e.g., cryptocurrency mining) at the organization's expense.
    - **Unexpected Financial Costs:** Unintended Google Cloud APIs are enabled across the organization's projects, leading to unexpected financial costs due to the usage of the enabled services, especially if costly services like compute or storage are enabled.
    - **Security Policy Violation and Compliance Issues:** Enabling unintended services might violate security policies or compliance regulations.
    - **Operational Disruption:** Unintended enabling of certain APIs could disrupt the intended project configuration or create conflicts with existing services. Administrators would need to manually disable the unintended services and potentially clean up any resources created by them.
- **Vulnerability Rank:** High
- **Currently Implemented Mitigations:**
    - None in the code itself to prevent modification of the `SERVICES_TO_ENABLE` environment variable.
    - The README.md mentions that the HTTP triggered function (`apiEnablerHttp`) is commented out in `serverless.yml` and not deployed by default "because of security reasons". This reduces the attack surface of direct public triggering but does not mitigate the risk of environment variable modification.
- **Missing Mitigations:**
    - **Externalize Configuration Storage:** Instead of relying on environment variables, store the list of services to enable in a more secure and auditable configuration management system. Options include Google Cloud Storage, Google Secret Manager, or Firestore/Datastore with restricted access and audit logs.
    - **Input Validation:** Implement validation on the `SERVICES_TO_ENABLE` environment variable within the Cloud Function code. This could involve whitelisting allowed services and format validation.
    - **Secure Environment Variable Management:** Employ secure methods for storing and managing environment variables, including the principle of least privilege for access and potentially encryption.
    - **Access Control and Auditing:** Implement strong IAM policies to control who can modify Cloud Function configurations and enable audit logs for configuration changes.
    - **Principle of Least Privilege for Service Account:** Minimize the permissions granted to the Cloud Function's service account. Instead of the Editor role, use a custom IAM role with only the necessary permissions (e.g., `serviceusage.services.enable` on organization level).
    - **Regular Configuration Review:** Periodically review the configured `SERVICES_TO_ENABLE` environment variable and compare it against the intended list of services to ensure no unauthorized modifications have been made.
- **Preconditions:**
    - An attacker must gain unauthorized access to the environment where the Cloud Function's configuration, specifically the `SERVICES_TO_ENABLE` environment variable, is stored. This could be through compromised service account, GCP credentials or IAM misconfigurations.
    - The Cloud Function must be deployed and configured to use the `SERVICES_TO_ENABLE` environment variable to determine which APIs to enable.
- **Source Code Analysis:**
    - **`main.py:get_services_to_enable()` function:**
    ```python
    def get_services_to_enable():
        """Loads services from environment.
        :return: dict
        """
        services_to_enable = {}

        services_to_enable_raw = os.environ["SERVICES_TO_ENABLE"] # [POINT OF VULNERABILITY] - Directly reads environment variable

        for service in services_to_enable_raw.split(","):
            services_to_enable[service] = True

        return services_to_enable
    ```
    - This function directly retrieves the value of the `SERVICES_TO_ENABLE` environment variable using `os.environ["SERVICES_TO_ENABLE"]`.
    - **No input validation or sanitization is performed** on the value read from the environment variable.
    - The function splits the string by commas and creates a dictionary where keys are service names.

    - **`main.py:enable_services()` function:**
    ```python
    def enable_services(credentials, project_number):
        """Will enable services for given project number.
        ...
        """
        enabled_services = []

        services_to_enable = get_services_to_enable() # Calls the vulnerable function

        project_name = "projects/" + project_number

        services = get_enabled_services(credentials=credentials, project_name=project_name)

        for service in services:
            service_name = service["config"]["name"]

            if service_name in services_to_enable:
                services_to_enable[service_name] = False # Mark existing services as already enabled

        for service_name, should_enable in services_to_enable.items():
            if should_enable:
                service_long_name = project_name + "/services/" + service_name
                enable_service(credentials=credentials, service_name=service_long_name) # Enables services based on the potentially modified list
                enabled_services.append(service_long_name)

        return enabled_services
    ```
    - This function calls `get_services_to_enable()` to get the list of services to enable.
    - It iterates through the services from the environment variable and calls `enable_service()` for each service that is not already enabled.
    - **The vulnerability is that the list of services to enable is entirely controlled by the `SERVICES_TO_ENABLE` environment variable without any checks or restrictions within the code.**

- **Security Test Case:**
    1. **Pre-requisite:** Deploy the Cloud Function to a GCP project as described in the README.md, ensuring the Pub/Sub trigger is set up. You need to have permissions to modify the Cloud Function's environment variables in the GCP console or through gcloud SDK.
    2. **Access Cloud Function Configuration:** In the GCP Console, navigate to Cloud Functions and select the deployed `apiEnablerListener` function.
    3. **Modify Environment Variables:** Go to the "Configuration" tab and then "Runtime, build, connections and security settings". Under "Runtime environment variables", locate the `SERVICES_TO_ENABLE` variable.
    4. **Inject Malicious Service:** Modify the value of `SERVICES_TO_ENABLE` to include a service that is not intended to be enabled by default. For example, append `,compute.googleapis.com` to the existing list.
    5. **Save Changes:** Save the updated Cloud Function configuration. This will deploy a new version of the function with the modified environment variable.
    6. **Trigger the Function:** Create a new GCP project within the organization that is configured to trigger the Pub/Sub topic linked to the Cloud Function.
    7. **Verify Enabled Services:** After the Cloud Function execution, navigate to the newly created project in the GCP Console. Go to "APIs & Services" -> "Enabled APIs & Services".
    8. **Observe Unintended Service Enabled:** Check if the `compute.googleapis.com` (or whichever malicious service you added) is now enabled in the project. If it is, this confirms the vulnerability.
    9. **Clean up (Important):** Disable the `compute.googleapis.com` service in the test project to avoid unexpected charges. Revert the `SERVICES_TO_ENABLE` environment variable in the Cloud Function back to its original intended value.
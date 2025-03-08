### Vulnerability List

- **Vulnerability Name:** Unprotected HTTP Endpoint for API Enablement (if enabled)
- **Description:**
    - The project includes an HTTP-triggered Cloud Function (`apiEnablerHttp`) that, if enabled, can be invoked via a public URL.
    - This function is designed to enable a predefined list of Google Cloud APIs.
    - An attacker who gains access to this function's URL can trigger it without authentication or authorization checks by default.
    - By sending a GET request to the function's URL, the attacker can enable the configured APIs for either all projects in the organization or a specific project if they provide the `project_number` parameter in the request.
    - Steps to trigger the vulnerability:
        1. Enable the `apiEnablerHttp` function in `serverless.yml` by uncommenting the relevant lines.
        2. Deploy the Cloud Function using `serverless deploy -v`.
        3. Obtain the deployed function's HTTP endpoint URL from the Google Cloud Console or Serverless deployment output.
        4. Send an HTTP GET request to the function's URL. For example, using `curl <function_url>`. This will enable APIs for all projects in the organization.
        5. To target a specific project, send a GET request to the function's URL with the `project_number` parameter. For example, `curl "<function_url>?project_number=victim-project-123"`.

- **Impact:**
    - **Unauthorized API Enablement:** An attacker can enable Google Cloud APIs in the organization's projects without proper authorization.
    - **Resource Consumption and Billing Implications:** Enabling APIs can lead to the consumption of Google Cloud resources and unexpected charges to the organization's billing account, especially if compute or storage related APIs are enabled and used by the attacker.
    - **Security Policy Violation:**  Enabling APIs without proper authorization can violate the organization's security policies and compliance requirements.
    - **Potential Data Exposure (depending on enabled APIs):** If APIs like Compute Engine or Cloud Storage are enabled, and the attacker gains further access, it could potentially lead to data exposure or unauthorized access to resources in the affected projects.

- **Vulnerability Rank:** High
- **Currently Implemented Mitigations:**
    - **Default Configuration:** The `apiEnablerHttp` function is commented out in the `serverless.yml` file by default. This means it is not deployed unless explicitly enabled by the user, which acts as a primary mitigation. This is described in `serverless.yml` comments: `# apiEnablerHttp: # This function will not be deployed by default since it gets publicly available. Deploy it on your own risk`.
- **Missing Mitigations:**
    - **Authentication and Authorization:** The `apiEnablerHttp` function lacks any form of authentication or authorization. Implementing authentication (e.g., requiring an API key or OAuth 2.0 token) and authorization (e.g., checking if the requester has the necessary permissions to enable APIs) is crucial if this endpoint is to be exposed.
    - **Rate Limiting:** Implementing rate limiting could help mitigate potential abuse by limiting the number of requests from a single source within a given timeframe.
    - **Input Validation:** While the code does check for `project_number` parameter, it doesn't validate the format or if the user is authorized to enable APIs for that project. Input validation and authorization checks are missing.
- **Preconditions:**
    - The attacker needs to know or discover the HTTP endpoint URL of the deployed Cloud Function (if `apiEnablerHttp` is enabled).
    - The `apiEnablerHttp` function must be enabled in `serverless.yml` and deployed.
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
        - The `api_enabler_http` function is directly accessible if deployed.
        - It retrieves the `project_number` from the request's GET parameters.
        - If `project_number` is provided, it calls `enable_services` for that specific project.
        - If `project_number` is not provided, it iterates through all projects in the organization (obtained by `get_projects`) and calls `enable_services` for each active project.
        - **Crucially, there are no checks within `api_enabler_http` to verify the identity or authorization of the caller.** Anyone who can access the function's URL can trigger this logic.
        - The function operates with the permissions of the Cloud Function's service account (`PROJECT_ID@appspot.gserviceaccount.com`), which is granted the `editor` role at the organization level as per the README. This means the function, and by extension, an unauthenticated attacker invoking it, has broad permissions to enable services across the organization.

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
        - **Fail:** If the APIs are not enabled (which is unlikely given the code and default permissions), or if the HTTP endpoint is not accessible, the test case fails. However, based on the code analysis, successful API enablement is expected, indicating a vulnerability.
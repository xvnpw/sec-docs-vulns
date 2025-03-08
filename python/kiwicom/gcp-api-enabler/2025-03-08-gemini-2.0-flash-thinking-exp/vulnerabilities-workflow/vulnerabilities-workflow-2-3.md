### Vulnerability List

- Vulnerability Name: Unauthorized API Enabling via Publicly Exposed HTTP GET Handler

- Description:
  - The `api_enabler_http` function is designed to enable Google Cloud APIs for projects.
  - This function can be triggered by sending an HTTP GET request to the Cloud Function's endpoint.
  - If deployed with the HTTP GET handler enabled (by uncommenting the `apiEnablerHttp` function in `serverless.yml`) and without any authorization mechanism, the function becomes publicly accessible.
  - An attacker can discover the Cloud Function's HTTP endpoint.
  - By sending a GET request to this endpoint, the attacker can trigger the `api_enabler_http` function.
  - Without any `project_number` parameter in the GET request, the function iterates through all projects in the organization and enables the APIs specified in the `SERVICES_TO_ENABLE` environment variable for each active project.
  - Alternatively, the attacker can provide a `project_number` as a GET parameter (e.g., `?project_number=PROJECT_ID`) to target a specific project for API enabling.
  - Since there are no authorization checks in the `api_enabler_http` function, any unauthenticated user can trigger this action.

- Impact:
  - **Unexpected Resource Consumption:** Enabling APIs can lead to the creation of default resources (like default Compute Engine network, service accounts, etc.) and potentially incur costs for the project owner, even if they did not intend to use those APIs.
  - **Unauthorized Access and Data Exposure:** If sensitive APIs (like Cloud Storage, Cloud SQL, etc.) are enabled, it could open up avenues for further attacks and potential data breaches, especially if these APIs are misconfigured or used insecurely after being enabled.
  - **Operational Disruption:** Unintended enabling of certain APIs could disrupt the intended project configuration or create conflicts with existing services.
  - **Compliance Issues:** Enabling APIs without proper authorization and auditing can lead to compliance violations, especially in regulated industries.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
  - **Default Configuration Disables HTTP Handler:** The `serverless.yml` file by default comments out the `apiEnablerHttp` function, meaning it is not deployed unless explicitly enabled by the user. This is mentioned in the README.md as a security measure.
  - Location: `/code/serverless.yml` (commented out `apiEnablerHttp` function) and `/code/README.md` (security warning about HTTP handler).

- Missing Mitigations:
  - **Authorization Mechanism:** The `api_enabler_http` function lacks any form of authorization. Implementing an authentication and authorization mechanism is crucial. This could be:
    - **API Key:** Require a secret API key to be passed in the request header or as a query parameter.
    - **Identity-Aware Proxy (IAP):** Integrate Google Cloud IAP to control access to the Cloud Function, allowing only authenticated users or service accounts to trigger it.
    - **Function Authentication:** Utilize Cloud Function's built-in authentication to restrict access to specific identities.

- Preconditions:
  - **HTTP GET Handler Enabled:** The `apiEnablerHttp` function must be uncommented and deployed in `serverless.yml`.
  - **Public Network Access:** The Cloud Function's HTTP endpoint must be accessible from the public internet.

- Source Code Analysis:
  - 1. **Entry Point:** The vulnerability is located in the `api_enabler_http` function in `/code/main.py`. This function is intended to be triggered by an HTTP GET request, as defined in the commented-out section of `/code/serverless.yml`.
  - 2. **Parameter Extraction:** The function starts by attempting to retrieve the `project_number` from the request arguments: `project_number = request.args.get("project_number")`.
  - 3. **Conditional Logic - Specific Project:** If `project_number` is provided, the code proceeds to enable services only for that specific project using `enable_services(credentials=credentials, project_number=project_number)`.
  - 4. **Conditional Logic - All Projects:** If `project_number` is *not* provided, the code retrieves all projects in the organization using `get_projects(credentials)`.
  - 5. **Iterating Through Projects:** It then iterates through each project obtained from `get_projects(credentials)`.
  - 6. **Active Project Check:** Inside the loop, it checks if the project is active: `if project["lifecycleState"] != PROJECT_ACTIVE: continue`. Only active projects are processed.
  - 7. **Enabling Services for Each Project:** For each active project, it extracts the `projectNumber` and calls `enable_services(credentials=credentials, project_number=project_number)` to enable the configured services.
  - 8. **No Authorization Checks:** At no point in the `api_enabler_http` function is there any code to verify the identity or authorization of the requester. The function directly proceeds to fetch project lists and enable APIs based solely on the presence or absence of the `project_number` parameter in the HTTP GET request.
  - 9. **Return Response:** Finally, the function returns a JSON response indicating the enabled services.

  ```python
  def api_enabler_http(request): # Vulnerable function - no authorization
      project_number = request.args.get("project_number") # Get project_number from request, attacker controlled

      response_data = initial_response_data()
      credentials = get_credentials()

      if project_number: # If project_number is provided by attacker
          response_data["enabledServices"][project_number] = enable_services( # Enable services for specific project
              credentials=credentials, project_number=project_number
          )
          return json.dumps(response_data, indent=4)

      projects = get_projects(credentials) # Get ALL projects in organization
      for project in projects: # Iterate through all projects
          if project["lifecycleState"] != PROJECT_ACTIVE:
              continue
          project_number = project["projectNumber"]
          response_data["enabledServices"][project_number] = enable_services( # Enable services for ALL active projects
              credentials=credentials, project_number=project_number
          )
      return json.dumps(response_data, indent=4)
  ```

- Security Test Case:
  - 1. **Prerequisites:**
    - Deploy the Cloud Function with the HTTP GET handler enabled. To do this, uncomment the `apiEnablerHttp` section in `/code/serverless.yml` and run `serverless deploy -v`.
    - Ensure the Cloud Function is publicly accessible (default setting for HTTP triggered Cloud Functions).
    - Have a Google Cloud Organization with at least one project (besides the project where the Cloud Function is deployed).
    - Know the HTTP endpoint of the deployed Cloud Function. This can be found in the Google Cloud Console after deployment or in the deployment logs.

  - 2. **Test Steps (Unauthorized API Enablement for All Projects):**
    - Open a web browser or use a tool like `curl`.
    - Access the Cloud Function's HTTP endpoint via a GET request without any parameters. For example: `https://<REGION>-<PROJECT_ID>.cloudfunctions.net/apiEnablerHttp`
    - Observe the response. It should be a JSON object listing projects and the APIs enabled for each project.
    - Go to the Google Cloud Console for a different project in the same organization (one that was not intended to have these APIs enabled).
    - Navigate to "APIs & Services" -> "Enabled APIs & Services".
    - Verify that the APIs listed in the `SERVICES_TO_ENABLE` environment variable are now enabled for this project, even though you did not intend to enable them.

  - 3. **Test Steps (Unauthorized API Enablement for Specific Project):**
    - Obtain the `project_number` of a specific Google Cloud project within the organization.
    - Open a web browser or use `curl`.
    - Access the Cloud Function's HTTP endpoint via a GET request, providing the `project_number` as a query parameter. For example: `https://<REGION>-<PROJECT_ID>.cloudfunctions.net/apiEnablerHttp?project_number=<TARGET_PROJECT_NUMBER>`
    - Observe the response. It should be a JSON object showing APIs enabled for the specified project number.
    - Go to the Google Cloud Console for the project with the `<TARGET_PROJECT_NUMBER>`.
    - Navigate to "APIs & Services" -> "Enabled APIs & Services".
    - Verify that the APIs listed in the `SERVICES_TO_ENABLE` environment variable are now enabled for this specific project.

  - 4. **Expected Result:**
    - In both test cases, the specified APIs should be enabled in the targeted Google Cloud projects without any authentication or authorization from the attacker, confirming the vulnerability.
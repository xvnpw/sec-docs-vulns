### Vulnerability List

- Vulnerability Name: Unauthorised API Enabling via `SERVICES_TO_ENABLE` Modification

- Description:
  1. The Google Cloud Function reads the list of services to enable from the `SERVICES_TO_ENABLE` environment variable.
  2. An attacker gains unauthorized access to the environment configuration where this variable is stored. This could be through compromised GCP credentials, misconfigured IAM permissions, or vulnerabilities in the deployment pipeline.
  3. The attacker modifies the `SERVICES_TO_ENABLE` environment variable, adding or replacing service names with APIs they want to enable in the organization's projects. These could be costly services to increase billing, or malicious services to compromise security.
  4. When a new GCP project is created within the organization, or when the HTTP triggered function (if enabled) is called, the Cloud Function executes.
  5. The function reads the modified `SERVICES_TO_ENABLE` variable and proceeds to enable the attacker-specified services in the new (or all) GCP projects.

- Impact:
  - Unintended Google Cloud APIs are enabled across the organization's projects.
  - This can lead to unexpected financial costs due to the usage of the enabled services, especially if costly services like compute or storage are enabled.
  - Enabling malicious or less secure services could introduce security vulnerabilities or compliance issues within the organization's GCP environment.
  - Operational disruption as administrators need to manually disable the unintended services and potentially clean up any resources created by them.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
  - None in the code itself to prevent modification of the `SERVICES_TO_ENABLE` environment variable.
  - The README.md mentions that the HTTP triggered function (`apiEnablerHttp`) is commented out in `serverless.yml` and not deployed by default "because of security reasons". This reduces the attack surface by not exposing a publicly accessible endpoint that could trigger the function and potentially amplify the impact if the `SERVICES_TO_ENABLE` is compromised. However, the Pub/Sub triggered function `apiEnablerListener` is still active and vulnerable if the environment variable is modified.

- Missing Mitigations:
  - **Input Validation:** Implement validation on the `SERVICES_TO_ENABLE` environment variable within the Cloud Function code. This could involve:
    - Whitelisting: Define an allowed list of services that can be enabled. The function should only enable services present in this whitelist, ignoring any others even if they are in the `SERVICES_TO_ENABLE` variable.
    - Format Validation: Check if the `SERVICES_TO_ENABLE` variable adheres to an expected format (e.g., comma-separated list of valid service names).
  - **Secure Environment Variable Management:** Employ secure methods for storing and managing environment variables.
    - Principle of Least Privilege: Restrict access to modify environment variables to only authorized personnel or automated systems.
    - Environment Variable Encryption: If the platform allows, encrypt environment variables at rest.
  - **Access Control and Auditing:**
    - IAM Policies: Implement strong IAM policies to control who can modify Cloud Function configurations, including environment variables, both at the project and organization level.
    - Audit Logging: Enable audit logs for Cloud Function configuration changes to track who modified the `SERVICES_TO_ENABLE` variable and when.
  - **Regular Configuration Review:** Periodically review the configured `SERVICES_TO_ENABLE` environment variable and compare it against the intended list of services to ensure no unauthorized modifications have been made.

- Preconditions:
  - An attacker must gain unauthorized access to the environment where the Cloud Function's configuration, specifically the `SERVICES_TO_ENABLE` environment variable, is stored. This could be:
    - Access to the GCP project via compromised credentials or IAM misconfigurations.
    - Access to the deployment pipeline configuration (e.g., CI/CD system) if environment variables are managed there.
    - Direct access to the Cloud Function's environment variables via the GCP Console if permissions are mismanaged.
  - The attacker needs to know the names of Google Cloud APIs to enable. This information is publicly available in Google Cloud documentation.

- Source Code Analysis:
  - **`main.py` - `get_services_to_enable()` function:**
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

  - **`main.py` - `enable_services()` function:**
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

- Security Test Case:
  1. **Pre-requisite:** Deploy the Cloud Function to a GCP project as described in the README.md, ensuring the Pub/Sub trigger is set up. You need to have permissions to modify the Cloud Function's environment variables in the GCP console or through gcloud SDK.
  2. **Access Cloud Function Configuration:** In the GCP Console, navigate to Cloud Functions and select the deployed `apiEnablerListener` function.
  3. **Modify Environment Variables:** Go to the "Configuration" tab and then "Runtime, build, connections and security settings". Under "Runtime environment variables", locate the `SERVICES_TO_ENABLE` variable.
  4. **Inject Malicious Service:** Modify the value of `SERVICES_TO_ENABLE` to include a service that is not intended to be enabled by default. For example, append `,compute.googleapis.com` to the existing list (or replace the entire list with just `compute.googleapis.com` for easier observation). `compute.googleapis.com` is used here as an example of a potentially costly service.
  5. **Save Changes:** Save the updated Cloud Function configuration. This will deploy a new version of the function with the modified environment variable.
  6. **Trigger the Function:** Create a new GCP project within the organization that is configured to trigger the Pub/Sub topic linked to the Cloud Function. Alternatively, if you want to test faster without creating a new project, you can manually trigger the `apiEnablerListener` function from the "Testing" tab in the GCP console. For Pub/Sub trigger, ensure a new project creation event is sent to the configured topic. For manual testing, send a JSON payload like `{"project_number": "your-test-project-number"}`.
  7. **Verify Enabled Services:** After the Cloud Function execution (it might take a few minutes), navigate to the newly created project (or the test project used in manual testing) in the GCP Console. Go to "APIs & Services" -> "Enabled APIs & Services".
  8. **Observe Unintended Service Enabled:** Check if the `compute.googleapis.com` (or whichever malicious service you added) is now enabled in the project. If it is, this confirms the vulnerability: an attacker modifying the `SERVICES_TO_ENABLE` environment variable can force the function to enable unintended APIs.
  9. **Clean up (Important):** Disable the `compute.googleapis.com` service in the test project to avoid unexpected charges. Revert the `SERVICES_TO_ENABLE` environment variable in the Cloud Function back to its original intended value.
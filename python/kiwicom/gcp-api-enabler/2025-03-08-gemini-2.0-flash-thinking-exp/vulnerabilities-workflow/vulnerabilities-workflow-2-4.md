### Vulnerability List

- **Vulnerability Name:** Insecure Storage of Services to Enable List

- **Description:**
    The list of Google Cloud APIs to be automatically enabled for new projects is stored as an environment variable named `SERVICES_TO_ENABLE`. This configuration is defined in the `.env` file and deployed with the Cloud Function. An attacker who gains unauthorized access to the Cloud Function's environment configuration can modify this environment variable to include additional, potentially malicious, services. When the Cloud Function is triggered for a new project, it will enable all services listed in the (potentially attacker-modified) `SERVICES_TO_ENABLE` environment variable.

    **Step-by-step trigger:**
    1. An attacker compromises the Google Cloud Function's service account, which requires Editor permissions at the organization level as per the project documentation.
    2. The attacker gains access to the Cloud Function's configuration, for example, by using the compromised service account to access the Google Cloud Console or using gcloud SDK.
    3. The attacker modifies the `SERVICES_TO_ENABLE` environment variable associated with the Cloud Function. They can add any Google Cloud API service name to this list, including services not intended to be automatically enabled.
    4. A new Google Cloud Project is created within the organization, triggering the Cloud Function via the configured Pub/Sub topic.
    5. The Cloud Function executes, reads the modified `SERVICES_TO_ENABLE` environment variable, and enables all services listed, including the ones added by the attacker, in the newly created project.

- **Impact:**
    By successfully modifying the `SERVICES_TO_ENABLE` environment variable, an attacker can force the Cloud Function to enable arbitrary Google Cloud APIs in newly created projects across the entire GCP organization. This can have severe consequences, including:
    * **Privilege Escalation:** Enabling IAM API (`iam.googleapis.com`) could allow the attacker to manipulate project permissions and escalate their privileges within the newly created projects or even the organization.
    * **Data Exfiltration:** Enabling Storage API (`storage.googleapis.com`) or Compute API (`compute.googleapis.com`) in projects where sensitive data might be stored could facilitate data exfiltration.
    * **Resource Abuse:** Enabling Compute API (`compute.googleapis.com`) or other resource-intensive APIs could allow the attacker to deploy and run malicious workloads (e.g., cryptocurrency mining) at the organization's expense.
    * **Compliance Violations:** Enabling unintended services might violate security policies or compliance regulations.
    * **Denial of Service (Indirect):** While not a direct DoS vulnerability, enabling numerous unnecessary services across many projects could lead to unexpected billing and resource consumption, effectively disrupting normal operations.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
    None directly implemented in the code. The security relies on the principle that access to Cloud Function environment variables is restricted to authorized personnel with sufficient GCP IAM permissions. However, if the Cloud Function's service account is compromised (which is the primary attack vector as per the problem description), this mitigation is bypassed.

- **Missing Mitigations:**
    * **Externalize Configuration Storage:** Instead of relying on environment variables, store the list of services to enable in a more secure and auditable configuration management system. Options include:
        * **Google Cloud Storage:** Store the list in a file in a private Cloud Storage bucket with restricted access. The Cloud Function would need to retrieve this file at runtime.
        * **Google Secret Manager:** Store the list as a secret in Secret Manager. This provides a more secure and auditable way to manage sensitive configuration data.
        * **Firestore/Datastore:** Store the list in a database service like Firestore or Datastore. This allows for more structured configuration and potentially easier updates.
    * **Input Validation and Sanitization (of service list - though less critical in this context):** Although the service list is intended to be managed by administrators, consider adding validation to the service names read from the configuration to ensure they are valid Google Cloud API service names. This can prevent accidental errors or attempts to inject unexpected values.
    * **Principle of Least Privilege for Service Account:** While not directly mitigating this specific vulnerability, adhering to the principle of least privilege for the Cloud Function's service account is crucial. Granting Editor role at the organization level is a very broad permission.  The required permissions should be carefully reviewed and minimized to only what is strictly necessary for the Cloud Function to perform its intended task. Ideally, a custom IAM role with only the necessary permissions (e.g., `serviceusage.services.enable` on organization level) should be used instead of the Editor role.

- **Preconditions:**
    * The attacker must successfully compromise the Google Cloud Function's service account or gain access to the GCP project where the Cloud Function is deployed with sufficient permissions to modify environment variables.
    * The Cloud Function must be deployed and configured to use the `SERVICES_TO_ENABLE` environment variable to determine which APIs to enable.

- **Source Code Analysis:**
    1. **`main.py:get_services_to_enable()` function:**
    ```python
    def get_services_to_enable():
        """Loads services from environment.
        :return: dict
        """
        services_to_enable = {}

        services_to_enable_raw = os.environ["SERVICES_TO_ENABLE"]

        for service in services_to_enable_raw.split(","):
            services_to_enable[service] = True

        return services_to_enable
    ```
    This function directly retrieves the value of the `SERVICES_TO_ENABLE` environment variable using `os.environ["SERVICES_TO_ENABLE"]`. It then splits the comma-separated string into a dictionary of services to be enabled. There is no validation or security mechanism implemented here to ensure the integrity or origin of this list.

    2. **`serverless.yml`:**
    ```yaml
    custom:
      dotenv:
        include:
          - SERVICES_TO_ENABLE
    ```
    The `serverless.yml` file uses the `serverless-dotenv-plugin` to load environment variables from the `.env` file, including `SERVICES_TO_ENABLE`, making it easily configurable but also potentially insecure if access to the environment is compromised.

    3. **`main.py:enable_services()` function:**
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
                services_to_enable[service_name] = False

        for service_name, should_enable in services_to_enable.items():
            if should_enable:
                service_long_name = project_name + "/services/" + service_name
                enable_service(credentials=credentials, service_name=service_long_name)
                enabled_services.append(service_long_name)

        return enabled_services
    ```
    The `enable_services` function calls `get_services_to_enable()` to retrieve the list of services. It then iterates through this list and enables each service using `enable_service()`. If the `services_to_enable` list has been tampered with by an attacker, this function will blindly enable those malicious services.

- **Security Test Case:**
    1. **Pre-deployment Setup:** Ensure the Cloud Function is deployed as described in the README, using environment variables for configuration.
    2. **Compromise Service Account (Simulated):** For testing purposes, assume you have gained access to the service account credentials used by the Cloud Function. In a real attack scenario, this could involve various techniques like credential phishing, exploiting vulnerabilities in other services, or insider threats. For this test, you can simulate this by using an account with Editor role on the organization.
    3. **Access Cloud Function Configuration:** Using the compromised service account (or an account with sufficient permissions), navigate to the Google Cloud Functions console in the GCP project where the API Enabler is deployed. Select the deployed Cloud Function.
    4. **Modify Environment Variable:** Edit the Cloud Function's configuration. Locate the "Environment variables" section and modify the `SERVICES_TO_ENABLE` variable. Append `,iam.googleapis.com` to the existing list of services. Save the updated configuration.
    5. **Trigger Cloud Function:** Create a new Google Cloud Project within the organization. This action should trigger the Pub/Sub topic and subsequently the Cloud Function.
    6. **Verify Enabled Services in New Project:** After a few minutes (to allow the Cloud Function to execute), navigate to the newly created GCP project in the Google Cloud Console. Go to "APIs & Services" -> "Enabled APIs & Services".
    7. **Check for Maliciously Enabled Service:** Verify that `IAM (Identity and Access Management) API` (or the service you added in step 4) is now enabled in the newly created project, in addition to the services that were originally intended to be enabled by the API Enabler.
    8. **Expected Result:** The `IAM (Identity and Access Management) API` should be enabled in the new project, demonstrating that an attacker can successfully modify the list of enabled services by altering the `SERVICES_TO_ENABLE` environment variable, leading to the unintended enabling of services.
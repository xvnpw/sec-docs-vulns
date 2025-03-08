- Vulnerability Name: Plaintext API Key in App Engine Configuration
- Description:
    1. The `app.yaml` file in the `/code/auth-appengine/` directory is used to configure the App Engine application.
    2. Line 5 of this file, `API_KEY: ""`, is intended to store an API key for accessing Cloud Scheduler API.
    3. The installation guide in `/code/auth-appengine/README.md` instructs users to directly edit this `app.yaml` file and paste the API key in plaintext between the quotation marks.
    4. This practice of storing API keys in plaintext configuration files exposes the key to anyone who can access the App Engine source code or configuration files.
    5. An attacker gaining access to the source code repository, or through misconfiguration of the App Engine deployment, could retrieve this API key.
- Impact:
    - **High:** If the API key is compromised, an attacker could potentially use it to access and manipulate the Cloud Scheduler API. Depending on the permissions granted to this API key, an attacker could:
        - List, create, delete, enable, and disable Report2BQ jobs.
        - Potentially disrupt report fetching and loading processes.
        - In a worst-case scenario, if the API key has overly broad permissions, the attacker might be able to escalate privileges within the GCP project.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - Identity Aware Proxy (IAP) is implemented for the `/code/auth-appengine/` application, which restricts access to the administration interface, potentially limiting unauthorized access to the `app.yaml` file through the deployed application. However, this does not prevent access from other vectors like compromised source code repository or misconfigured deployment pipelines.
- Missing Mitigations:
    - **Secure API Key Storage:** API keys should never be stored in plaintext configuration files. Implement secure storage mechanisms like Google Cloud Secret Manager to store and retrieve the API key. The application should retrieve the API key from Secret Manager at runtime instead of reading it from `app.yaml`.
    - **Principle of Least Privilege for API Key:**  The API key created for Report2BQ should be granted the minimum necessary permissions required for the application to function. Restrict the API key's scope to only the Cloud Scheduler API and only the specific actions required (e.g., list, get jobs).
- Preconditions:
    - An attacker needs to gain access to the `app.yaml` file in `/code/auth-appengine/`. This could be achieved through:
        - Compromising the source code repository where the project is hosted.
        - Exploiting a vulnerability in the App Engine application or deployment process that allows access to configuration files.
        - Social engineering or insider threat to gain access to the development/deployment environment.
- Source Code Analysis:
    - File: `/code/auth-appengine/app.yaml`
    ```yaml
    runtime: python310

    env_variables:
      # Insert an API key with access to the Cloud Scheduler API here
      API_KEY: ""
    ```
    - The `API_KEY: ""` line in `app.yaml` clearly indicates a configuration setting for the API key, intended to be manually populated in plaintext.
    - File: `/code/auth-appengine/README.md`
    ```markdown
    2. Edit the `app.yaml` file in your favourite text editor.
    Modify line 5 (`API_KEY: ""`) and copy/paste the API key from the [Credentials](https://console.cloud.google.com/apis/credentials) page into the API KEY between the quotation marks.
    ```
    - The documentation explicitly instructs users to store the API key directly in the `app.yaml` file.
- Security Test Case:
    1. **Prerequisites:**
        - Deploy the `auth-appengine` application as described in the `README.md`.
        - Obtain access to the deployed App Engine instance (e.g., through compromised developer account or misconfiguration).
    2. **Steps:**
        - Access the App Engine instance's file system or configuration settings. The method to achieve this depends on the attacker's access level and the specific vulnerabilities they exploit (e.g., App Engine admin console, deployment pipeline access, or potential application vulnerabilities).
        - Locate and open the `app.yaml` file within the App Engine deployment.
        - Examine the content of the `app.yaml` file.
        - Observe the value associated with the `API_KEY` environment variable.
    3. **Expected Result:**
        - The `API_KEY` environment variable in `app.yaml` will contain the plaintext API key that was configured during the installation process. This confirms the vulnerability.
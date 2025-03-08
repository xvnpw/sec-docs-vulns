- Vulnerability Name: Storing GCP credentials in environment variables

- Description:
    1. The README.md file instructs users to authenticate with Google BigQuery using a service account.
    2. Step 2.7 of the "How to use it" section advises users to set the `GOOGLE_APPLICATION_CREDENTIALS` environment variable to the path of the `client_secrets.json` file.
    3. While environment variables are a common way to configure applications, storing sensitive credentials like service account keys directly in environment variables can pose a security risk.
    4. If the environment where `target-bigquery` is running is compromised (e.g., through a server-side vulnerability, supply chain attack or insider threat), an attacker could potentially gain access to the service account credentials.
    5. With compromised service account credentials, an attacker could gain unauthorized access to the Google BigQuery project, potentially leading to data breaches, data manipulation, or other malicious activities.

- Impact:
    - High. If an attacker gains access to the service account credentials, they can potentially read, modify, or delete data in the linked Google BigQuery project, leading to significant data breaches and data integrity issues.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    - No specific mitigations are implemented within the `target-bigquery` project to prevent storing credentials in environment variables. The README.md only documents this approach as the recommended authentication method.

- Missing Mitigations:
    - The project should discourage storing service account credentials directly in environment variables and recommend more secure alternatives for credential management.
    - Suggest using Google Cloud's recommended best practices for credential management, such as workload identity federation, Google Cloud Secret Manager, or other secure vault solutions.
    - Provide documentation and examples for using more secure credential management methods.

- Preconditions:
    - The user must follow the README.md instructions and configure `target-bigquery` to authenticate using a service account.
    - The user must set the `GOOGLE_APPLICATION_CREDENTIALS` environment variable to the path of the service account key file.
    - The environment where `target-bigquery` is running must be vulnerable to compromise.

- Source Code Analysis:
    - The code itself does not directly handle credential storage, as it relies on the standard Google Cloud client library for Python's default credential resolution.
    - The vulnerability lies in the documented configuration practice in `README.md`.
    - The `README.md` file, in "Step 2: Authenticate with a service account", explicitly instructs users to:
        ```
        7. Set a **GOOGLE_APPLICATION_CREDENTIALS** environment variable on the machine, where the value is the fully qualified
           path to **client_secrets.json** file:
        ```
    - This recommendation makes the application vulnerable if the environment is compromised.

- Security Test Case:
    1. **Setup:**
        - Deploy `target-bigquery` in a test environment following the README.md instructions, including setting the `GOOGLE_APPLICATION_CREDENTIALS` environment variable with a valid service account key for a test BigQuery project.
        - Simulate a compromise of the environment where `target-bigquery` is running. This could be achieved through various means depending on the test environment (e.g., gaining shell access to a VM, exploiting a mock application vulnerability).
    2. **Exploit:**
        - As an attacker with access to the compromised environment, retrieve the value of the `GOOGLE_APPLICATION_CREDENTIALS` environment variable.
        - Use the retrieved path to access and extract the service account key file (`client_secrets.json`).
        - Utilize the extracted service account key to authenticate with the Google Cloud SDK or client libraries from an attacker-controlled machine, outside of the test environment.
    3. **Verification:**
        - From the attacker-controlled machine, successfully authenticate to the test Google BigQuery project using the compromised service account key.
        - Verify unauthorized access by performing actions such as listing BigQuery datasets, tables, or querying data within the test project.
        - Observe if actions are successful, confirming that the compromised credentials grant unauthorized access to the BigQuery project.
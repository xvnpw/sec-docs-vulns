### Combined Vulnerability List

This document outlines the identified vulnerabilities after combining and filtering the provided lists. Each vulnerability is described in detail, including its potential impact, rank, mitigations, preconditions, source code analysis, and a security test case.

#### Vulnerability Name: Owner permission granted to Compute Engine Default Service Account

- Description:
    1. The `Initial Setup` section in `README.md` instructs users to grant 'Owner' role to the Compute Engine default service account using the command:
    ```bash
    gcloud projects add-iam-policy-binding $GCP_PROJECT_ID \
      --member="serviceAccount:${GCP_PROJECT_NUMBER}-compute@developer.gserviceaccount.com" \
      --role='roles/owner'
    ```
    2. This command grants the 'Owner' role at the project level to the Compute Engine default service account.
    3. The 'Owner' role is overly permissive, granting broad access to all Google Cloud resources within the project.
    4. An attacker who gains access to any VM instance running as the Compute Engine default service account can leverage these excessive permissions to compromise the entire Google Cloud project.
- Impact:
    - Critical. Full project compromise. An attacker can gain complete control over all Google Cloud resources within the project, including data access, modification, deletion, and resource manipulation. This can lead to severe data breaches, financial loss, and disruption of services.
- Vulnerability Rank: critical
- Currently Implemented Mitigations:
    - None. The setup guide explicitly instructs users to grant this overly permissive role.
- Missing Mitigations:
    - **Principle of Least Privilege**: Instead of granting 'Owner', implement the principle of least privilege by granting only the necessary IAM roles to the Compute Engine default service account.  Specifically, the application likely only needs roles to interact with Dataflow, Composer, BigQuery, AutoML and Storage.  More granular roles like `roles/dataflow.developer`, `roles/composer.worker`, `roles/bigquery.user`, `roles/automl.serviceAgent`, `roles/storage.objectAdmin` should be considered, depending on the actual operations performed by the compute instances.
    - **Service Account Scoping**:  Instead of relying on project-level IAM, use service account scopes when launching Compute Engine instances. This further restricts the permissions available to the instance.
    - **Avoid Default Service Account**: Instead of using the Compute Engine default service account, create a dedicated service account with only the necessary permissions and attach it to the Compute Engine instances.
- Preconditions:
    - The user must follow the `Initial Setup` instructions in `README.md` and execute the command to grant 'Owner' role to the Compute Engine default service account.
    - An attacker needs to gain access to a Compute Engine VM running under the default Compute Engine service account. This could be achieved through various VM instance compromise techniques (e.g., exploiting vulnerabilities in applications running on the VM, gaining access to VM credentials, etc.).
- Source Code Analysis:
    - `/code/README.md`: The setup instructions clearly state to grant the 'Owner' role.
    ```markdown
    ### Grant service account permissions

    - Grant Owner permissions to the default compute service account:

        ```bash
          gcloud projects add-iam-policy-binding $GCP_PROJECT_ID \
            --member="serviceAccount:${GCP_PROJECT_NUMBER}-compute@developer.gserviceaccount.com" \
            --role='roles/owner'
        ```
    ```
    - This instruction is directly copy-pasteable and encourages users to create a highly insecure configuration.
- Security Test Case:
    1. Deploy the Blockbuster project on GCP following the `Initial Setup` instructions in `README.md`, specifically granting the 'Owner' role to the Compute Engine default service account.
    2. Create a Compute Engine VM instance in the same project, ensuring it uses the default Compute Engine service account.
    3. SSH into the newly created Compute Engine VM instance.
    4. From within the VM instance, use the Google Cloud SDK (pre-installed) to attempt to list all GCS buckets in the project:
    ```bash
    gcloud storage buckets list
    ```
    5. If the vulnerability exists, the command will successfully list all GCS buckets in the project, demonstrating unauthorized access due to the 'Owner' role.
    6. Further escalate the test by attempting to read data from a bucket, create a new BigQuery dataset, or perform other privileged actions to confirm the full extent of the 'Owner' role's impact.

#### Vulnerability Name: Command Injection via Airflow Variables

- Description:
    1. An attacker gains access to the Cloud Composer environment, either through compromised credentials or by exploiting a misconfiguration that allows unauthorized access.
    2. The attacker modifies the `variables.json` or `features.json` files stored in the Cloud Storage bucket associated with the Cloud Composer environment. These files are intended to configure the Airflow DAGs.
    3. The attacker injects malicious code into the JSON files. For example, within a string value in `variables.json`, the attacker could insert a command like `;$(malicious_command)`.
    4. The Airflow DAGs, specifically the `blockbuster_training_prepare_source.py`, `blockbuster_training_preprocess.py`, `blockbuster_training_train_model.py`, `blockbuster_training_analyze.py`, `blockbuster_predictions_and_activation.py` DAGs, use the `airflow_utils.retrieve_airflow_variable_as_dict` function to load configuration variables from Airflow variables, which are initialized from these JSON files.
    5. If the DAGs, or any underlying functions they call, insecurely process these variables—for example, by directly passing them to a shell command without sanitization—the injected malicious command from `variables.json` or `features.json` will be executed within the Cloud Composer environment.
    6. The `gcloud composer environments run variables` command is used to import these JSON files into Airflow variables, making the malicious content available to the DAGs.
    7. When a vulnerable DAG runs and processes the compromised Airflow variable, the injected command is executed, leading to command injection.

- Impact:
    - High: Successful command injection allows the attacker to execute arbitrary commands within the Cloud Composer environment. This could lead to:
        - Data exfiltration: Access and extraction of sensitive marketing analytics data, customer data, or internal project information stored within the Cloud Composer environment or connected GCP services.
        - System compromise: Full control over the Cloud Composer environment, enabling the attacker to modify DAGs, access secrets, pivot to other GCP resources, or disrupt the marketing analytics solution.
        - Data manipulation: Modification or deletion of critical data, leading to incorrect analytics, business disruption, or reputational damage.

- Vulnerability Rank: Critical

- Currently Implemented Mitigations:
    - None: The provided code does not include any explicit sanitization or validation of the data loaded from `variables.json` or `features.json` before using them in operations that could lead to command execution. The project description itself warns about the inactive development status, implying no recent security updates.

- Missing Mitigations:
    - **Input Sanitization:** Implement strict input validation and sanitization for all data read from `variables.json` and `features.json`. This should include validating data types, formats, and lengths, and escaping or rejecting any characters or patterns that could be used for command injection.
    - **Secure Deserialization:** Ensure that JSON deserialization processes are secure and do not introduce vulnerabilities. While JSON itself is generally safe, the *use* of the deserialized data in subsequent operations is critical.
    - **Principle of Least Privilege:**  Apply the principle of least privilege to the service accounts and roles used by the Cloud Composer environment. Restrict the permissions of the Cloud Composer service account to the minimum necessary for its intended function, limiting the impact of a successful command injection.
    - **Regular Security Audits and Penetration Testing:** Conduct regular security audits and penetration testing to identify and address potential vulnerabilities proactively.
    - **Code Reviews:** Implement mandatory security-focused code reviews for all changes to DAGs and supporting code to catch potential vulnerabilities before they are deployed.
    - **Web Application Firewall (WAF):** Although the primary attack vector isn't a web application, consider if a WAF or similar network-level security controls could provide any additional defense-in-depth.

- Preconditions:
    1. **Access to Cloud Composer Environment:** The attacker needs some level of access to the Cloud Composer environment to modify files in its associated Cloud Storage bucket. This could be achieved through compromised GCP credentials, a publicly accessible Composer UI with weak authentication, or other misconfigurations.
    2. **Vulnerable DAG Execution:** An Airflow DAG must be executed that processes the compromised Airflow variables in a vulnerable manner (e.g., passing them unsanitized to a shell command or insecure deserialization function).
    3. **`variables.json` or `features.json` Modification:** The attacker must successfully modify the `variables.json` or `features.json` files in the Cloud Storage bucket to inject malicious commands or payloads.

- Source Code Analysis:
    1. **`src/dags/dependencies/airflow_utils.py`:**
        ```python
        def retrieve_airflow_variable_as_dict(
            key: str) -> Dict[str, Union[str, Dict[str, str]]]:
          """Retrieves Airflow variables given key.
          ...
          """
          value = models.Variable.get(key)
          try:
            value_dict = json.loads(value) # Insecure Deserialization Point - Potentially vulnerable if JSON contains malicious code for execution later.
          except json.decoder.JSONDecodeError as error:
            raise Exception('Provided key "{}" cannot be decoded. {}'.format(
                key, error))
          return value_dict
        ```
        - This function, used throughout the DAGs, retrieves Airflow variables and parses them as JSON. While `json.loads` itself isn't directly vulnerable to command injection, the *deserialized data* is used in DAG logic, creating potential for vulnerabilities depending on how this data is subsequently handled.


    **Visualization:**

    ```
    Attacker Modifies variables.json/features.json in GCS Bucket -->
    gcloud composer environments run variables (Imports JSON to Airflow Variables) -->
    Airflow DAGs (blockbuster_*.py) -->
    retrieve_airflow_variable_as_dict() (Loads variables as Python Dictionaries) -->
    Vulnerable Operator/Library (If exists, processes variables insecurely leading to command injection) -->
    Command Execution in Cloud Composer Environment
    ```

- Security Test Case:
    1. **Pre-requisite:** Assume you have access to the Cloud Composer environment's Cloud Storage bucket and can modify files within it. You also have access to trigger DAG runs in the Airflow UI.
    2. **Modify `variables.json`:**
        - Download `setup/variables.json` from the repository.
        - Edit `setup/variables.json`. In any string value, inject a command. For example, modify the `gcp_project` value under `"bb_project"` to: `"test_project; touch /tmp/pwned;"`.
        - Upload the modified `variables.json` to the Cloud Storage bucket of your Composer environment, placing it in the `data` folder (e.g., `/data/variables.json`).
    3. **Import Variables:**
        - In your local terminal, execute the command to import the modified `variables.json` into Airflow variables:
          ```bash
          gcloud composer environments run $GCP_COMPOSER_ENV_NAME \
            --location $GCP_REGION \
            variables -- --i /home/airflow/gcs/data/variables.json
          ```
    4. **Trigger a DAG:**
        - In the Airflow UI, trigger any of the DAGs: `0_BB_Prepare_Source`, `1_BB_Analysis`, `2_BB_Preprocess`, `3_BB_Data_load_and_train`, or `4_BB_Predict_and_activate`.
    5. **Check for Command Execution:**
        - After the DAG run completes (or fails), SSH into the Cloud Composer worker environment (using `kubectl exec -it ...` to access a worker pod in the Composer cluster - you'll need to find the worker pod name using `kubectl get pods -n composer-...`).
        - Check if the command injected in `variables.json` was executed. In our example, check if the file `/tmp/pwned` was created: `ls /tmp/pwned`.
        - If the file `/tmp/pwned` exists, this confirms command injection vulnerability.
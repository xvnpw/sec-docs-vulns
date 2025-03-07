## Combined Vulnerability List

This document outlines the identified vulnerabilities, combining information from multiple lists and removing duplicates, focusing on high and critical severity issues.

### 1. OSDU Endpoint URL Parameter Injection

- **Vulnerability Name:** OSDU Endpoint URL Parameter Injection
- **Description:**
  1. The `setup.sh` script configures the `osducli` tool.
  2. It uses the `OSDU_ENDPOINT` environment variable to set the `server` parameter in the `osducli` configuration file (`$HOME/.osducli/config`).
  3. The `server` parameter defines the base URL for OSDU API requests.
  4. An attacker controlling `OSDU_ENDPOINT` can inject a malicious URL.
  5. Data loading scripts in `/src/data_load/load.py` use the `osducli` configuration.
  6. API requests from data loading scripts are redirected to the attacker's malicious URL.
- **Impact:**
  1. **Data Redirection:** Sensitive data for the OSDU instance is sent to the attacker's server, including ingested TNO data, metadata, and logs.
  2. **Information Leakage:** Authentication tokens used for OSDU API access might be exposed to the attacker's server.
  3. **Man-in-the-Middle Attack:** Data in transit can be intercepted, monitored, and potentially modified by the attacker.
- **Vulnerability Rank:** High
- **Currently Implemented Mitigations:**
  - None. The `setup.sh` script directly uses `OSDU_ENDPOINT` without validation.
- **Missing Mitigations:**
  - **Input Validation and Sanitization:** Validate and sanitize `OSDU_ENDPOINT` in `setup.sh` before configuring `osducli`. This includes:
    - Whitelisting allowed domains or URL patterns.
    - Sanitizing the URL to remove or encode harmful characters.
  - **Secure Configuration Method:** Use a more secure configuration method than directly using environment variables in `setup.sh`, such as:
    - A configuration file not directly modified by environment variables.
    - A secrets management system for sensitive configuration values.
- **Preconditions:**
  - The attacker must control the `OSDU_ENDPOINT` environment variable before `setup.sh` execution or during ARM template deployment. This can be achieved by:
    - Compromising the CI/CD pipeline.
    - Exploiting deployment environment misconfigurations.
    - Modifying the `.envrc` file or directly setting the environment variable in a "Developer Persona" environment.
- **Source Code Analysis:**
  1. **File: `/code/setup.sh`**
     ```bash
     CONFIG_FILE=$HOME/.osducli/config
     cat > $CONFIG_FILE << EOF
     [core]
     server = ${OSDU_ENDPOINT}
     crs_catalog_url = /api/crs/catalog/v2/
     crs_converter_url = /api/crs/converter/v2/
     entitlements_url = /api/entitlements/v2/
     file_url = /api/file/v2/
     legal_url = /api/legal/v1/
     schema_url = /api/schema-service/v1/
     search_url = /api/search/v2/
     storage_url = /api/storage/v2/
     unit_url = /api/unit/v3/
     workflow_url = /api/workflow/v1/
     data_partition_id = ${DATA_PARTITION}
     legal_tag = ${LEGAL_TAG}
     acl_viewer = data.default.viewers@p${DATA_PARTITION}.dataservices.energy
     acl_owner = data.default.owners@${DATA_PARTITION}.dataservices.energy
     authentication_mode = refresh_token
     token_endpoint = https://login.microsoftonline.com/${AZURE_TENANT}/oauth2/v2.0/token
     refresh_token = ${REFRESH_TOKEN}
     client_id = ${CLIENT_ID}
     client_secret = ${CLIENT_SECRET}
     EOF
     ```
     - `setup.sh` directly embeds the `OSDU_ENDPOINT` environment variable into the `osducli` configuration file's `server` parameter without validation.
  2. **Files: `/code/src/data_load/load.py` and `/code/src/data_load/utils.py`**
     ```python
     # Read config file dataload.ini
     config = configparser.RawConfigParser()
     config.read("output/dataload.ini")

     # Some constants, used by script
     SCHEMAS_URL = config.get("CONNECTION", "schemas_url")
     STORAGE_URL = config.get("CONNECTION", "storage_url")
     WORKFLOW_URL = config.get("CONNECTION", "workflow_url")
     SEARCH_URL = config.get("CONNECTION", "search_url")
     FILE_URL = config.get("CONNECTION", "file_url")
     ```
     - Python scripts use the `osducli` configuration to determine OSDU API endpoint URLs. They read `dataload.ini` (generated from `osducli` config) and use the `server` setting (from `OSDU_ENDPOINT`) to construct URLs for OSDU services. Compromised `OSDU_ENDPOINT` redirects API requests.
- **Security Test Case:**
  1. **Setup:**
     - Deploy ARM template from `azuredeploy.json`.
     - Locate deployed Container Instance in Azure portal.
     - Modify Container Instance's environment variables, setting `OSDU_ENDPOINT` to `https://attacker.example.com`. Restart container if needed. Alternatively, set up network traffic capture on `attacker.example.com`.
  2. **Execution:**
     - Execute "Step 2" from `README.md` to load data, triggering the Template Spec and container instance with modified `OSDU_ENDPOINT`.
  3. **Verification:**
     - **Network Traffic Analysis:** Monitor network traffic from Container Instance. Verify requests are sent to `attacker.example.com`. Examine captured traffic/logs on `attacker.example.com` for redirected OSDU requests and sensitive data/authentication headers.
     - **Container Instance Logs:** Review Container Instance logs in Azure portal for errors indicating redirection or failed API calls. Successful redirection might not show errors if the attacker's server partially mimics the OSDU API.

This test case validates the OSDU Endpoint URL Parameter Injection vulnerability through API call redirection to a malicious server.

### 2. Plaintext Storage of Credentials in Container Configuration File

- **Vulnerability Name:** Plaintext Storage of Credentials in Container Configuration File
- **Description:**
  1. `setup.sh` script executes during container startup.
  2. It configures `osducli` by creating `$HOME/.osducli/config`.
  3. `setup.sh` directly embeds `REFRESH_TOKEN`, `CLIENT_ID`, and `CLIENT_SECRET` environment variables in plaintext into this configuration file.
  4. The configuration file resides within the container's filesystem.
  5. An attacker gaining container/filesystem/log access can read this file and extract plaintext credentials.
  6. With these credentials, the attacker can authenticate to the OSDU instance and perform unauthorized actions.
- **Impact:**
  - Critical. Exposure of `CLIENT_SECRET` and `REFRESH_TOKEN` bypasses authentication and authorization.
  - Unauthorized access to the OSDU instance.
  - Data compromise, modification, or deletion within OSDU.
  - Potential privilege escalation within the OSDU environment.
- **Vulnerability Rank:** Critical
- **Currently Implemented Mitigations:**
  - None. Secrets are directly embedded in plaintext in the container configuration file.
- **Missing Mitigations:**
  - **Secure Secret Storage:** Use Azure Key Vault or similar for secure secret management and injection, avoiding plaintext storage.
  - **Runtime Environment Variable Injection:** Retrieve credentials from environment variables only at container runtime, not during image build or initial setup.
  - **Principle of Least Privilege:** Use credentials with minimal necessary permissions for data loading tasks.
  - **Regular Credential Rotation:** Implement regular rotation of credentials.
- **Preconditions:**
  - "Developer Persona" data loading using the provided Docker container and `load.sh`.
  - User has set `REFRESH_TOKEN`, `CLIENT_ID`, and `CLIENT_SECRET` environment variables.
  - Attacker gains unauthorized access to the running container, its filesystem, or logs.
- **Source Code Analysis:**
  1. **File: `/code/load.sh`**: Calls `setup.sh`.
  2. **File: `/code/setup.sh`**: Configures `osducli` and stores credentials in plaintext.
  ```bash
  #!/usr/bin/env bash
  # ...
  CONFIG_FILE=$HOME/.osducli/config

  cat > $CONFIG_FILE << EOF
  [core]
  server = ${OSDU_ENDPOINT}
  # ...
  authentication_mode = refresh_token
  token_endpoint = https://login.microsoftonline.com/${AZURE_TENANT}/oauth2/v2.0/token
  refresh_token = ${REFRESH_TOKEN}
  client_id = ${CLIENT_ID}
  client_secret = ${CLIENT_SECRET}
  EOF

  chmod 600 $CONFIG_FILE
  ```
  **Visualization:**

  ```
  load.sh --> ConfigureIni() --> setup.sh
                                    |
                                    | Creates $HOME/.osducli/config with plaintext credentials
                                    V
  Container Filesystem <-------------------- Plaintext Credentials Stored Here
  ```
  - `load.sh` calls `ConfigureIni`, which calls `setup.sh`.
  - `setup.sh` writes `${REFRESH_TOKEN}`, `${CLIENT_ID}`, and `${CLIENT_SECRET}` directly to `$CONFIG_FILE` in plaintext using `cat`.
  - `chmod 600` limits access within the container but secrets are still vulnerable if the container is compromised.
- **Security Test Case:**
  1. **Prerequisites:**
     - Follow "Developer Persona" setup, build and run Docker container.
     - Set `AZURE_TENANT`, `CLIENT_ID`, `CLIENT_SECRET`, and `REFRESH_TOKEN` environment variables.
     - Run container with `docker run -it --rm --env-file .env -v $(pwd)/open-test-data:/app/open-test-data -v $(pwd)/output:/app/output osdu-data-load /bin/bash`.
  2. **Access Container Shell:** Run `docker run` to get a shell inside the container.
  3. **Navigate to Configuration Directory:** `cd /app`.
  4. **Inspect Configuration File:** `cat /home/app/.osducli/config`.
  5. **Verify Plaintext Credentials:** Observe plaintext `refresh_token`, `client_id`, and `client_secret` in the output.
  6. **(Optional) Simulate Credential Usage:** Use extracted credentials with `osducli` commands (e.g., `osdu storage container list`) to verify unauthorized OSDU access.

This test case demonstrates easy retrieval of plaintext credentials from the configuration file upon container access.

### 3. Overly Permissive Storage Account Access via ARM Template Misconfiguration

- **Vulnerability Name:** Overly Permissive Storage Account Access via ARM Template Misconfiguration
- **Description:**
    1. Attacker identifies an instance of `osdu-data-load-tno` deployed on Azure.
    2. Attacker examines the public `azuredeploy.json` ARM template.
    3. The ARM template configures the Azure Storage Account for staging TNO data with overly permissive access policies (e.g., broad SAS tokens or misconfigured network rules).
    4. Attacker exploits this to gain unauthorized access to the Storage Account.
    5. Attacker accesses sensitive TNO open test data staged in the Storage Account.
- **Impact:**
    - Unauthorized access to sensitive TNO open test data in Azure Storage Account.
    - Potential data breach if TNO data is confidential.
    - Reputational damage.
- **Vulnerability Rank:** High
- **Currently Implemented Mitigations:**
    - None. No specific mitigations for Storage Account access control misconfigurations are included.
- **Missing Mitigations:**
    - **Restrict Storage Account Network Access:** Implement network rules in the ARM template to limit access to authorized Azure services and trusted networks.
    - **Principle of Least Privilege for SAS Tokens:** If using SAS tokens, generate them with minimal permissions and short durations. Review ARM template and scripts for secure SAS token generation.
    - **Azure Private Link:** Consider Azure Private Link for private Storage Account access within Azure network.
    - **Regular Security Audits:** Implement regular audits of deployed Azure resources and Storage Account configurations.
    - **Security Hardening Documentation:** Provide documentation on secure Storage Account configuration when deploying the ARM template.
- **Preconditions:**
    - `osdu-data-load-tno` deployed on Azure using the provided ARM template.
    - Azure Storage Account deployed by ARM template is misconfigured with overly permissive access.
    - Attacker has network access to the deployed Azure Storage Account.
- **Source Code Analysis:**
    1. **`File: /code/azuredeploy.json`**: ARM template for Azure resource deployment, including Storage Account.
    2. Analyze `resources` section for Storage Account definition (`type: 'Microsoft.Storage/storageAccounts'`).
    3. Examine `properties` for access control configurations:
        - `networkAcls`: Check for `networkAcls` property and network rule configuration. Overly permissive if `bypass` is `None` or `AzureServices` only and `defaultAction` is `Allow`, or if `ipRules` and `virtualNetworkRules` are not restrictive.
        - **Absence of specific access restriction configurations:** Lack of restrictive `networkAcls` in the ARM template leads to less secure default configuration.
    4. **Scripts Analysis (`load.sh`, `src/data_load/load.py`):** Review for Storage Account interaction and SAS token usage. Analyze SAS token generation, permissions, and expiry if used. Direct embedding of Storage Account keys is less likely in template deployments but also a vulnerability.

    **Visualization:**

    ```mermaid
    graph LR
        A[Attacker] -->|1. Identify Project Instance| B(Public Azure Deployment);
        B -->|2. Examine azuredeploy.json| C(Public GitHub Repository);
        C -->|3. Analyze Storage Account Config| D{Overly Permissive Access?};
        D -- Yes --> E[Exploit Misconfiguration];
        E -->|4. Access Storage Account| F(Azure Storage Account);
        F -->|5. Access Staged TNO Data| G(Sensitive TNO Data);
        D -- No --> H[No Vulnerability (in this aspect)];
    ```

- **Security Test Case:**
    1. **Prerequisites:**
        - Deploy `osdu-data-load-tno` to Azure using `azuredeploy.json` with default parameters.
        - Obtain deployed Storage Account name from Azure portal.
    2. **Steps:**
        - **Attempt Public Access:** Try accessing Storage Account from public network without authentication (if `azuredeploy.json` allows public access). Use Azure Storage Explorer or `az storage blob list`.
        - **Identify Potential SAS Tokens:** If scripts generate SAS tokens, try to intercept/locate one.
        - **Attempt Anonymous Blob Listing:** If accessible, list blobs in data staging container using `az storage blob list`.
        - **Download Sample Data:** If blob listing is successful, download a file using `az storage blob download`.
    3. **Expected Result:**
        - **Vulnerable:** Successful blob listing and data download without authorization indicate misconfiguration.
        - **Not Vulnerable (Mitigated):** Access denied or requiring valid restricted credentials indicates proper configuration (not default in provided template).
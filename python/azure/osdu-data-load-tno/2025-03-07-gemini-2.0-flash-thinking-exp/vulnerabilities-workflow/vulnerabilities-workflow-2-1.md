### Vulnerability List

- Vulnerability Name: OSDU Endpoint URL Parameter Injection
- Description:
  1. The `setup.sh` script is used to configure the `osducli` tool.
  2. This script directly uses the `OSDU_ENDPOINT` environment variable to set the `server` parameter in the `osducli` configuration file located at `$HOME/.osducli/config`.
  3. The `server` parameter in the `osducli` configuration defines the base URL for all API requests to the OSDU instance.
  4. If an attacker can control the `OSDU_ENDPOINT` environment variable, they can inject a malicious URL.
  5. When the data loading scripts in `/src/data_load/load.py` are executed, they use the `osducli` configuration, including the attacker-controlled `OSDU_ENDPOINT`.
  6. Consequently, all API requests made by the data loading scripts will be redirected to the malicious URL specified in `OSDU_ENDPOINT`.
- Impact:
  1. **Data Redirection:** Sensitive data intended for the legitimate OSDU instance could be sent to an attacker-controlled server, potentially including ingested TNO data, metadata, and logs.
  2. **Information Leakage:** Authentication tokens or other sensitive information used for OSDU API access, if inadvertently included in requests, could be exposed to the attacker's server.
  3. **Man-in-the-Middle Attack:** An attacker could intercept, monitor, and potentially modify data in transit between the data loading process and the legitimate OSDU instance or attacker server, depending on the malicious URL setup.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
  - None. The project directly uses the `OSDU_ENDPOINT` environment variable in `setup.sh` without any validation or sanitization.
- Missing Mitigations:
  - **Input Validation and Sanitization:** Implement validation and sanitization of the `OSDU_ENDPOINT` environment variable within the `setup.sh` script before using it to configure `osducli`. This could include:
    - Whitelisting allowed domains or URL patterns.
    - Sanitizing the URL to remove or encode potentially harmful characters.
  - **Secure Configuration Method:** Instead of directly using environment variables in `setup.sh`, consider using a more secure configuration method for `osducli`. This could involve:
    - Using a configuration file that is not directly modified by environment variables.
    - Employing a dedicated secrets management system to handle sensitive configuration values.
- Preconditions:
  - The attacker must be able to control or influence the `OSDU_ENDPOINT` environment variable before the `setup.sh` script is executed or during the ARM template deployment process. This could be achieved through:
    - Compromising the CI/CD pipeline used to deploy the solution.
    - Exploiting misconfigurations in the deployment environment that allow modification of environment variables.
    - If running in the "Developer Persona", the attacker could modify the `.envrc` file or directly set the environment variable in their development environment.
- Source Code Analysis:
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
     - The `setup.sh` script configures the `osducli` tool by directly embedding the value of the `OSDU_ENDPOINT` environment variable into the `server` parameter of the `osducli` configuration file. No validation or sanitization is performed on the `OSDU_ENDPOINT` value before it is used.
  2. **File: `/code/src/data_load/load.py` and `/code/src/data_load/utils.py`**
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
     - The Python scripts in `/src/data_load/load.py` rely on the `osducli` configuration to determine the OSDU API endpoint URLs. They read the configuration file (`dataload.ini` which is generated from `osducli` config) and use the `server` setting (derived from `OSDU_ENDPOINT`) to construct URLs for various OSDU services (schemas, storage, workflow, search, file).
     - The `utils.py` file's `get_headers` function and the functions in `load.py` use these constants to make requests to the OSDU API. If `OSDU_ENDPOINT` is compromised, these requests will be directed to the attacker's chosen URL.
- Security Test Case:
  1. **Setup:**
     - Deploy the ARM template from `azuredeploy.json` as described in the `README.md`.
     - Locate the deployed Container Instance resource in the Azure portal.
     - Modify the Container Instance's environment variables. Specifically, update the `OSDU_ENDPOINT` environment variable to a malicious URL, e.g., `https://attacker.example.com`. You may need to stop and restart the container instance for the environment variable change to take effect. Alternatively, set up a network traffic capturing tool (like `tcpdump` or Wireshark) on a server you control (`attacker.example.com`).
  2. **Execution:**
     - Execute "Step 2" from the `README.md` to load data to the OSDU instance. This step triggers the Template Spec, which in turn runs the container instance with the modified `OSDU_ENDPOINT` environment variable.
  3. **Verification:**
     - **Network Traffic Analysis:** Monitor the network traffic originating from the Container Instance. Verify if requests are being sent to `attacker.example.com` instead of the legitimate OSDU endpoint. On `attacker.example.com` server, examine the captured network traffic or logs to confirm if requests intended for the OSDU instance (like file upload, metadata posting, manifest ingestion) are being received. Check if sensitive data or authentication headers are present in these redirected requests.
     - **Container Instance Logs:** Review the logs of the Container Instance in Azure portal. Look for error messages or unusual behavior that might indicate redirection or failed API calls to the legitimate OSDU endpoint (due to redirection). However, successful redirection might not produce errors in the logs if the attacker's server is set up to mimic the OSDU API partially.

This test case will demonstrate that by manipulating the `OSDU_ENDPOINT` environment variable, an attacker can successfully redirect API calls from the data loading process to a malicious server, thus validating the OSDU Endpoint URL Parameter Injection vulnerability.
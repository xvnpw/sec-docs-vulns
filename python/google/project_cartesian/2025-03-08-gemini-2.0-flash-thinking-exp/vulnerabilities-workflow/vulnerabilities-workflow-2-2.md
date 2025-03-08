- Vulnerability name: Insecure Configuration Update Endpoint
- Description:
    1. An attacker identifies the Cloud Run service URL for the Project Cartesian instance. This URL is typically publicly accessible if the Cloud Run service is deployed without specific ingress controls.
    2. The attacker crafts a `curl` request to the `/updateConfig` endpoint of the Cloud Run service. This request includes the `sheet_name` parameter in the query string, specifying the attacker's controlled Google Sheet name containing malicious configuration.
    3. The attacker sends the crafted `curl` request to the `/updateConfig` endpoint without any authentication headers or tokens.
    4. The `/updateConfig` endpoint, as implemented in `main.py`, processes the request and calls the `_load_config` function, using the `sheet_name` parameter from the URL.
    5. The `_load_config` function fetches the configuration from the attacker-specified Google Sheet and updates the application's `config.json` file and in-memory `params` variable.
    6. Subsequent executions of the main application logic (e.g., via the `/execute` endpoint or scheduled runs) will use the attacker-modified configuration. This can lead to the application processing data according to the attacker's parameters, potentially exfiltrating data to attacker-controlled destinations or manipulating data processing logic.
- Impact:
    - **Configuration Manipulation:** Attackers can overwrite the application's configuration, including sensitive parameters like BigQuery datasets, Google Sheet names, and Merchant Center IDs.
    - **Data Exfiltration:** By modifying the `output_google_sheet_name` in the configuration, attackers can redirect the output feed to a Google Sheet they control, allowing them to steal Merchant Center data.
    - **Data Manipulation:** Attackers can alter data processing logic by modifying other configuration parameters, potentially leading to incorrect or malicious feeds being generated.
    - **Supply Chain Attack:** If the generated feeds are used in downstream systems (e.g., ad campaigns), the attacker's modifications could propagate to these systems, causing further harm.
- Vulnerability rank: High
- Currently implemented mitigations:
    - None. The `/updateConfig` endpoint in `main.py` does not implement any form of authentication or authorization. It directly processes requests from any source.
- Missing mitigations:
    - **Authentication:** Implement authentication to verify the identity of the caller to the `/updateConfig` endpoint. This could be API keys, OAuth 2.0, or other authentication mechanisms.
    - **Authorization:** Implement authorization to ensure that only authorized users or service accounts can update the configuration. This could involve checking IAM roles or using a dedicated access control list.
    - **Input Validation:** Validate the `sheet_name` parameter to ensure it conforms to expected patterns and prevent injection attacks. However, relying solely on input validation is insufficient for security in this case.
    - **Network Security:** Restrict access to the `/updateConfig` endpoint to authorized networks or IP ranges using Cloud Run ingress controls or a Web Application Firewall (WAF). However, this might not be sufficient if internal attackers or compromised accounts are a threat.
- Preconditions:
    - The Project Cartesian application must be deployed and running on Cloud Run with the `/updateConfig` endpoint publicly accessible or accessible to the attacker's network.
    - The attacker must know or be able to discover the Cloud Run service URL.
    - The attacker needs to know the structure of the configuration Google Sheet to craft a valid sheet name.
- Source code analysis:
    - File: `/code/main.py`
    ```python
    @app.route("/updateConfig")
    def configure():
        """
        Reads a google sheet by name with the configuration translates it to json writes it to file and global variables
        Returns the new configuration as a json.
        """
        try:
          sheet=request.args.get("sheet_name")
          line=_load_config(sheet)
          return line
        except Exception as e:
          print(e)
          return "Loading Unsuccesful!"

    def _load_config(input_google_sheet_name:str)-> str:
        """
        Takes a google sheets name, transforms to json and updates configuration file and current variables
            params:
                input_google_sheet_name: String with the google sheets name.

            returns:
                New configuration json

        """
        # ... (rest of the _load_config function)
    ```
    - The `configure` function is mapped to the `/updateConfig` endpoint.
    - It directly retrieves the `sheet_name` from the request arguments using `request.args.get("sheet_name")`.
    - It calls the `_load_config` function with the user-provided `sheet_name` without any authentication or authorization checks.
    - The `_load_config` function then proceeds to fetch and load the configuration from the specified Google Sheet.
    - There are no checks in place to verify the legitimacy of the request or the source of the configuration sheet.

- Security test case:
    1. **Prerequisites:**
        - Deploy Project Cartesian to Cloud Run.
        - Obtain the Cloud Run service URL (e.g., `https://<cloud-run-url>/`).
        - Create a malicious Google Sheet with a modified configuration. For example, change `output_google_sheet_name` to a sheet you control. Name this sheet something simple, e.g., `attacker-config`. Share this sheet with "editor" role to the service account of the deployed application (as per setup instructions, although this is not strictly needed for *this* test case as we are exploiting lack of auth *before* sheet access).
    2. **Exploit:**
        - Open a terminal.
        - Execute the following `curl` command, replacing `<cloud-run-url>` with your Cloud Run service URL:
          ```bash
          curl "https://<cloud-run-url>/updateConfig?sheet_name=attacker-config"
          ```
        - Observe the response from the server. It should return the content of the attacker-controlled configuration sheet, indicating that the configuration has been loaded.
    3. **Verify Impact:**
        - Trigger the main application logic by either:
            - Waiting for the scheduled execution (if configured).
            - Manually calling the `/execute` endpoint:
              ```bash
              curl -H "Authorization: Bearer $(gcloud auth print-identity-token)" "https://<cloud-run-url>/execute"
              ```
        - Check the output Google Sheet specified in the attacker's configuration (`attacker-config` in this example). The feed data should now be written to this attacker-controlled sheet instead of the original intended sheet, demonstrating successful configuration modification and data redirection.
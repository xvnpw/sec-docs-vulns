### Vulnerabilities Found

This document outlines the identified vulnerabilities within the Project Cartesian application.

#### 1. Configuration Sheet Injection

* Vulnerability Name: Configuration Sheet Injection
* Description:
    An attacker can compromise the application by manipulating the optional configuration Google Sheet. The application's `/updateConfig` endpoint allows users to update the configuration by providing a Google Sheet name as a parameter. If an attacker gains knowledge of the Cloud Run endpoint URL, they can create a malicious Google Sheet with altered configurations and provide its name to the `/updateConfig` endpoint. The application will then fetch this malicious configuration and overwrite its local `config.json` file and in-memory parameters. This allows the attacker to inject arbitrary configurations into the application.

    Steps to trigger the vulnerability:
    1.  Attacker creates a Google Sheet containing malicious configurations. This could include changing the `output_google_sheet_name` to a sheet controlled by the attacker, or modifying other parameters like `bigquery_dataset`, `mc_fields`, or `attribute_filters` to alter data processing.
    2.  Attacker obtains the Cloud Run endpoint URL of the Project Cartesian instance. This URL might be discoverable through misconfiguration or information disclosure.
    3.  Attacker crafts a malicious URL by appending the `/updateConfig` endpoint path to the Cloud Run URL and adding a query parameter `sheet_name` set to the name of their malicious Google Sheet. For example: `https://CLOUD_RUN_ENDPOINT/updateConfig?sheet_name=ATTACKER_CONTROLLED_SHEET_NAME`.
    4.  Attacker sends a request to this crafted URL, for instance by using `curl` or simply opening the URL in a web browser.
    5.  The Project Cartesian application, upon receiving this request, will use the provided `sheet_name` to fetch the configuration from the attacker's Google Sheet, replacing its intended configuration.
    6.  When the application next executes its main function (either via scheduled run or manual trigger of `/execute`), it will operate using the attacker-injected malicious configuration.

* Impact:
    The impact of this vulnerability is significant:
    -   **Data Redirection/Exfiltration**: By modifying the `output_google_sheet_name` parameter in the malicious configuration sheet, the attacker can redirect the output of the data processing to a Google Sheet under their control. This allows the attacker to exfiltrate sensitive data from the Google Merchant Center, intended for the legitimate user's Google Sheet, to their own sheet.
    -   **Data Manipulation**: The attacker can alter other configuration parameters, such as `mc_fields`, `additional_columns`, and `attribute_filters`. This could lead to unintended or malicious modifications of the data processing logic. For example, the attacker could alter the columns included in the output feed, inject fabricated data through `additional_columns`, or filter out legitimate data by modifying `attribute_filters`. This could compromise the integrity of the dynamic creative feeds generated by Project Cartesian, leading to incorrect or misleading advertisements.

* Vulnerability Rank: High
* Currently Implemented Mitigations:
    There are no mitigations implemented in the provided project files to prevent this vulnerability. The `/updateConfig` endpoint directly loads and applies any Google Sheet configuration provided via the `sheet_name` parameter without any validation, authorization, or sanitization.
* Missing Mitigations:
    -   **Access Control for `/updateConfig` Endpoint**: The `/updateConfig` endpoint should be protected with authentication and authorization mechanisms. This would ensure that only authorized users (e.g., administrators) can trigger configuration updates. Currently, the endpoint appears to be publicly accessible, making it vulnerable to anyone who discovers the Cloud Run URL.
    -   **Input Validation for `sheet_name`**: The application should validate the `sheet_name` parameter to ensure it adheres to an expected format and does not contain malicious characters or excessively long names.
    -   **Configuration Validation**: After fetching the configuration from the Google Sheet, the application should validate the critical configuration parameters. This validation should include checks against expected data types, allowed values, and consistency. For example, it should verify that `output_google_sheet_name` is a valid sheet name, BigQuery dataset and table names conform to naming conventions, and Merchant Center ID is in the correct format. A whitelist of allowed values or a schema validation could be implemented.

* Preconditions:
    -   Attacker must be able to create and modify a Google Sheet.
    -   Attacker must obtain the Cloud Run endpoint URL for the Project Cartesian instance. This might be achieved through reconnaissance, misconfiguration, or accidental exposure.

* Source Code Analysis:
    1.  **Endpoint Definition**: In `main.py`, the `/updateConfig` endpoint is defined as a Flask route:
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
        ```
        This endpoint directly calls the `_load_config` function with the `sheet_name` parameter obtained from the request arguments. There is no input validation on `sheet_name` at this stage.

    2.  **`_load_config` Function**: The `_load_config` function in `main.py` is responsible for fetching and loading the configuration from the Google Sheet:
        ```python
        def _load_config(input_google_sheet_name:str)-> str:
            """
            Takes a google sheets name, transforms to json and updates configuration file and current variables
                params:
                    input_google_sheet_name: String with the google sheets name.

                returns:
                    New configuration json

            """
            global params
            global merchant_center_fields
            credentials, project_id = google.auth.default(
                scopes=GOOGLE_SHEETS_AUTH_SCOPES
            )
            client = gspread.authorize(credentials)
            try:
              spreadsheet=client.open(input_google_sheet_name)
            except gspread.exceptions.SpreadsheetNotFound :
              print("Configuration sheet does not exist!...")
              return "Configuration sheet does not exist!... Not updated"
            worksheet = spreadsheet.get_worksheet(0)
            list_of_lists = worksheet.get_all_values()
            config_json=_transform_config_to_json(list_of_lists)
            params=config_json
            merchant_center_fields=params["mc_fields"]
            f = open("config.json", "w")
            json.dump(config_json, f)
            f.close()
            a_file = open("config.json","r")
            Lines = a_file.readlines()
            for line in Lines:
              print(line)
            a_file.close()
            return line
        ```
        -   It retrieves the `input_google_sheet_name` which is directly passed from the `/updateConfig` endpoint's `sheet` variable.
        -   It authenticates with Google Sheets using service account credentials.
        -   Crucially, it uses `client.open(input_google_sheet_name)` to open the Google Sheet *without any validation* of the sheet name. This allows an attacker to provide any valid Google Sheet name.

* Security Test Case:
    1.  **Setup Attacker-Controlled Sheet**:
        -   Create a new Google Sheet named "MaliciousConfigSheet".
        -   In the first sheet, add "Parameter" and "Value" columns.
        -   Set `output_google_sheet_name` parameter to "AttackerOutputSheet" (create this sheet as well and share with attacker account).

    2.  **Get Cloud Run Endpoint**:
        -   Obtain the Cloud Run endpoint URL. Let's assume it is `https://projectcartesian-xyz-uc.a.run.app`.

    3.  **Exploit Execution**:
        -   Craft the malicious URL: `https://projectcartesian-xyz-uc.a.run.app/updateConfig?sheet_name=MaliciousConfigSheet`.
        -   Execute this URL using `curl`:
            ```bash
            curl "https://projectcartesian-xyz-uc.a.run.app/updateConfig?sheet_name=MaliciousConfigSheet"
            ```

    4.  **Trigger Data Processing**:
        -   Trigger data processing via `/execute` endpoint:
            ```bash
            curl -H "Authorization: Bearer $(gcloud auth print-identity-token)" "https://projectcartesian-xyz-uc.a.run.app/execute"
            ```

    5.  **Verify Data Redirection**:
        -   Check "AttackerOutputSheet" for redirected data feed.

#### 2. Insecure Storage of Service Account Credentials

* Vulnerability Name: Insecure Storage of Service Account Credentials
* Description:
    The project setup instructions guide users to download a service account JSON key file and place it directly into the `/code/` directory. The `config.json` file then points to this location for service account authentication. If an attacker gains access to the project code directory, they can easily retrieve the service account JSON key file and impersonate the service account, gaining unauthorized access to Google Cloud resources.

* Impact:
    Critical. Successful exploitation of this vulnerability allows an attacker to gain unauthorized access to sensitive Google Cloud resources, including Google Merchant Center data, BigQuery datasets, and Google Sheets. This could lead to data exfiltration, data manipulation, and disruption of operations.

* Vulnerability Rank: Critical
* Currently Implemented Mitigations:
    None. The project documentation explicitly instructs users to store the service account key file insecurely within the project directory.
* Missing Mitigations:
    -   **Secure Key Storage**: Implement secure storage for the service account key, such as using Google Cloud Secret Manager or storing the key file outside the application's code directory and accessing it via secure environment variables.
    -   **Secure Configuration Practices Documentation**: Update the project documentation to strongly discourage storing the service account key file in the project directory and provide guidance on secure key management.

* Preconditions:
    -   User has followed the insecure setup instructions and placed the service account JSON key file in the `/code/` directory.
    -   Attacker gains access to the Cloud Run instance or project's code repository.

* Source Code Analysis:
    1. **/code/README.md & /code/CONTRIBUTING.md:** Setup instructions in these files guide users to store the service account key file in `/code/`.
    2. **/code/config.json:**  `service_account_credentials_path` parameter points to the insecurely stored key file.
    3. **/code/service_account_authenticator.py:**
        ```python
        params = Utilities.load_config('config.json')
        json_name=str(params["service_account_credentials_path"])
        class Service_Account_Authenticator:
          def __init__(self,scope:list):
            self.credentials_json=json_name # Vulnerable: Reads key path from config
            self.scope=scope
            self.service_account_credentials=self.authenticate()
          def authenticate(self):
            credentials = ServiceAccountCredentials.from_json_keyfile_name(self.credentials_json, self.scope) # Vulnerable: Loads key from insecure path
            return credentials
        ```
        The code reads the key file path from `config.json` and uses it to load credentials, directly using the insecurely stored key.

* Security Test Case:
    1. Deploy Project Cartesian to Cloud Run with insecure key storage as per instructions.
    2. Gain shell access to the running Cloud Run container (e.g., using `kubectl exec` in Cloud Shell).
    3. Navigate to `/app` directory.
    4. List files and identify the service account JSON key file.
    5. Read the key file content using `cat <YOUR_SERVICE_ACCOUNT_JSON_FILE_NAME>.json`.
    6. Copy the JSON key content.
    7. Outside the container, set `GOOGLE_APPLICATION_CREDENTIALS_JSON` environment variable to the copied key content.
    8. Use `gcloud bq datasets list --project=$GCP_PROJECT` to verify unauthorized access to BigQuery datasets using the compromised key.
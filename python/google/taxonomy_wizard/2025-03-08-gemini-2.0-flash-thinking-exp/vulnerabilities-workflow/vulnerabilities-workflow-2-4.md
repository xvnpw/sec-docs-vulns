- Vulnerability Name: Insecure Access to Configurator and Validator Cloud Functions
- Description:
    1. The `deploy.sh`, `resources/python_cloud_functions/configurator/deploy.sh`, and `resources/python_cloud_functions/validator/deploy.sh` scripts deploy the Configurator and Validator Cloud Functions with the `--no-allow-unauthenticated` flag.
    2. This flag, by default, should restrict access to authenticated requests only, requiring valid Identity and Access Management (IAM) authentication.
    3. However, the provided scripts configure these Cloud Functions to be invoked by service accounts (`taxonomy-wizard-configurator` and `taxonomy-wizard-validator`) and by Google Cloud Scheduler using OIDC authentication.
    4. **Missing**: There is no explicit enforcement of authentication or authorization within the `handle_request` functions in `resources/python_cloud_functions/configurator/main.py` and `resources/python_cloud_functions/validator/main.py`.
    5. **Vulnerability**: If the Cloud Function's IAM policy is misconfigured or unintentionally allows public access (e.g., due to overly permissive roles granted during initial setup or later modifications outside of these scripts), an attacker could potentially bypass authentication and directly invoke these functions.
    6. **Exploit Scenario**: An attacker discovers the Cloud Function URLs (e.g., through misconfiguration or information disclosure). The attacker sends crafted HTTP requests to the Configurator or Validator endpoints without proper authentication. If the IAM policy is weak, the Cloud Function executes the request.

- Impact:
    - **Configurator**: Unauthorized access to the Configurator Cloud Function could allow an attacker to manipulate taxonomy configurations, potentially injecting malicious or non-compliant naming conventions into the system. This could lead to the generation of incorrect validation rules, bypassing intended taxonomy enforcement, and allowing non-compliant or malicious campaign names to be accepted by the validator and propagated to Google advertising platforms.
    - **Validator**: Unauthorized access to the Validator Cloud Function could allow an attacker to trigger validation processes arbitrarily or bypass validation checks altogether. They might be able to inject data directly for validation, potentially manipulating validation results or exploiting vulnerabilities in the validation logic if any exist.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - The deployment scripts use `--no-allow-unauthenticated` to restrict access to authenticated principals.
    - Service accounts and OIDC for Cloud Scheduler are configured for function invocation.
- Missing Mitigations:
    - Explicit authentication and authorization checks within the `handle_request` functions in `configurator/main.py` and `validator/main.py` to verify the identity and permissions of the caller, regardless of IAM policy.
    - Robust input validation and sanitization within the `handle_request` functions to prevent injection attacks even if authentication is bypassed.
    - Regular audits of IAM policies on the Cloud Functions to ensure they are correctly configured and not overly permissive.
- Preconditions:
    - The Taxonomy Wizard is deployed.
    - The IAM policy for the Configurator or Validator Cloud Function is misconfigured to allow unintended access, or an attacker finds a way to bypass the intended authentication mechanism (though not evident from code).
    - The attacker needs to know or discover the Cloud Function URL.
- Source Code Analysis:
    - **`deploy.sh`, `resources/python_cloud_functions/configurator/deploy.sh`, `resources/python_cloud_functions/validator/deploy.sh`**: These scripts use `--no-allow-unauthenticated` during Cloud Function deployment, which is a basic IAM mitigation. They also configure service accounts for function execution and Cloud Scheduler for automated validation.
    - **`resources/python_cloud_functions/validator/main.py` and `resources/python_cloud_functions/configurator/main.py`**: The `handle_request` functions are the entry points for HTTP requests to the Cloud Functions. There is **no code** within these functions to explicitly check for authentication or authorization. The functions directly process the `action` and `payload` from the request.

    ```python
    # resources/python_cloud_functions/validator/main.py
    def handle_request(request: flask.Request):
      """Validation of request and creation of task.

      Args:
          request: Request object.

      Returns:
          Successful start response or error response.
      """
      try:
        action: str = request.args.get('action') # Directly using request parameters
        payload: Mapping[str:Sequence[NamesInput] | str] = request.get_json() # Directly using request payload
        project_id: str = payload['taxonomy_cloud_project_id']
        dataset: str = payload['taxonomy_bigquery_dataset']

        if action == 'list_specs':
          return list_specs(project_id, dataset)
        # ... other actions ...
      except Exception as e:
        err = f'Invocation failed with error: {str(e)}'
        logging.error(err)
        return err, 400, None
    ```
    - **Visualization**:
        ```mermaid
        graph LR
            A[External Attacker] --> B{Cloud Function URL};
            B --> C[Cloud Function Endpoint (Validator/Configurator)];
            C --> D{handle_request Function};
            D -- No Authentication Check --> E[Process Request];
            E --> F[BigQuery/Google Ads Platform];
        ```

- Security Test Case:
    1. Deploy Taxonomy Wizard using `deploy.sh`.
    2. Obtain the Configurator Cloud Function Endpoint URL after deployment (as shown in the script output or from Google Cloud Console).
    3. Using `curl` or a similar HTTP client, send a POST request to the Configurator Cloud Function endpoint without any authentication headers (e.g., no `Authorization` header). For example, to trigger the 'overwrite' action:

       ```bash
       curl -X POST \
         <CONFIGURATOR_CLOUD_FUNCTION_ENDPOINT>?action=overwrite \
         -H 'Content-Type: application/json' \
         -d '{
               "taxonomy_cloud_project_id": "<YOUR_PROJECT_ID>",
               "taxonomy_bigquery_dataset": "taxonomy_wizard",
               "data": [
                 {
                   "type": "TaxonomyField",
                   "data": []
                 },
                 {
                   "type": "TaxonomySpec",
                   "data": []
                 },
                 {
                   "type": "TaxonomyDimension",
                   "data": []
                 }
               ]
             }'
       ```
    4. Observe the response. If the request is processed successfully (you get a `200` response with `{'response': 'Successfully generated tables.'}` or a similar success message), it indicates that the Cloud Function is accessible without proper authentication, confirming the vulnerability.
    5. Repeat steps 2-4 for the Validator Cloud Function Endpoint, using a valid 'action' and minimal payload to test unauthenticated access. For example, to test 'list_specs' action:

       ```bash
       curl -X GET \
         "<VALIDATOR_CLOUD_FUNCTION_ENDPOINT>?action=list_specs&taxonomy_cloud_project_id=<YOUR_PROJECT_ID>&taxonomy_bigquery_dataset=taxonomy_wizard"
       ```
    6. If you receive a list of specs (or an empty list but a `200` OK response), it confirms unauthenticated access to the Validator function.

This test case verifies if an external attacker can access and trigger the Cloud Functions without authentication, exploiting a potential misconfiguration in IAM or a lack of explicit authentication checks in the code.
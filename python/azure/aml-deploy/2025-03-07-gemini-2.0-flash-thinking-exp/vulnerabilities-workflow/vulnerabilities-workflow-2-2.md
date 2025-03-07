- Vulnerability Name: Insecure Model Endpoint Exposure due to Disabled Authentication
- Description:
  - The Azure Machine Learning Deploy GitHub Action allows users to deploy machine learning models as web service endpoints on Azure Container Instances (ACI) or Azure Kubernetes Service (AKS).
  - By default, when deploying to ACI, the `authentication_enabled` parameter is set to `false`. This configuration can also be explicitly set by the user in the `deploy.json` parameters file or through action inputs.
  - When `authentication_enabled` is false, the deployed web service endpoint is publicly accessible without any authentication required.
  - An attacker can discover the scoring URI of the deployed service (which is outputted by the GitHub Action as `service_scoring_uri`).
  - The attacker can then send requests to this URI to query the machine learning model and obtain predictions without any authorization.
  - This is done by sending a POST request to the scoring URI with input data in the format expected by the model.
- Impact:
  - Unauthorized access to the machine learning model deployed as a web service.
  - Confidentiality breach of the machine learning model and its prediction logic.
  - Potential misuse of the machine learning model for malicious purposes.
  - Data exfiltration if the model processes or reveals sensitive information in its predictions.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
  - For AKS deployments, `authentication_enabled` defaults to `true`, enabling key-based authentication by default.
  - The documentation in `README.md` mentions the `authentication_enabled` parameter and its default values for ACI and AKS.
  - The documentation implicitly warns about the risk by stating "Whether or not to enable key auth for this Webservice." and providing default values.
- Missing Mitigations:
  - **Stronger Warning in Documentation:** The documentation should explicitly highlight the security risk of disabling authentication for ACI deployments and recommend enabling authentication for production environments.
  - **Default to Secure Configuration for ACI:** Consider changing the default value of `authentication_enabled` to `true` for ACI deployments to enforce authentication by default. Alternatively, provide a clear and prominent warning during ACI deployment when authentication is disabled.
  - **Security Best Practices Guidance:** Include a section in the documentation outlining security best practices for deploying ML models, emphasizing the importance of authentication and authorization.
- Preconditions:
  - The user must deploy a machine learning model using the Azure Machine Learning Deploy GitHub Action.
  - The deployment must be to Azure Container Instances (ACI).
  - The `authentication_enabled` parameter must be set to `false` (either explicitly or by default).
- Source Code Analysis:
  - **`action.yml`:** Defines the inputs for the GitHub Action, including parameters related to deployment.
  - **`README.md`:** Documents the usage of the action and describes the `authentication_enabled` parameter, noting the default value for ACI as `false` and AKS as `true`. It also mentions the parameter description "Whether or not to enable key auth for this Webservice."
  - **`code/main.py`:**
    - The `main()` function reads the `authentication_enabled` parameter from the `parameters` dictionary, which is loaded from the `deploy.json` file or defaults.
    - For ACI deployments, the `AciWebservice.deploy_configuration()` function is called.
    - ```python
      deployment_config = AciWebservice.deploy_configuration(
          # ... other parameters ...
          auth_enabled=parameters.get("authentication_enabled", None),
          # ... other parameters ...
      )
      ```
    - The `auth_enabled` parameter in `AciWebservice.deploy_configuration()` directly controls whether authentication is enabled for the deployed ACI web service.
    - If `parameters.get("authentication_enabled", None)` evaluates to `None` or `False`, and no environment variable overrides it, the ACI endpoint will be deployed without authentication, as the default for ACI in Azure ML SDK is to disable authentication.
    - The code does not enforce authentication or provide any warnings if authentication is disabled for ACI deployments.
- Security Test Case:
  - Step 1: Create a `deploy.json` file in your repository (e.g., `.cloud/.azure/deploy.json`) with the following content to explicitly disable authentication for ACI deployment:
    ```json
    {
      "authentication_enabled": false
    }
    ```
  - Step 2: Configure a GitHub Actions workflow to use the `Azure/aml-deploy@v1` action to deploy a registered model to ACI. Ensure that the workflow uses the `deploy.json` file created in Step 1.
  - Step 3: Run the GitHub Actions workflow. Once the deployment is successful, note the `service_scoring_uri` output from the `aml-deploy` action.
  - Step 4: Use `curl` or a similar tool to send a POST request to the `service_scoring_uri` without providing any authentication keys or tokens. For example:
    ```bash
    curl -X POST -H "Content-Type: application/json" -d '{"data": [[1,2,3,4]]}' <service_scoring_uri>
    ```
    Replace `<service_scoring_uri>` with the actual scoring URI obtained from the GitHub Actions output. The input data `{"data": [[1,2,3,4]]}` is a sample input; adjust it based on the expected input format of your deployed model.
  - Step 5: Observe the response. If the vulnerability exists, the request will be successful, and you will receive a prediction from the machine learning model without any authentication. This confirms that the endpoint is publicly accessible and vulnerable to unauthorized access.
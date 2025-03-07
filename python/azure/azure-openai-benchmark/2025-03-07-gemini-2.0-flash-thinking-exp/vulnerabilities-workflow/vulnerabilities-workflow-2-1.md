### Vulnerability List

- **Vulnerability Name:** Insecure Storage of Azure OpenAI API Key
- **Description:** The Azure OpenAI benchmarking tool instructs users to store their Azure OpenAI API key in the `OPENAI_API_KEY` environment variable as part of the setup process. This practice, while convenient for testing, can lead to unintentional exposure of the API key if users are not careful about managing their environment variables securely. An attacker who gains access to the exposed API key can then make unauthorized calls to the victim's Azure OpenAI service.
    1. User follows the setup instructions in the README.md, which recommends setting the `OPENAI_API_KEY` environment variable.
    2. User insecurely manages the environment variable, for example by:
        - Hardcoding the API key directly into scripts used to run the benchmark tool.
        - Committing scripts containing the API key to version control systems (e.g., Git).
        - Exposing the API key in CI/CD pipeline logs or configuration files.
        - Leaving the environment variable set in shared or publicly accessible environments.
    3. An attacker gains access to the exposed API key through one of the insecure management practices mentioned above.
    4. The attacker uses the stolen `OPENAI_API_KEY` to authenticate against the victim's Azure OpenAI service.
    5. The attacker can now make unauthorized requests to the Azure OpenAI API, potentially incurring costs for the victim, accessing deployed models, and potentially causing data breaches depending on the models and data accessed.
- **Impact:** Unauthorized access and usage of the victim's Azure OpenAI service. This can lead to:
    - **Financial costs:** Unauthorized usage of the Azure OpenAI service will be billed to the victim's Azure subscription.
    - **Data breaches:** Depending on the models deployed and the attacker's actions, sensitive data could be accessed or manipulated.
    - **Reputational damage:** If the unauthorized access is publicly disclosed, it can damage the victim's reputation.
- **Vulnerability Rank:** High
- **Currently Implemented Mitigations:**
    - **Warning in README.md:** The README.md includes a warning: "> :warning: **Code in this repo is written for testing purposes and should not be used in production**". This implicitly suggests caution but does not specifically address API key security.
    - **Security Reporting Guidelines:** The `SECURITY.md` file provides guidelines for reporting security vulnerabilities to Microsoft Security Response Center, indicating a commitment to security.
- **Missing Mitigations:**
    - **Explicit Security Warning in README.md:** The README.md should include a clear and explicit warning about the security risks of storing API keys in environment variables, even for testing purposes. This warning should advise users against insecure practices and recommend more secure alternatives.
    - **Recommendations for Secure API Key Management:** The README.md should suggest secure alternatives for managing API keys, especially for non-testing or more sensitive environments. Examples include:
        - Using secrets management tools like Azure Key Vault.
        - Storing the API key in a configuration file with restricted permissions, instead of environment variables.
        - For local testing, advising users to use environment variables only temporarily and to unset them after use.
    - **Code-Level Mitigation (Optional but Recommended):** Consider adding functionality to the tool to support reading the API key from more secure sources beyond just environment variables. This could include:
        - Reading from Azure Key Vault directly (if applicable to the intended users).
        - Supporting configuration files with restricted access.
- **Preconditions:**
    - The user must follow the setup instructions in the README.md and choose to use environment variables for API key management.
    - The user must then insecurely manage the `OPENAI_API_KEY` environment variable, making it accessible to potential attackers.
- **Source Code Analysis:**
    - **`benchmark/loadcmd.py`**:
        ```python
        api_key = os.getenv(args.api_key_env) # line 70
        ```
        This line in `loadcmd.py` retrieves the API key from the environment variable specified by the `--api-key-env` argument, which defaults to `OPENAI_API_KEY`. This is the primary point where the API key is accessed from the environment.
    - **`benchmark/oairequester.py`**:
        ```python
        class OAIRequester:
            """
            ...
            :param api_key: Azure OpenAI resource endpoint key.
            :param url: ...
            """
            def __init__(self, api_key: str, url: str, backoff=False): # line 36
                self.api_key = api_key # line 37
                self.url = url # line 38
                self.backoff = backoff # line 39

            async def _call(self, session:aiohttp.ClientSession, body: dict, stats: RequestStats): # line 71
                headers = {
                    "api-key": self.api_key, # line 73
                    "Content-Type": "application/json", # line 74
                    TELEMETRY_USER_AGENT_HEADER: USER_AGENT, # line 75
                }
                ...
                response = await session.post(self.url, headers=headers, json=body) # line 79
                ...
        ```
        The `OAIRequester` class stores the API key and uses it in the `api-key` header for each HTTP request to the Azure OpenAI API.
    - **`README.md`**:
        ```markdown
        2. Your resource endpoint and access key. The script assumes the key is stored in the following environment variable: ```OPENAI_API_KEY```. For more information on finding your endpoint and key, see the [Azure OpenAI Quickstart](https://learn.microsoft.com/azure/ai-services/openai/quickstart?tabs=command-line&pivots=programming-language-python#retrieve-key-and-endpoint).
        ```
        This section in the README explicitly instructs users to store the API key in the `OPENAI_API_KEY` environment variable without sufficient security warnings.

- **Security Test Case:**
    1. **Initial Setup:** Ensure the `OPENAI_API_KEY` environment variable is **not** set in your testing environment.
    2. **Run Benchmark Tool without API Key:** Execute the benchmark tool using the `load` command as described in the README, providing a valid Azure OpenAI endpoint and deployment name.
        ```bash
        python -m benchmark.bench load --deployment <your-deployment-name> https://<your-aoai-endpoint>.openai.azure.com
        ```
    3. **Verify Error Message:** Observe the output of the benchmark tool. It should fail to authenticate and display an error message indicating that the `OPENAI_API_KEY` environment variable is missing or invalid. This confirms that the tool relies on this environment variable for authentication.
    4. **Simulate API Key Exposure:**
        - **Manually set the `OPENAI_API_KEY` environment variable** with a valid Azure OpenAI API key for your test resource.
        - **Capture Network Request:** Use a network interception tool (like `tcpdump`, Wireshark, or browser developer tools if applicable) or a proxy to capture the HTTP requests made by the benchmark tool.
        - **Run the Benchmark Tool Again:** Execute the same benchmark command as in step 2.
        - **Inspect Captured Request:** Examine the captured HTTP request. Verify that the `api-key` header is present in the request and contains the value of the `OPENAI_API_KEY` environment variable you set. This confirms that the API key is transmitted in the HTTP header.
    5. **Unauthorized Access (Manual Verification):**
        - **Extract API Key:** Obtain the API key value from the `OPENAI_API_KEY` environment variable you set in step 4.
        - **Use `curl` to Simulate Attack:** Use `curl` or a similar HTTP client to make a direct request to the Azure OpenAI API, using the extracted API key for authentication. For example:
        ```bash
        curl -X POST https://<your-aoai-endpoint>.openai.azure.com/openai/deployments/<your-deployment-name>/chat/completions?api-version=2023-05-15 \
          -H "Content-Type: application/json" \
          -H "api-key: <your-extracted-api-key>" \
          -d '{"messages":[{"role": "user", "content": "This is a test."}]}'
        ```
        - **Verify Unauthorized Access:** If the `curl` command successfully returns a response from the Azure OpenAI API, it demonstrates that an attacker with the exposed API key can indeed make unauthorized requests and access the service, confirming the vulnerability.

This test case demonstrates how the API key is used by the tool and how an exposed API key can be used for unauthorized access, validating the "Insecure Storage of Azure OpenAI API Key" vulnerability.
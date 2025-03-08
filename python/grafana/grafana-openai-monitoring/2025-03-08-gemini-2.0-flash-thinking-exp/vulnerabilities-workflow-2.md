## Vulnerability: Hardcoded Credentials in Usage Examples

This vulnerability arises from insecure examples provided in the documentation of the `grafana-openai-monitoring` library. The README files in both Python and JavaScript offer usage examples that include placeholders for sensitive credentials. If developers follow these examples and directly replace the placeholders with their actual credentials in the application code, these credentials can be unintentionally exposed. This exposure can occur if the code is committed to a public repository, shared insecurely, or even left in easily accessible locations on a server.

### Vulnerability Name
Hardcoded Credentials in Usage Examples

### Description
The README files in both Python and JavaScript provide usage examples that include placeholders for sensitive credentials such as:
- OpenAI API keys (`YOUR_OPENAI_API_KEY`)
- Grafana Cloud Prometheus URLs (`YOUR_PROMETHEUS_METRICS_URL`)
- Grafana Cloud Loki URLs (`YOUR_LOKI_LOGS_URL`)
- Grafana Cloud Metrics usernames (`YOUR_METRICS_USERNAME`)
- Grafana Cloud Logs usernames (`YOUR_LOGS_USERNAME`)
- Grafana Cloud Access Tokens (`YOUR_ACCESS_TOKEN`)

If developers directly copy and paste these examples and replace the placeholders with their actual credentials directly in the application code, these credentials can be unintentionally exposed. This exposure can occur if the code is committed to a public repository, shared insecurely, or even left in easily accessible locations on a server.

### Impact
Exposure of sensitive credentials (OpenAI API keys and Grafana Cloud access tokens).
This can lead to:
- **Unauthorized access to OpenAI APIs**: Attackers could use the exposed OpenAI API keys to make requests to the OpenAI API on behalf of the victim, potentially incurring costs and accessing sensitive data or models.
- **Unauthorized access to Grafana Cloud resources**: Exposed Grafana Cloud access tokens, usernames, and URLs could allow attackers to access Grafana Cloud dashboards, metrics, and logs. This could lead to data breaches, modification of dashboards, or disruption of monitoring services.

### Vulnerability Rank
High

### Currently Implemented Mitigations
None in the provided code.

### Missing Mitigations
- **Strong warning in documentation**: The documentation (especially README files and configuration sections) should include a prominent warning against hardcoding sensitive credentials directly into the application code. This warning should be placed near the usage examples.
- **Best practices for credential management**: The documentation should recommend secure methods for managing sensitive credentials, such as:
  - Using environment variables to store credentials outside of the codebase.
  - Utilizing configuration files that are not committed to version control.
  - Employing secrets management systems (e.g., HashiCorp Vault, AWS Secrets Manager) for more secure storage and retrieval of credentials, although this might be an over-complication for basic usage.
- **Example code improvements**: The usage examples in README files and documentation should be modified to demonstrate loading credentials from environment variables instead of showing placeholders for direct replacement. For example, in Python:

  ```python
  import os
  from openai import OpenAI
  from grafana_openai_monitoring import chat_v2

  client = OpenAI(
      api_key=os.getenv("OPENAI_API_KEY"),
  )

  client.chat.completions.create = chat_v2.monitor(
      client.chat.completions.create,
      metrics_url=os.getenv("PROMETHEUS_URL"),
      logs_url=os.getenv("LOKI_URL"),
      metrics_username=os.getenv("PROMETHEUS_USERNAME"),
      logs_username=os.getenv("LOKI_USERNAME"),
      access_token=os.getenv("GRAFANA_CLOUD_ACCESS_TOKEN")
  )
  ```
  And similarly for JavaScript examples, using `process.env`.

### Preconditions
- Developers follow the usage examples provided in the README files.
- Developers directly replace the placeholder credentials in the example code with their actual sensitive credentials.
- The application code containing the hardcoded credentials is then exposed, for example:
  - Committed to a public version control repository (like GitHub).
  - Stored in an unencrypted or publicly accessible location.
  - Shared insecurely via email, chat, or other communication channels.

### Source Code Analysis
1. **README.md (Python and Node.js):**
   - Both `/code/README.md`, `/code/python/README.md`, and `/code/node/README.md` files contain "Usage" sections with code examples.
   - These examples are intended to demonstrate how to use the `grafana-openai-monitoring` library in Python and JavaScript.
   - In the code examples, placeholders like `apiKey: 'YOUR_OPENAI_API_KEY'` and similar placeholders for Grafana Cloud credentials are explicitly used within the code itself.
   - For example, in `/code/python/README.md`:
     ```python
     client = OpenAI(
         api_key="YOUR_OPENAI_API_KEY",
     )

     client.chat.completions.create = chat_v2.monitor(
         client.chat.completions.create,
         metrics_url="YOUR_PROMETHEUS_METRICS_URL",
         logs_url="YOUR_LOKI_LOGS_URL",
         metrics_username="YOUR_METRICS_USERNAME",
         logs_username="YOUR_LOGS_USERNAME",
         access_token="YOUR_ACCESS_TOKEN"
     )
     ```
   - Similar examples are present in the JavaScript README.md files.
2. **Lack of explicit warning:**
   - While the "Configuration" sections in the README files mention "Replace this with your actual...", there is no explicit and strong warning against hardcoding these values directly in the code, nor are secure alternatives clearly presented in the immediate context of the usage examples.

   **Visualization:**

   ```
   README.md (Usage Example) --> Contains hardcoded credential placeholders
                                   |
                                   V
   Developer copies example   --> Replaces placeholders with actual credentials
                                   |
                                   V
   Application Code         --> Contains HARDCODED CREDENTIALS
                                   |
                                   V (If code is exposed publicly)
   Credential Exposure      --> Attackers can potentially access credentials
   ```

### Security Test Case
1. **Setup a public repository:**
   - Create a new public repository on a platform like GitHub (e.g., `test-openai-monitoring-exposure`).
2. **Create a Python application file:**
   - In the repository, create a Python file (e.g., `main.py`).
   - Copy the Python usage example for `chat_v2.monitor` from `/code/python/README.md` into `main.py`.
   - **Intentionally hardcode credentials:** Replace the placeholders in `main.py` with **your actual** OpenAI API key and Grafana Cloud credentials.
     ```python
     import os
     from openai import OpenAI
     from grafana_openai_monitoring import chat_v2

     client = OpenAI(
         api_key="YOUR_OPENAI_API_KEY_VALUE", # Replace with your actual OpenAI API key
     )

     client.chat.completions.create = chat_v2.monitor(
         client.chat.completions.create,
         metrics_url="YOUR_PROMETHEUS_METRICS_URL_VALUE", # Replace with your actual Prometheus URL
         logs_url="YOUR_LOKI_LOGS_URL_VALUE", # Replace with your actual Loki URL
         metrics_username="YOUR_METRICS_USERNAME_VALUE", # Replace with your actual Metrics username
         logs_username="YOUR_LOGS_USERNAME_VALUE", # Replace with your actual Logs username
         access_token="YOUR_ACCESS_TOKEN_VALUE" # Replace with your actual Access Token
     )

     response = client.chat.completions.create(model="gpt-3.5-turbo", messages=[{"role": "user", "content": "Hello"}])
     print(response)
     ```
   - **Important:** Use *test* credentials if possible, or be aware of the risks of exposing real credentials, even for testing. For this test case, the goal is to demonstrate the *possibility* of exposure, not necessarily to actively exploit it.
3. **Commit and push the code:**
   - Initialize a Git repository in the project directory (if not already).
   - Add `main.py` to the repository: `git add main.py`
   - Commit the changes: `git commit -m "Hardcoded credentials example"`
   - Push the repository to your public GitHub repository: `git push origin main`
4. **Public Exposure Verification (Simulate Attacker):**
   - **Access the public repository:** As an "attacker" (or simply using a different browser/account), go to the public GitHub repository you created (`test-openai-monitoring-exposure`).
   - **Browse the code:** Navigate to `main.py` in the repository.
   - **Verify exposed credentials:** Observe that the OpenAI API key and Grafana Cloud credentials you hardcoded in step 2 are now publicly visible in the `main.py` file in your public GitHub repository.

This test case demonstrates how easily credentials can be exposed if developers follow the README usage examples without proper security awareness and best practices for credential management.
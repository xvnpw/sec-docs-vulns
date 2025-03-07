### Vulnerability List:

- Vulnerability Name: Plaintext Storage of Credentials in Container Configuration File
- Description:
  1. The `setup.sh` script is executed during container startup as part of the data loading process.
  2. This script configures the `osducli` tool by creating a configuration file at `$HOME/.osducli/config`.
  3. Within `setup.sh`, the values of environment variables `REFRESH_TOKEN`, `CLIENT_ID`, and `CLIENT_SECRET` are directly embedded into this configuration file in plaintext.
  4. This configuration file resides within the container's filesystem.
  5. An attacker who gains unauthorized access to the container, its filesystem, or container logs (if configuration file content is logged) can read this file and extract the plaintext credentials.
  6. With these credentials, the attacker can authenticate to the OSDU instance and perform unauthorized actions, potentially gaining full access to the data partition.
- Impact:
  - Critical. Exposure of `CLIENT_SECRET` and `REFRESH_TOKEN` allows an attacker to bypass authentication and authorization mechanisms.
  - An attacker can gain unauthorized access to the target OSDU instance.
  - Data within the OSDU instance could be compromised, modified, or deleted.
  - The attacker could potentially escalate privileges within the OSDU environment depending on the permissions associated with the compromised credentials.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations:
  - None. The project directly embeds secrets into a configuration file within the container image during setup.
- Missing Mitigations:
  - **Secure Secret Storage:** Implement a secure method for managing and injecting secrets, such as using Azure Key Vault or a similar secrets management service. Secrets should not be stored in plaintext within the container image or configuration files.
  - **Environment Variable Injection at Runtime:** Instead of embedding secrets in the configuration file during image build or initial setup, the application should be designed to retrieve credentials from environment variables only at runtime when the container is started. This prevents secrets from being persisted within the container image itself.
  - **Principle of Least Privilege:** Ensure that the credentials used for data loading have the minimum necessary permissions required for the task. Avoid using highly privileged accounts for routine data loading operations.
  - **Regular Credential Rotation:** Implement a policy for regular rotation of credentials to limit the window of opportunity in case of a compromise.
- Preconditions:
  - The user must utilize the "Developer Persona" method for data loading, which involves using the provided Docker container and running the `load.sh` script.
  - The user must have set the environment variables `REFRESH_TOKEN`, `CLIENT_ID`, and `CLIENT_SECRET` as instructed in the "Developer Persona" documentation.
  - An attacker must gain unauthorized access to the running container instance or its filesystem or logs.
- Source Code Analysis:
  1. **File: `/code/load.sh`**: This script is the main entry point for the data loading process. It calls `setup.sh` and other scripts.
  ```bash
  #!/usr/bin/env bash
  # ...
  ConfigureIni;
  # ...
  ```
  2. **File: `/code/setup.sh`**: This script is responsible for configuring the `osducli` tool.
  ```bash
  #!/usr/bin/env bash
  # ...
  CONFIG_FILE=$HOME/.osducli/config

  cat > $CONFIG_FILE << EOF
  [core]
  server = ${OSDU_ENDPOINT}
  # ...
  authentication_mode = refresh_token
  token_endpoint = https://login.microsoftonline.com/${AZURE_TENANT}/oauth2/v2.0/token
  refresh_token = ${REFRESH_TOKEN}
  client_id = ${CLIENT_ID}
  client_secret = ${CLIENT_SECRET}
  EOF

  chmod 600 $CONFIG_FILE
  ```
  **Visualization:**

  ```
  load.sh --> ConfigureIni() --> setup.sh
                                    |
                                    | Creates $HOME/.osducli/config with plaintext credentials
                                    V
  Container Filesystem <-------------------- Plaintext Credentials Stored Here
  ```

  **Explanation:**
  - The `load.sh` script executes the `ConfigureIni` function, which in turn calls `setup.sh`.
  - `setup.sh` directly writes the values of `${REFRESH_TOKEN}`, `${CLIENT_ID}`, and `${CLIENT_SECRET}` into the configuration file `$CONFIG_FILE` using a `cat` command with a heredoc (`EOF`).
  - The configuration file is created with `chmod 600`, limiting access to the user within the container, but it still stores the secrets in plaintext within the container's filesystem, making them vulnerable if the container is compromised.
- Security Test Case:
  1. **Prerequisites:**
     - Follow the "Developer Persona" instructions in `README.md` to set up the development environment, including building and running the Docker container.
     - Ensure you have set the environment variables `AZURE_TENANT`, `CLIENT_ID`, `CLIENT_SECRET`, and `REFRESH_TOKEN` as instructed.
     - Run the container, for example using `docker run -it --rm --env-file .env -v $(pwd)/open-test-data:/app/open-test-data -v $(pwd)/output:/app/output osdu-data-load /bin/bash`. This will give you an interactive shell inside the running container.
  2. **Access Container Shell:** Execute the `docker run` command above to get a shell inside the container.
  3. **Navigate to Configuration Directory:** Inside the container shell, navigate to the home directory: `cd /app`.
  4. **Inspect Configuration File:** View the content of the `osducli` configuration file using `cat /home/app/.osducli/config`.
  5. **Verify Plaintext Credentials:** Observe the output of the `cat` command. You will see the `refresh_token`, `client_id`, and `client_secret` values are stored in plaintext within the configuration file.
  6. **(Optional) Simulate Credential Usage:**  You can further verify the vulnerability by using the extracted `CLIENT_ID`, `CLIENT_SECRET`, and `REFRESH_TOKEN` with `osducli` commands within the container to access the OSDU instance, demonstrating unauthorized access is possible with these leaked credentials. For example, try to list storage containers using `osdu storage container list`.

This test case demonstrates that an attacker gaining access to the container can easily retrieve the plaintext credentials from the configuration file.
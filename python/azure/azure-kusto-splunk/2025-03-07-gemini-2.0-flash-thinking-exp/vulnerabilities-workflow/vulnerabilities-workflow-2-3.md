### Vulnerability List

- Vulnerability Name: Insecure Storage of Azure Data Explorer Credentials
- Description:
    1. The application stores Azure Data Explorer credentials, specifically the `client_secret`, in plaintext within the `config.yml` configuration file.
    2. An attacker gains unauthorized access to the file system where the `config.yml` file is located. This could be achieved through various methods, such as exploiting other vulnerabilities in the system, insider threats, or misconfiguration of access controls on the server or container where the application is deployed.
    3. The attacker reads the `config.yml` file.
    4. The attacker extracts the plaintext `client_secret` from the `config.yml` file.
    5. Using the obtained `client_secret`, along with other parameters like `client_id`, `tenant_id`, and `ingest_url` which are also available in the same `config.yml`, the attacker can successfully authenticate to the targeted Azure Data Explorer cluster.
    6. Once authenticated, the attacker can perform unauthorized actions on the Azure Data Explorer cluster. The extent of these actions depends on the permissions associated with the compromised credentials, potentially including reading sensitive data, modifying or deleting critical information, or disrupting the service.
- Impact: Critical. Successful exploitation of this vulnerability leads to unauthorized access to the Azure Data Explorer cluster. This can result in severe consequences, including data breaches, data manipulation, data loss, and service disruption, depending on the permissions associated with the compromised credentials.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations: None. The application stores the `client_secret` in plaintext directly within the `config.yml` file. There are no mechanisms in place to encrypt or securely store these sensitive credentials.
- Missing Mitigations:
    - Implement secure credential storage: The application should utilize secure methods for storing sensitive credentials instead of plaintext configuration files. Options include:
        - Using a dedicated secrets management service like Azure Key Vault to store and retrieve credentials.
        - Employing environment variables to inject credentials at runtime, avoiding storage in configuration files.
        - Encrypting the `config.yml` file or specific credential values within it using robust encryption algorithms and securely managing the encryption keys.
    - Implement file system access controls: Restrict access to the `config.yml` file and the application's deployment environment to only authorized users and processes. This can be achieved through proper file permissions in the operating system or container environment. Regularly review and enforce these access controls.
- Preconditions:
    - The `SplunkADXForwarder` application must be deployed and configured to use Azure Data Explorer, with the Azure Data Explorer credentials (including `client_secret`) configured in the `config.yml` file.
    - An attacker must be able to gain unauthorized access to the file system where the `config.yml` file is stored. This could be the server where the application is running, a container image, or a shared storage volume.
- Source Code Analysis:
    - File: `/code/SplunkADXForwarder/config.yml`
        ```yaml
        client_secret : client_secret
        ```
        This configuration file explicitly defines the `client_secret` parameter and, as shown in the example, stores it in plaintext.  There is no indication of encryption or secure handling of this sensitive value within this file.
    - File: `/code/SplunkADXForwarder/app.py`
        ```python
        with open("config.yml", "r") as config_file:
            config = yaml.safe_load(config_file)

        client_secret = config['client_secret']

        kcsb = KustoConnectionStringBuilder.with_aad_application_key_authentication(cluster, client_id, client_secret, authority)
        ```
        This code snippet demonstrates how the application reads the `config.yml` file, loads the configuration, and retrieves the `client_secret` directly from the configuration. Subsequently, this plaintext `client_secret` is used to construct the `KustoConnectionStringBuilder` for authenticating with Azure Data Explorer. This confirms that the application directly utilizes the plaintext secret from the configuration file for authentication, without any secure handling or retrieval mechanisms.
- Security Test Case:
    1. Deploy the `SplunkADXForwarder` application. For example, use Docker to build and run the application:
        ```bash
        cd /code/SplunkADXForwarder/
        docker build -t splunk-adx-forwarder .
        docker run -d --name splunk-adx-forwarder-instance splunk-adx-forwarder
        ```
    2. Access the running container's shell. This allows you to simulate an attacker gaining access to the application's environment:
        ```bash
        docker exec -it splunk-adx-forwarder-instance /bin/bash
        ```
    3. Navigate to the application's configuration directory within the container:
        ```bash
        cd /app
        ```
    4. Read the contents of the `config.yml` file to expose the stored credentials:
        ```bash
        cat config.yml
        ```
    5. Observe the output and confirm that the `client_secret` is visible in plaintext within the `config.yml` file. Note down the values for `ingest_url`, `client_id`, `client_secret`, `authority`, `database_name`.
    6. Exit the container shell:
        ```bash
        exit
        ```
    7. Using a Kusto client (like Kusto Explorer or the `kustoctl` CLI tool) from your local machine or a different secure environment, attempt to connect to the Azure Data Explorer cluster using the extracted credentials. Construct the connection string using the `ingest_url`, `client_id`, `client_secret`, and `authority` obtained from `config.yml`.
    8. If the connection to the Azure Data Explorer cluster is successful using these credentials, it validates the vulnerability. This confirms that an attacker who gains access to the `config.yml` file can successfully extract and use the plaintext credentials to access the Azure Data Explorer cluster without authorization.
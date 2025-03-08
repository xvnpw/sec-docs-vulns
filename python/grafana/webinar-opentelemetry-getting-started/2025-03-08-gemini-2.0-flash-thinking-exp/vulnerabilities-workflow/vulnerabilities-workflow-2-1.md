### Vulnerability List:

- **Vulnerability Name:** Grafana Cloud API Token Exposure via Environment Variables

- **Description:**
    1. A user follows the instructions in the `README.md` to deploy the sample application.
    2. As part of the setup, the user is instructed to obtain a Grafana Cloud API token and set it as an environment variable `OTEL_EXPORTER_OTLP_HEADERS`.
    3. If the user deploys this application in a publicly accessible environment (e.g., a public cloud server) without securing environment variables, the API token becomes potentially exposed.
    4. An attacker who gains unauthorized access to the environment where the application is running (e.g., through server misconfiguration, other vulnerabilities, or insider access) can retrieve the Grafana Cloud API token.
    5. The attacker can then use this stolen API token to authenticate and access the victim's Grafana Cloud account, potentially gaining access to monitoring data, dashboards, and other Grafana Cloud resources.

- **Impact:**
    - Unauthorized access to the victim's Grafana Cloud account.
    - Potential compromise of sensitive monitoring data sent to Grafana Cloud.
    - Ability for the attacker to manipulate Grafana dashboards, alerts, and monitoring configurations within the victim's Grafana Cloud account.
    - Potential for further malicious activities within the Grafana Cloud environment depending on the permissions associated with the compromised API token.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
    - None. The provided code and documentation do not include any mitigations for the risk of API token exposure through environment variables. The `README.md` actually encourages setting the API token as an environment variable without sufficient warning about the security implications for production deployments.

- **Missing Mitigations:**
    - **Security Warning in Documentation:** The `README.md` should include a prominent security warning about the risks of exposing Grafana Cloud API tokens via environment variables in publicly accessible environments. It should emphasize that environment variables are generally not a secure way to store secrets in production.
    - **Guidance on Secure Secret Management:** The documentation should guide users towards more secure methods of managing Grafana Cloud API tokens, especially for production deployments. This could include:
        - Using dedicated secret management tools or services (e.g., HashiCorp Vault, AWS Secrets Manager, Kubernetes Secrets).
        - Loading API tokens from configuration files that are not publicly accessible.
        - Using environment variable encryption or other techniques to protect secrets at rest and in transit.
    - **Principle of Least Privilege Recommendation:**  Users should be advised to create Grafana Cloud API tokens with the minimum necessary permissions to limit the potential damage if a token is compromised.

- **Preconditions:**
    - The sample application is deployed in a publicly accessible environment.
    - The user follows the `README.md` instructions and sets the Grafana Cloud API token as an environment variable (`OTEL_EXPORTER_OTLP_HEADERS`).
    - The environment where the application is deployed is not properly secured, allowing potential attackers to access environment variables.

- **Source Code Analysis:**
    - **`README.md`**: The instructions in the "Run the sample application via Docker" and "Run the sample application locally" sections explicitly guide users to set the `OTEL_EXPORTER_OTLP_HEADERS` environment variable with the Grafana Cloud API token.
    ```markdown
    ```sh
    export OTEL_EXPORTER_OTLP_HEADERS="Authorization=Basic%20..."
    ```
    ```sh
    docker run \
      -e OTEL_EXPORTER_OTLP_PROTOCOL="http/protobuf" \
      -e OTEL_EXPORTER_OTLP_ENDPOINT="https://otlp-gateway-prod-us-east-0.grafana.net/otlp"
      -e OTEL_EXPORTER_OTLP_HEADERS="Authorization=Basic%20..." \
      -p 8080:8080 \
      grafana-otel-webinar
    ```
    This documentation suggests a configuration method that is insecure for production environments without providing sufficient warnings or alternative secure practices.
    - **`app.py` and `Dockerfile`**: These files do not directly handle the API token. The vulnerability is introduced by the deployment instructions and the inherent insecurity of environment variables for sensitive secrets in publicly accessible systems.

- **Security Test Case:**
    1. **Deploy the Application:** Deploy the Docker image built from the provided `Dockerfile` to a publicly accessible server (e.g., an EC2 instance or a similar cloud VM). When running the Docker container, include the `-e OTEL_EXPORTER_OTLP_HEADERS="<YOUR_GRAFANA_CLOUD_API_TOKEN>"` parameter, replacing `<YOUR_GRAFANA_CLOUD_API_TOKEN>` with a valid Grafana Cloud API token. Ensure port 8080 is publicly accessible.
    2. **Access the Deployed Application:** Verify that the application is running by accessing the `/rolldice` endpoint (e.g., `http://<YOUR_PUBLIC_IP>:8080/rolldice`) from an external network.
    3. **Attempt to Access Environment Variables (Simulated Attack):** In a real attack scenario, an attacker would attempt to gain access to the server's environment variables through various means (e.g., exploiting other vulnerabilities in the application or server, social engineering, or insider access). For the purpose of this test case, we will simulate gaining local access to the running container's environment.
    4. **Inspect Docker Container Environment:**  On the server where the Docker container is running, use Docker commands to inspect the environment variables of the running container. For example:
       ```sh
       docker ps # to get the container ID
       docker inspect <CONTAINER_ID> | grep OTEL_EXPORTER_OTLP_HEADERS
       ```
    5. **Extract API Token:** The output of the `docker inspect` command will reveal the value of the `OTEL_EXPORTER_OTLP_HEADERS` environment variable, which contains the Grafana Cloud API token.
    6. **Verify API Token Validity:** Use the extracted Grafana Cloud API token to authenticate against the Grafana Cloud API. For example, use `curl` to make a request to a Grafana Cloud API endpoint that requires authentication, including the extracted token in the `Authorization` header.
       ```sh
       curl -H "Authorization: <EXTRACTED_API_TOKEN>" "https://<YOUR_GRAFANA_CLOUD_INSTANCE>.grafana.net/api/datasources" # Replace with a valid Grafana Cloud API endpoint
       ```
    7. **Confirm Unauthorized Access:** If the API request is successful and returns data from your Grafana Cloud instance, it confirms that the extracted API token is valid and can be used to access your Grafana Cloud account. This demonstrates the vulnerability of exposing the API token through environment variables in a publicly accessible environment.
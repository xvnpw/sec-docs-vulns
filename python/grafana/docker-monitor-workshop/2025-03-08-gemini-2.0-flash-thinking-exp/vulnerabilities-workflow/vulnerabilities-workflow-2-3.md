- Vulnerability Name: Unauthenticated Alloy Reload API Access
- Description:
    - The Grafana Alloy UI and its configuration reload API endpoint `/-/reload` are exposed without any authentication mechanism.
    - An attacker can send a POST request to the `/-/reload` endpoint from any network if the Alloy UI port (default `12345`) is publicly accessible.
    - This request can include a new Alloy configuration file in the request body.
    - Alloy will then load and apply this new configuration, replacing the existing one.
    - This allows an attacker to inject a malicious Alloy configuration.
- Impact:
    - By injecting a malicious configuration, an attacker can redirect the flow of collected metrics and logs.
    - This can lead to data exfiltration, where sensitive data from Docker containers (metrics and logs) is sent to an attacker-controlled system.
    - The attacker can gain visibility into the monitored system's performance, logs, and potentially sensitive information contained within logs or metrics.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - None. The provided `docker-compose.yml` and workshop setup expose the Alloy UI and reload API without any authentication or access control.
- Missing Mitigations:
    - Implement authentication and authorization for the Alloy UI and the `/-/reload` API endpoint in the Alloy configuration.
    - Restrict access to the Alloy UI and `/-/reload` API to trusted networks or users using network firewalls or access control lists.
    - Document the security risks of exposing the Alloy UI and reload API without authentication and provide guidance on how to secure them.
- Preconditions:
    - The Grafana Alloy service is deployed using the provided `docker-compose.yml` or similar configuration.
    - The Alloy UI port (default `12345`) is exposed to the public internet or an untrusted network.
    - An attacker has network access to the exposed Alloy UI port.
- Source Code Analysis:
    - **File: `/code/docker-compose.yml`**
        - The `alloy` service definition includes the following port mapping:
          ```yaml
          ports:
            - 12345:12345
          ```
        - This line exposes port `12345` of the Alloy container to port `12345` on the host machine, making the Alloy UI accessible from outside the Docker network if the host machine's port `12345` is reachable.
        - The `command` for the Alloy container is:
          ```yaml
          command: run --server.http.listen-addr=0.0.0.0:12345 --storage.path=/var/lib/alloy/data /etc/alloy/config.alloy
          ```
        - `--server.http.listen-addr=0.0.0.0:12345` explicitly binds the Alloy HTTP server (which serves the UI and API) to all interfaces (`0.0.0.0`) on port `12345`. This makes the UI and API accessible from any network that can reach the host on port `12345`.
        - There is no configuration within `docker-compose.yml` or the provided `loki-config.yaml` to enable authentication for Alloy's HTTP server.
    - **File: `/code/README.md`**
        - The documentation explicitly instructs users how to access the Alloy UI:
          ```
          ### Step 3: Access Grafana Alloy UI
          Open your browser and go to `http://localhost:12345`. This should show you a plank Alloy UI.
          ```
        - It also documents how to use the reload API without mentioning any authentication requirements:
          ```
          - Use the `reload` API endpoint
            ```bash
            curl -X POST http://localhost:12345/-/reload
            ```
          ```
        - This confirms that the intended setup, as described in the workshop, exposes the unauthenticated reload API.
    - **Grafana Alloy Default Behavior:**
        - By default, Grafana Alloy does not enforce authentication on its HTTP UI and API endpoints, including the `/-/reload` endpoint. Authentication and authorization need to be explicitly configured. The provided project files do not include any such configuration.

- Security Test Case:
    1. **Deploy the workshop:** Run `docker-compose up -d` in the `/code` directory to start the monitoring stack.
    2. **Verify Alloy UI Access:** Open a web browser and navigate to `http://<your-docker-host>:12345`. You should be able to access the Grafana Alloy UI without any login prompt.
    3. **Attempt Reload API Access without Authentication:**
        - Open a terminal and use `curl` to send a reload request to the Alloy API:
          ```bash
          curl -X POST http://<your-docker-host>:12345/-/reload
          ```
        - Observe the response. If the reload API is unauthenticated, the request will likely succeed (or at least not be rejected due to authentication failure). Alloy might return a message like `"configuration reloaded"` or a similar success indication.
    4. **(Optional) Inject Malicious Configuration (Conceptual):**
        - Create a malicious Alloy configuration file (`malicious-config.alloy`) that, for example, attempts to send collected metrics to an attacker-controlled endpoint.
        - Send a reload request with this malicious configuration:
          ```bash
          curl -X POST -H "Content-Type: application/yaml" --data-binary "@malicious-config.alloy" http://<your-docker-host>:12345/-/reload
          ```
        - If successful, the Alloy instance will reload with the attacker's configuration, and depending on the malicious configuration's content, data exfiltration or other malicious actions could be performed. (Note: Crafting a fully functional malicious config and setting up an attacker endpoint for data reception is beyond the scope of a basic test but illustrates the potential impact).
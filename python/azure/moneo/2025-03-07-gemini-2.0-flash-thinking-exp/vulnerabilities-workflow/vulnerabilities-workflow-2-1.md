- Vulnerability Name: Default Grafana Credentials
- Description:
    - Step 1: Moneo offers a "Local Grafana Deployment" method where Grafana is deployed locally on a head node using Docker.
    - Step 2: The Grafana Docker container is configured using environment variables defined in `/code/src/master/grafana/grafana.env`.
    - Step 3: This file sets default credentials for the Grafana admin user: `GF_SECURITY_ADMIN_USER=azure` and `GF_SECURITY_ADMIN_PASSWORD=azure`.
    - Step 4: If a user deploys Moneo using the "Local Grafana Deployment" method and does not change these default credentials, the Grafana portal will be accessible with these well-known credentials.
    - Step 5: An attacker, knowing the default credentials, can attempt to access the Grafana portal by navigating to `http://master-ip-or-domain:3000` (as described in `/code/README.md` and `/code/docs/LocalGrafanaDeployment.md`).
    - Step 6: The attacker can then log in using the username "azure" and password "azure".
- Impact:
    - An attacker gains unauthorized access to the Grafana portal.
    - This allows the attacker to view all monitoring dashboards, metrics, and data collected by Moneo, potentially including sensitive information about GPU system performance, utilization, and configurations.
    - Depending on Grafana configurations and installed plugins, the attacker might be able to further compromise the system, modify dashboards, create new users, or potentially gain access to the underlying Prometheus database or even the head node itself if Grafana is misconfigured or vulnerable to further exploits.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - None. The project uses default credentials in the configuration file for local Grafana deployment without any enforced password change or security hardening during the deployment process.
- Missing Mitigations:
    - **Strong Password Policy Enforcement:** Implement a mechanism to force users to change the default Grafana administrator password during the "Local Grafana Deployment" setup. This could be achieved by:
        -  Providing a script that prompts the user to set a new password before deploying Grafana.
        -  Modifying the deployment script to generate a random admin password if one is not provided by the user and securely storing or communicating it to the user.
    - **Documentation and Security Best Practices:**
        -  Clearly document the security implications of using default credentials in `/code/docs/LocalGrafanaDeployment.md` and `/code/README.md`.
        -  Strongly advise users to change the default Grafana credentials immediately after deployment and provide instructions on how to do so.
        -  Recommend additional security measures for "Local Grafana Deployment", such as deploying Grafana behind a reverse proxy with authentication, using network segmentation, and regularly updating Grafana to the latest secure version.
- Preconditions:
    - Moneo is deployed using the "Local Grafana Deployment" method.
    - The user does not change the default Grafana administrator credentials after deployment.
    - The head node hosting the Grafana portal is accessible to the attacker, either publicly or within the same network.
- Source Code Analysis:
    - File: `/code/src/master/grafana/grafana.env`
    - Content:
        ```env
        GF_SECURITY_ADMIN_USER=azure
        GF_SECURITY_ADMIN_PASSWORD=azure
        GF_SERVER_HTTP_PORT=3000
        GF_INSTALL_PLUGINS=grafana-piechart-panel,grafana-clock-panel,grafana-simple-json-datasource
        ```
    - Analysis:
        - The `grafana.env` file directly sets the Grafana administrator username and password to "azure" and "azure" respectively.
        - This file is used by the `run.sh` script in `/code/src/master/` to launch the Grafana Docker container.
        - The `run.sh` script does not include any logic to check or modify these default credentials, meaning Grafana will always start with these defaults unless the user manually intervenes after deployment.
    - Visualization:
        ```
        /code/src/master/grafana/grafana.env  -->  Docker run command in /code/src/master/run.sh  -->  Grafana Docker Container with default credentials
        ```
- Security Test Case:
    - Step 1: Deploy Moneo using the "Local Grafana Deployment Guide" as described in `/code/docs/LocalGrafanaDeployment.md`. Execute the command `python3 moneo.py --deploy -c hostfile full`.
    - Step 2: After successful deployment, identify the IP address or domain name of the head node where Grafana is deployed (as configured in your `hostfile`).
    - Step 3: Open a web browser and navigate to `http://<head-node-ip-or-domain>:3000`.
    - Step 4: The Grafana login page should be displayed.
    - Step 5: Enter "azure" as the username and "azure" as the password.
    - Step 6: Click the "Log in" button.
    - Step 7: If the login is successful and you are redirected to the Grafana dashboard, the vulnerability is confirmed. This indicates that the default credentials are active and allow unauthorized access.
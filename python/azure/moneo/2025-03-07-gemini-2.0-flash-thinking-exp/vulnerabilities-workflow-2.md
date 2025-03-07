## Vulnerabilities List

### Vulnerability: Default Grafana Credentials

- **Description:**
    - Step 1: Moneo offers a "Local Grafana Deployment" method, deploying Grafana locally on a head node using Docker for monitoring visualization.
    - Step 2: The Grafana Docker container is configured using environment variables defined in `/code/src/master/grafana/grafana.env`.
    - Step 3: This configuration file sets default credentials for the Grafana admin user: `GF_SECURITY_ADMIN_USER=azure` and `GF_SECURITY_ADMIN_PASSWORD=azure`.
    - Step 4: When a user deploys Moneo using the "Local Grafana Deployment" method, Grafana is initialized with these hardcoded default credentials.
    - Step 5: If the user fails to change these default credentials post-deployment, the Grafana portal remains accessible via these well-known credentials.
    - Step 6: An attacker, aware of these default credentials and with network access to the Grafana portal (typically exposed on port 3000 of the head node), can attempt to log in.
    - Step 7: By navigating to `http://master-ip-or-domain:3000` and using the username "azure" and password "azure", an attacker can successfully gain unauthorized access to the Grafana instance.

- **Impact:**
    - **Unauthorized Access to Grafana Portal:** An attacker gains complete and unauthorized access to the Grafana portal with administrator privileges.
    - **Information Disclosure:** The attacker can view all monitoring dashboards, metrics, and sensitive data collected by Moneo. This includes detailed insights into GPU system performance, utilization, network traffic, and potentially sensitive information about AI workflows.
    - **Dashboard Manipulation and Malicious Script Injection:** With admin access, the attacker can modify existing dashboards or create new ones. This allows for the injection of malicious JavaScript code into dashboards, potentially leading to Cross-Site Scripting (XSS) attacks against other Grafana users who view these compromised dashboards.
    - **Configuration Changes:** The attacker can alter Grafana settings, configurations, and potentially data sources, disrupting monitoring capabilities or gaining further access to connected systems.
    - **Potential System Compromise:** Depending on Grafana configurations, installed plugins, and any existing vulnerabilities within Grafana, the attacker might be able to further compromise the head node server or the underlying Prometheus database.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
    - None. The project uses default credentials directly in the configuration file for local Grafana deployment.
    - Documentation in `/code/docs/LocalGrafanaDeployment.md` mentions the default credentials and instructs users to change them, but this relies on manual user action and is not enforced.

- **Missing Mitigations:**
    - **Enforced Password Change during Deployment:** Implement a mechanism to force users to change the default Grafana administrator password during the "Local Grafana Deployment" setup. This could involve:
        -  A script that prompts for a new password before deploying Grafana.
        -  Generating a random password if the user doesn't provide one and securely displaying it to the user post-deployment.
    - **Automated Password Generation:** Automatically generate a strong, unique, and random Grafana admin password during the deployment process instead of using static default credentials.
    - **Deployment-time Security Warning:** Display a clear warning message in the CLI during the "Local Grafana Deployment" process, emphasizing the critical security risk of using default credentials and urging immediate password change after deployment.
    - **Security Hardening Guide:** Provide a comprehensive security hardening guide specifically for "Local Grafana Deployment," detailing best practices for securing Grafana, including:
        - Enforcing strong password policies.
        - Enabling HTTPS for secure communication.
        - Implementing network access restrictions (e.g., firewalls, reverse proxies).
        - Regularly updating Grafana to the latest secure version.
        - Disabling unnecessary Grafana features and plugins.
    - **Post-Deployment Security Check:** Implement a post-deployment check that verifies if the default Grafana credentials are still in use and alerts the user if they are, prompting immediate action.

- **Preconditions:**
    - Moneo must be deployed using the "Local Grafana Deployment" method.
    - The user must not have changed the default Grafana administrator credentials ("azure/azure") after the deployment process.
    - The head node hosting the Grafana portal (port 3000) must be network accessible to the attacker.

- **Source Code Analysis:**
    - **File:** `/code/src/master/grafana/grafana.env`
        ```env
        GF_SECURITY_ADMIN_USER=azure
        GF_SECURITY_ADMIN_PASSWORD=azure
        GF_SERVER_HTTP_PORT=3000
        GF_INSTALL_PLUGINS=grafana-piechart-panel,grafana-clock-panel,grafana-simple-json-datasource
        ```
        - **Analysis:** This file explicitly defines the default Grafana administrator username (`GF_SECURITY_ADMIN_USER`) and password (`GF_SECURITY_ADMIN_PASSWORD`) as "azure". These environment variables are directly used by the Grafana Docker container during startup.
    - **File:** `/code/src/master/run.sh`
        ```bash
        docker run --name grafana \
            -it --net=host  -d -p 3000:3000 \
            --env-file $PWD/grafana/grafana.env \
            -v $PWD/grafana/dashboards:/var/lib/grafana/dashboards \
            -v $PWD/grafana/provisioning:/etc/grafana/provisioning \
            grafana/grafana
        ```
        - **Analysis:** The `run.sh` script uses the `--env-file` option to pass environment variables from `/code/src/master/grafana/grafana.env` to the Grafana Docker container. This includes the default credentials. The script lacks any logic to modify or enforce a change of these default credentials.
    - **File:** `/code/docs/LocalGrafanaDeployment.md`
        ```markdown
        3. Log into the portal by navigating to `http://manager-ip-or-domain:3000` and inputting your credentials

            ![image](https://user-images.githubusercontent.com/70273488/173685955-dc51f7fc-da55-450b-b214-20d875e7687f.png)

            Note: By default username/password are set to "azure". This can be changed here "src/master/grafana/grafana.env"
        ```
        - **Analysis:** The documentation mentions the default credentials and points to the configuration file for changing them. However, it does not enforce or strongly guide users to change these credentials, relying on manual user intervention which is often overlooked.

- **Security Test Case:**
    - Step 1: Deploy Moneo using the "Local Grafana Deployment Guide" as described in `/code/docs/LocalGrafanaDeployment.md` by executing `python3 moneo.py --deploy -c hostfile full`. Ensure the deployment is successful.
    - Step 2: Identify the IP address or domain name of the head node where Grafana is deployed (as configured in your `hostfile`).
    - Step 3: Open a web browser and navigate to the Grafana portal at `http://<head-node-ip-or-domain>:3000`.
    - Step 4: The Grafana login page should be displayed.
    - Step 5: Enter "azure" as the username and "azure" as the password in the login form.
    - Step 6: Click the "Log in" button.
    - Step 7: **Expected Result:** Successful login to the Grafana dashboard. This confirms that the default credentials are active and allow unauthorized access.
    - Step 8: **(Optional - XSS Test):** After successful login, navigate to Dashboards, create a new dashboard, add a Text panel, switch to "Text" mode and insert `<script>alert("XSS Vulnerability");</script>`. Save the dashboard and view it. An alert box should appear, demonstrating the potential for XSS exploitation due to admin access.
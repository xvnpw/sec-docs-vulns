### Vulnerability List

- Vulnerability Name: Default Grafana Credentials in Local Deployment
- Description:
    1. Moneo offers a "Local Grafana Deployment" method where it deploys Grafana on a designated head node for visualization.
    2. By default, Moneo configures Grafana with a hardcoded username "azure" and password "azure", as defined in the `src/master/grafana/grafana.env` file.
    3. If a user deploys Moneo using the "Local Grafana Deployment" method and fails to change these default credentials, the Grafana web interface will be accessible with these well-known credentials.
    4. An attacker, if able to reach the Grafana portal (typically exposed on port 3000 of the head node), can attempt to log in using "azure/azure".
    5. Upon successful login with the default credentials, the attacker gains unauthorized access to the Grafana instance.
- Impact:
    1. **Information Disclosure:** An attacker can access all Grafana dashboards, gaining visibility into sensitive system and performance metrics collected by Moneo. This can include GPU utilization, memory usage, network traffic, and potentially custom metrics if configured.
    2. **Further System Compromise:** Depending on the attacker's skill and Grafana's configuration, they might be able to leverage Grafana features or vulnerabilities to further compromise the head node server. This could include actions like creating malicious dashboards that execute code on the server or exploiting known Grafana vulnerabilities if the deployed version is outdated.
    3. **Data Manipulation (Potentially):** While primarily a monitoring tool, Grafana might offer functionalities (depending on plugins and configuration) that could be misused by an attacker with unauthorized access to manipulate dashboards or data sources, leading to misleading or false monitoring information.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - Documentation: The `docs/LocalGrafanaDeployment.md` guide explicitly mentions the default Grafana credentials ("azure/azure") and instructs users to change them. It also points to the `src/master/grafana/grafana.env` file where these credentials can be modified.
    - Location: `/code/docs/LocalGrafanaDeployment.md`
- Missing Mitigations:
    - Automated Password Change: Implement a mechanism to automatically generate and set a strong, unique Grafana admin password during the "Local Grafana Deployment" process.
    - Enforced Password Complexity: Enforce a strong password policy for Grafana administrator accounts, requiring passwords to meet complexity requirements (length, character types, etc.).
    - Deployment-time Warning: During the "Local Grafana Deployment," display a clear warning message in the CLI if the default Grafana credentials are still in use, urging the user to change them immediately.
    - Security Hardening Guide: Provide a comprehensive security hardening guide specifically for "Local Grafana Deployment," detailing best practices for securing Grafana, including network access restrictions, disabling unnecessary features, and regular security updates.
- Preconditions:
    - Deployment Method: The "Local Grafana Deployment" method must be used to deploy Moneo.
    - Unchanged Credentials: The user must not have changed the default Grafana administrator credentials ("azure/azure") after Moneo deployment.
    - Network Accessibility: The Grafana port (default port 3000) on the head node must be reachable from the attacker's network.
- Source Code Analysis:
    - File: `/code/src/master/grafana/grafana.env`
        ```env
        GF_SECURITY_ADMIN_USER=azure
        GF_SECURITY_ADMIN_PASSWORD=azure
        ```
        - This file explicitly sets the default administrator username (`GF_SECURITY_ADMIN_USER`) and password (`GF_SECURITY_ADMIN_PASSWORD`) for the Grafana instance to "azure".
        - These environment variables are used by the Grafana Docker container during startup to configure the initial admin credentials.
    - File: `/code/docs/LocalGrafanaDeployment.md`
        ```markdown
        3. Log into the portal by navigating to `http://manager-ip-or-domain:3000` and inputting your credentials

            ![image](https://user-images.githubusercontent.com/70273488/173685955-dc51f7fc-da55-450b-b214-20d875e7687f.png)

            Note: By default username/password are set to "azure". This can be changed here "src/master/grafana/grafana.env"
        ```
        - The documentation confirms the use of default credentials and guides users to the configuration file for changing them, but this relies on manual user action which is often missed or delayed.
- Security Test Case:
    1. Deploy Moneo using the "Local Grafana Deployment" method as described in `docs/LocalGrafanaDeployment.md`. Follow all steps but **intentionally skip changing the default Grafana credentials**.
    2. Identify the IP address or domain name of the head node where Grafana is deployed (referred to as `manager-ip-or-domain` in the documentation).
    3. Open a web browser and navigate to the Grafana portal using the URL `http://<manager-ip-or-domain>:3000`.
    4. The Grafana login page should be displayed.
    5. In the login form, enter "azure" as the username and "azure" as the password.
    6. Click the "Log in" button.
    7. **Expected Result:** If the login is successful and you are granted access to the Grafana dashboards, it confirms that the default credentials vulnerability is present. This indicates that an attacker could also gain unauthorized access using these default credentials.
### Vulnerability List

- Vulnerability Name: Default Grafana Administrator Credentials
- Description: Moneo's local Grafana deployment method configures Grafana with default administrator credentials: username "azure" and password "azure". If a user deploys Moneo using the local Grafana deployment and does not change these default credentials, an attacker can gain unauthorized administrator access to the Grafana instance.
- Impact: High. Successful exploitation grants an attacker full administrative control over the locally deployed Grafana instance. This allows the attacker to:
    - View sensitive monitoring data collected by Moneo.
    - Modify existing dashboards to inject malicious JavaScript code.
    - Create new dashboards containing malicious JavaScript code.
    - Change Grafana settings and configurations.
    - Potentially compromise accounts of other users who access the Grafana instance through XSS if malicious dashboards are created or modified.
- Vulnerability Rank: High
- Currently Implemented Mitigations: None. The project does not implement any measures to prevent the use of default Grafana credentials in local deployments.
- Missing Mitigations:
    - **Enforce Password Change:** The Moneo deployment process should enforce or strongly encourage users to change the default Grafana administrator password immediately after deployment.
    - **Random Password Generation:** During the local Grafana deployment setup, Moneo could automatically generate a strong, random password for the Grafana administrator account. This password should be securely communicated to the user (e.g., displayed in the terminal output after deployment).
    - **Security Hardening Documentation:** Provide clear documentation and instructions on how to harden the security of the locally deployed Grafana instance, including changing default credentials, enabling HTTPS, and implementing access controls.
- Preconditions:
    - User chooses the "Local Grafana Deployment" method when deploying Moneo.
    - User does not manually change the default Grafana administrator credentials after deployment.
    - The Grafana instance is accessible over the network (e.g., on a head node accessible via a web browser).
- Source Code Analysis:
    - File: `/code/src/master/grafana/grafana.env`
        - This file defines environment variables for the Grafana Docker container.
        - It hardcodes the default administrator username (`GF_SECURITY_ADMIN_USER`) and password (`GF_SECURITY_ADMIN_PASSWORD`) to "azure".
        ```
        GF_SECURITY_ADMIN_USER=azure
        GF_SECURITY_ADMIN_PASSWORD=azure
        ```
    - File: `/code/src/master/run.sh`
        - This script is responsible for launching the Grafana Docker container during local deployment.
        - It uses the `--env-file` option to load environment variables from `/code/src/master/grafana/grafana.env`, including the default credentials.
        ```bash
        docker run --name grafana \
            -it --net=host  -d -p 3000:3000 \
            --env-file $PWD/grafana/grafana.env \
            -v $PWD/grafana/dashboards:/var/lib/grafana/dashboards \
            -v $PWD/grafana/provisioning:/etc/grafana/provisioning \
            grafana/grafana
        ```
    - File: `/code/src/master/managerLaunch.sh`
        - This script calls `/code/src/master/run.sh` to start Grafana and Prometheus.
        - It does not include any steps to change the default Grafana credentials.
- Security Test Case:
    1. Deploy Moneo using the Local Grafana Deployment method as described in `/code/docs/LocalGrafanaDeployment.md`. Follow the steps in "2. Now deploy Moneo - using Moneo cli:".
    2. After successful deployment, access the Grafana portal in a web browser by navigating to `http://<master-ip-or-domain>:3000`, where `<master-ip-or-domain>` is the IP address or domain name of the manager node (head node).
    3. On the Grafana login page, attempt to log in using the default username "azure" and password "azure".
    4. If the login is successful, it confirms the vulnerability. An attacker with network access to the Grafana instance can use these default credentials to gain administrator access.
    5. (Optional for further impact demonstration) After successful login with default credentials, navigate to Dashboards, create a new dashboard, add a Text panel, and insert the following JavaScript code into the text panel (using "Text" mode): `<script>alert("XSS Vulnerability");</script>`. Save the dashboard. Access the dashboard and observe the alert box, demonstrating potential XSS exploitation after gaining admin access.
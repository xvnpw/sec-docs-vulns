- Vulnerability Name: Weak Default Grafana Credentials in Local Deployment
- Description:
  - In the "Local Grafana Deployment" method, Moneo deploys Grafana with default credentials.
  - An attacker with network access to the Moneo master node (hosting Grafana) can attempt to log in to the Grafana web interface using these default credentials.
  - If successful, the attacker gains unauthorized access to the Grafana dashboard.
  - The default username and password for Grafana are set in the `src/master/grafana/grafana.env` file.
  - According to `docs/LocalGrafanaDeployment.md`, the Grafana portal can be reached via `http://master-ip-or-domain:3000`.
  - The documentation also mentions that default username/password are set to "azure" and can be changed in `src/master/grafana/grafana.env`. However, there is no enforcement or prompt to change these default credentials during deployment.
- Impact:
  - Unauthorized access to the Grafana portal exposes sensitive system metrics collected by Moneo.
  - An attacker can view detailed performance and utilization data for GPUs, InfiniBand networks, CPUs, and memory.
  - This information can be used to understand system workload, identify potential targets for further attacks, or gain insights into sensitive AI workflows running on the monitored infrastructure.
  - Although direct system control is not granted, the exposed metrics can aid in reconnaissance and potentially lead to more severe attacks.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
  - Documentation mentions that default credentials can be changed in `src/master/grafana/grafana.env` (`docs/LocalGrafanaDeployment.md`).
  - No mitigation is implemented in the code to enforce or guide users to change default credentials during deployment.
- Missing Mitigations:
  - Enforce or strongly recommend changing default Grafana credentials during the "Local Grafana Deployment" process.
  - Provide a script or clear instructions to guide users on how to change the default credentials upon deployment.
  - Consider generating random default credentials for each deployment to avoid the predictability of a static default.
  - Implement a post-deployment security check that warns users if default credentials are still in use.
- Preconditions:
  - Moneo deployed using the "Local Grafana Deployment" method.
  - Network access to the master node's IP address and port 3000 (default Grafana port).
  - Default Grafana credentials have not been changed by the user.
- Source Code Analysis:
  - File: `/code/src/master/grafana/grafana.env`
    ```env
    GF_SECURITY_ADMIN_USER=azure
    GF_SECURITY_ADMIN_PASSWORD=azure
    ```
    This file sets the default Grafana administrator username and password to "azure". These credentials are used by the Grafana instance deployed by Moneo in the "Local Grafana Deployment" method.

  - File: `/code/docs/LocalGrafanaDeployment.md`
    ```markdown
    3. Log into the portal by navigating to `http://manager-ip-or-domain:3000` and inputting your credentials

        ![image](https://user-images.githubusercontent.com/70273488/173685955-dc51f7fc-da55-450b-b214-20d875e7687f.png)

        Note: By default username/password are set to "azure". This can be changed here "src/master/grafana/grafana.env"
    ```
    This documentation confirms that default credentials are "azure/azure" and points to the `grafana.env` file for changing them. It acknowledges the default credentials but doesn't enforce changing them.

- Security Test Case:
  - Step 1: Deploy Moneo using the "Local Grafana Deployment" method as described in `docs/LocalGrafanaDeployment.md`.
    ```sh
    python3 moneo.py --deploy -c hostfile full
    ```
    Ensure that the hostfile is configured and the deployment is successful.
  - Step 2: Identify the IP address or domain name of the master node where Grafana is deployed. This information should be available from the deployment process or the hostfile.
  - Step 3: Open a web browser and navigate to `http://<master-ip-or-domain>:3000`.
  - Step 4: The Grafana login page should be displayed.
  - Step 5: Enter "azure" as the username and "azure" as the password.
  - Step 6: Click the "Log in" button.
  - Step 7: If the default credentials are still active, you will be successfully logged in to the Grafana dashboard, demonstrating unauthorized access using default credentials.
  - Step 8: Observe the Grafana dashboards to confirm access to system metrics.
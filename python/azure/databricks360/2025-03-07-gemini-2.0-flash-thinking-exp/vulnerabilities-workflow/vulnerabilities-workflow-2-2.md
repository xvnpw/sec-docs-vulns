### Vulnerability List:

- Vulnerability Name: Overly Permissive External Location Permissions

- Description:
    1. The Infrastructure-as-Code (IaC) scripts, specifically `iac-adb-360/helpers/create-ms-externlocation.sh` and `iac-adb-360/helpers/create-ms-catalognschema-sepstor.sh`, are used to create Unity Catalog external locations.
    2. These scripts, by default, grant `ALL_PRIVILEGES` on the newly created external locations to the `devcat-admins` group using the command `databricks grants update external_location $extlocationname --json '{ "changes": [{"principal": "devcat-admins", "add" : ["ALL_PRIVILEGES"]}] }'`.
    3. If the `devcat-admins` group in Unity Catalog is misconfigured or contains users or service principals with overly broad access, it can lead to unauthorized access to the underlying storage account associated with the external location.
    4. An attacker, if part of or able to compromise a member of the `devcat-admins` group, could leverage these permissions to bypass intended access controls and directly access, modify, or exfiltrate data in the linked storage account. This is because `ALL_PRIVILEGES` on an external location grants full control over the storage paths defined within that external location.

- Impact:
    - High
    - Unauthorized access to sensitive data stored in the linked storage accounts.
    - Potential data exfiltration, modification, or deletion by unauthorized users who are members of the `devcat-admins` group.
    - Violation of data confidentiality and integrity.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    - The project uses Unity Catalog for access control, which is a mitigation in itself compared to workspace-level ACLs.
    - The principle of least privilege should be applied when managing `devcat-admins` group membership, but this is not enforced by the IaC code itself.

- Missing Mitigations:
    - **Least Privilege Principle for Group Permissions:** The IaC should not grant `ALL_PRIVILEGES` by default. Instead, it should grant only the necessary minimal permissions required for the intended use case, such as `READ_FILES` or `WRITE_FILES`, and only when truly necessary.
    - **Documentation and Guidance:**  The documentation should explicitly warn administrators about the risks of granting `ALL_PRIVILEGES` and provide guidance on how to configure more restrictive permissions and manage `devcat-admins` group membership securely.
    - **Security Test Cases:** Include automated security tests that verify the principle of least privilege is applied to external locations and storage credentials.

- Preconditions:
    - The IaC pipelines have been executed to create the Databricks workspace and Unity Catalog objects.
    - The `devcat-admins` group in Unity Catalog exists.
    - An attacker is able to gain membership or compromise an existing member of the `devcat-admins` group.

- Source Code Analysis:
    - File: `/code/iac-adb-360/helpers/create-ms-externlocation.sh`
    ```bash
    databricks grants update external_location $extlocationname --json '{ "changes": [{"principal": "devcat-admins", "add" : ["ALL_PRIVILEGES"]}] }'
    ```
    - File: `/code/iac-adb-360/helpers/create-ms-catalognschema-sepstor.sh`
    ```bash
    databricks grants update external_location $extlocationname --json '{ "changes": [{"principal": "devcat-admins", "add" : ["ALL_PRIVILEGES"]}] }'
    ```
    - These lines in the scripts directly grant `ALL_PRIVILEGES` to the `devcat-admins` group on the created external locations.
    - There is no configuration option within these scripts to modify these permissions to be more restrictive.
    - An administrator running these scripts without understanding the implications will inadvertently configure overly permissive access to the underlying storage.
    - Visualization:
        ```mermaid
        graph LR
        A[IaC Script: create-ms-externlocation.sh] --> B{Databricks CLI: grants update external_location}
        B --> C[Unity Catalog Metastore]
        C --> D{External Location Permissions}
        D --> E[devcat-admins group gets ALL_PRIVILEGES]
        E --> F[Unauthorized Storage Access if devcat-admins misconfigured]
        ```

- Security Test Case:
    1. **Pre-requisites:**
        - Deploy the Databricks lakehouse solution using the provided IaC.
        - Ensure the `devcat-admins` group exists in Unity Catalog.
        - Add a test user (attacker) to the `devcat-admins` group.
        - Identify the name of the external location created by the IaC (e.g., `bronzextlocdev`).
    2. **Steps:**
        - As the test user (attacker), log in to the Databricks workspace.
        - Use the Databricks CLI or a notebook to list the files within the external location. For example, using Databricks CLI:
            ```bash
            databricks fs ls dbfs:/external_locations/<external_location_name>/
            ```
            Replace `<external_location_name>` with the actual name of the external location (e.g., `bronzextlocdev`).
        - Attempt to read the content of a file within the external location. For example, using Databricks CLI:
            ```bash
            databricks fs head dbfs:/external_locations/<external_location_name>/<some_file.parquet>
            ```
        - Attempt to write a new file to the external location. For example, using Databricks CLI:
            ```bash
            echo "test data" | databricks fs cp - dbfs:/external_locations/<external_location_name>/test_attacker_file.txt
            ```
    3. **Expected Result:**
        - The test user (attacker), being a member of `devcat-admins` group with `ALL_PRIVILEGES`, should be able to successfully list files, read file content, and write new files to the external location.
        - This demonstrates that the default permissions are overly permissive and allow unauthorized data access and modification if the `devcat-admins` group is not strictly managed.

---
- Vulnerability Name: Potential Insecure Cluster Configuration via Shared Cluster Configuration File

- Description:
    1. The IaC scripts, specifically `iac-adb-360/helpers/create-cluster.sh`, utilize external JSON configuration files to define and create Databricks clusters.
    2. The script uses the command `databricks clusters create --json "@iac-adb-360/helpers/$clusterconf.json"` where `$clusterconf` is a variable (e.g., `sharedcluster`) that determines the JSON configuration file used.
    3. The project files do not include example cluster configuration JSON files (like `sharedcluster.json`). If these files are not properly created and secured, or if they contain insecure default settings, it can lead to vulnerabilities.
    4. Potential insecure configurations in these JSON files could include:
        - **Public cluster access:**  If the cluster configuration allows public access or does not enforce proper authentication, it could be accessed by unauthorized users.
        - **Weak authentication:** If authentication mechanisms are not properly configured or enforced, it could be easier for attackers to gain access.
        - **Overly permissive access control:** If the cluster's access control settings are too broad, it could allow unauthorized actions within the cluster.
        - **Exposure of sensitive information:** If the configuration files themselves are not properly secured, they could expose sensitive information like credentials or internal configurations.
    5. An attacker who gains access to or influences the cluster configuration JSON files could potentially deploy insecure Databricks clusters, leading to unauthorized access, data breaches, or other security incidents.

- Impact:
    - Medium to High (depending on the severity of misconfiguration in cluster config files)
    - Deployment of insecure Databricks clusters.
    - Potential unauthorized access to cluster resources and data processing capabilities.
    - Risk of data breaches, data manipulation, or denial of service.

- Vulnerability Rank: Medium

- Currently Implemented Mitigations:
    - The project uses IaC to automate cluster deployment, which can enforce consistent configurations if properly managed.
    - The `data_security_mode: USER_ISOLATION` is set in `bundle_adb_360/resources/adb360_init_job.yml`, `adb360_incremental_load_job.yml`, and `adb360_historical_load_job.yml` job definitions, which is a security best practice for clusters used by multiple users. However, this is only for job clusters, not necessarily for shared clusters created via `create-cluster.sh`.

- Missing Mitigations:
    - **Secure Default Cluster Configurations:** Provide secure default cluster configuration JSON files (e.g., `sharedcluster.json`) that adhere to security best practices (no public access, strong authentication, least privilege access control, etc.). These files should be part of the repository and version controlled.
    - **Cluster Configuration Validation:** Implement validation mechanisms within the IaC pipelines to check cluster configurations against security policies before deployment. This could include static analysis of JSON files or dynamic checks against a security baseline.
    - **Documentation and Guidance:** Provide clear documentation and guidance on how to create and manage secure cluster configurations, emphasizing security best practices and potential risks of misconfigurations.
    - **Security Test Cases:** Develop security test cases to verify that deployed clusters adhere to security policies and do not have insecure configurations.

- Preconditions:
    - The IaC pipelines are used to deploy Databricks infrastructure, including cluster creation using `create-cluster.sh`.
    - The cluster configuration JSON files (e.g., `sharedcluster.json`) are not securely configured or managed.
    - An attacker is able to influence or access the cluster configuration JSON files or exploit insecure default configurations.

- Source Code Analysis:
    - File: `/code/iac-adb-360/helpers/create-cluster.sh`
    ```bash
    databricks clusters create --json "@iac-adb-360/helpers/$clusterconf.json"
    ```
    - This line shows that cluster configuration is loaded from an external JSON file determined by the `$clusterconf` variable.
    - The security of the cluster entirely depends on the content of this external JSON file, which is not provided in the project files.
    - If `clusterconf.json` contains insecure settings, the deployed cluster will be vulnerable.
    - Visualization:
        ```mermaid
        graph LR
        A[IaC Script: create-cluster.sh] --> B{Reads Cluster Config from JSON: $clusterconf.json}
        B --> C{Databricks CLI: clusters create --json}
        C --> D[Databricks Workspace]
        D --> E{Insecure Cluster Configuration if JSON is Malicious}
        E --> F[Potential Unauthorized Access to Cluster]
        ```

- Security Test Case:
    1. **Pre-requisites:**
        - Deploy the Databricks lakehouse solution using the provided IaC.
        - Identify the cluster configuration file used by `create-cluster.sh` (e.g., assume it's `sharedcluster.json` and it's located at `/code/iac-adb-360/helpers/sharedcluster.json`).
        - Modify the assumed cluster configuration file (`sharedcluster.json`) to introduce an insecure setting, for example, by enabling public access if such an option exists in Databricks cluster configurations (Note: Public access might not be directly configurable, but consider other insecure settings like disabling authentication requirements if possible, or using very weak passwords if applicable to any cluster features). For this test case, assume we can modify the `autotermination_minutes` to a very large value, simulating a long-running potentially exposed cluster.
    2. **Steps:**
        - Run the IaC pipeline that executes `create-cluster.sh`. This should deploy a Databricks cluster with the modified (insecure) configuration.
        - Attempt to access the Databricks cluster in a way that exploits the introduced misconfiguration. (Since direct public access is unlikely, monitor cluster behavior for unexpected long-running status due to the modified `autotermination_minutes`, or try to find other exploitable misconfigurations if directly modifiable).
        - If a public access misconfiguration was hypothetically possible, try to access the cluster from outside the intended network perimeter without proper authentication.
    3. **Expected Result:**
        - If the cluster configuration file contains insecure settings, the deployed cluster should reflect these settings and exhibit vulnerable behavior. For example, if `autotermination_minutes` was set to a high value, the cluster will remain active for an extended period, potentially unnecessarily increasing the attack surface. If hypothetically public access was enabled, the attacker should be able to access cluster resources without proper authorization.
        - This demonstrates that insecure cluster configuration files can lead to vulnerable Databricks environments.

---
- Vulnerability Name: Potential for Insecure Job Execution Context in Databricks Asset Bundles

- Description:
    1. Databricks Asset Bundles, as used in this project, allow defining jobs and workflows in YAML configuration files (`bundle_adb_360/resources/*.yml`).
    2. The `databricks.yml` file specifies the `run_as` context for these jobs, which determines the identity under which the jobs are executed. In `databricks.yml`, the `run_as` is configured as:
        ```yaml
        run_as:
          service_principal_name: 1f75dd16-f271-4248-ae35-993e70abe5a8
        ```
    3. If the specified service principal (`1f75dd16-f271-4248-ae35-993e70abe5a8` in the example) or user account has overly broad permissions within the Databricks workspace or Unity Catalog, jobs might be executed with excessive privileges.
    4. An attacker, if able to modify the `databricks.yml` or job configuration files (e.g., through a compromised CI/CD pipeline or by directly editing the repository if permissions are weak), could potentially escalate privileges by:
        - Changing the `run_as` context to a more privileged service principal or user.
        - Modifying job tasks to perform unauthorized actions if the `run_as` context has excessive permissions.
    5. This could lead to unauthorized data access, modification, or other malicious activities performed by the Databricks jobs.

- Impact:
    - Medium
    - Jobs running with overly broad permissions.
    - Potential for privilege escalation if job configurations are modified by an attacker.
    - Unauthorized data access, modification, or other malicious job activities.

- Vulnerability Rank: Medium

- Currently Implemented Mitigations:
    - The project uses service principals for job execution, which is generally a security best practice compared to using personal user accounts.
    - Unity Catalog access control should limit the permissions of the service principal used for job execution.

- Missing Mitigations:
    - **Least Privilege Principle for Job Execution:** The `run_as` service principal should be granted only the minimal permissions required for the jobs to function correctly. Avoid using highly privileged service principals or accounts.
    - **Job Configuration Validation:** Implement validation checks in the CI/CD pipelines to ensure that job configurations adhere to security policies, including verifying the `run_as` context and task definitions.
    - **Secure Configuration Management:** Securely manage access to the repository and CI/CD pipelines to prevent unauthorized modification of job configuration files.
    - **Documentation and Guidance:** Provide clear guidance on securely configuring the `run_as` context for Databricks Asset Bundle jobs and the principle of least privilege.
    - **Security Test Cases:** Create security test cases to verify that jobs are executed with the intended least privilege context and cannot be easily modified to escalate privileges.

- Preconditions:
    - Databricks Asset Bundles are deployed and used to manage Databricks jobs.
    - The `run_as` context in `databricks.yml` is configured with a service principal or user that has more permissions than necessary.
    - An attacker is able to modify the `databricks.yml` or job configuration files, or exploit misconfigurations in the CI/CD pipeline.

- Source Code Analysis:
    - File: `/code/bundle_adb_360/databricks.yml`
    ```yaml
    run_as:
      service_principal_name: 1f75dd16-f271-4248-ae35-993e70abe5a8
    ```
    - This section defines the `run_as` context for all jobs in the bundle.
    - If the service principal `1f75dd16-f271-4248-ae35-993e70abe5a8` has excessive permissions, all jobs will inherit these permissions.
    - An attacker modifying this file can change the `service_principal_name` to a more privileged one, or if user context is used, potentially escalate privileges.
    - Visualization:
        ```mermaid
        graph LR
        A[databricks.yml: run_as] --> B{Specifies Job Execution Context (Service Principal)}
        B --> C[Databricks Job Execution]
        C --> D{Jobs Run As Specified Service Principal}
        D --> E[Privilege Escalation if Service Principal Overly Permissive or Modified]
        ```

- Security Test Case:
    1. **Pre-requisites:**
        - Deploy Databricks Asset Bundles using the provided configurations.
        - Identify the service principal configured in `databricks.yml` for `run_as` (e.g., `1f75dd16-f271-4248-ae35-993e70abe5a8`).
        - Determine the current permissions of this service principal in Unity Catalog and the Databricks workspace.
    2. **Steps:**
        - **Scenario 1: Verify Least Privilege (Ideal Case):**
            - As a user with limited permissions, attempt to execute one of the Databricks jobs defined in `bundle_adb_360/resources/*.yml`.
            - Verify that the job executes successfully and performs its intended tasks, but does not have permissions to perform actions outside its intended scope (e.g., access data it shouldn't, modify configurations, etc.).
        - **Scenario 2: Test for Privilege Escalation (Vulnerability Case):**
            - Modify the `databricks.yml` file (if possible in your test environment, e.g., by directly editing a local copy before deployment, or if you have write access to the repository branch used for testing).
            - Change the `service_principal_name` in `databricks.yml` to a service principal or user account that you control and grant this test service principal/user *excessive* permissions in Unity Catalog and the Databricks workspace (e.g., `admin` role if possible for testing purposes, or broad `ALL PRIVILEGES` on data).
            - Redeploy the Databricks Asset Bundles with the modified `databricks.yml`.
            - Execute the same Databricks job as in Scenario 1.
            - Verify that the job now executes with the *escalated* privileges of the modified `run_as` context. For example, check if the job can now access data or perform actions that it was not authorized to do in Scenario 1 (with the original, presumably less privileged, service principal).
    3. **Expected Result:**
        - **Scenario 1 (Ideal):** The job executes successfully within its intended scope, demonstrating that the default `run_as` context *might* be configured with reasonable permissions (this needs to be verified by checking actual permissions, not just job functionality).
        - **Scenario 2 (Vulnerability):** If the job, after modifying `databricks.yml` to use a more privileged `run_as` context, can now perform actions it was previously unauthorized to do, this confirms the vulnerability. It demonstrates that changing the `run_as` configuration can effectively escalate the privileges of job execution, and insecure configuration management of `databricks.yml` or overly permissive `run_as` accounts pose a security risk.
- Vulnerability Name: Insecure Storage of CycleCloud API Credentials

- Description:
    1. The `cyclecloud-scalelib` library uses a configuration file named `autoscale.json` to store sensitive information, including credentials (username and password) for accessing the Azure CycleCloud REST API.
    2. The `install.sh` script and example installation scripts in `example-celery` create this `autoscale.json` file during the setup process.
    3. By default, the `autoscale.json` file is created with file permissions that might allow unauthorized users with local machine access to read its contents.
    4. An attacker with access to the machine where `autoscale.json` is stored can read the file and extract the CycleCloud API credentials.
    5. With these credentials, the attacker can then authenticate to the CycleCloud REST API and perform unauthorized actions, potentially manipulating Azure cloud resources managed by the CycleCloud environment.

- Impact:
    - Unauthorized Access to Azure CycleCloud Environment: Attackers can gain full or partial control over the Azure CycleCloud environment depending on the permissions associated with the compromised credentials.
    - Cloud Resource Manipulation: Attackers can leverage the compromised credentials to start, stop, scale, or delete Azure resources managed by CycleCloud, leading to potential service disruption, data loss, or financial impact due to unauthorized resource usage.
    - Lateral Movement: In a broader cloud environment, compromised CycleCloud credentials might facilitate lateral movement to other Azure services or resources if the same credentials are reused or if the compromised account has broader access.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    - None. The project does not implement any specific mitigations to prevent insecure storage of credentials in `autoscale.json`.

- Missing Mitigations:
    - Secure Credential Storage: Implement secure storage mechanisms for CycleCloud API credentials, such as using Azure Key Vault or other secrets management solutions instead of storing them in a plain text file.
    - Least Privilege Principle: Encourage users to create CycleCloud API credentials with the minimum necessary permissions required for autoscaling, limiting the potential impact of credential compromise.
    - Documentation and Best Practices: Provide clear documentation and best practices for users on how to securely manage CycleCloud API credentials, emphasizing the importance of restricting access to `autoscale.json` and using secure storage solutions.  Warn users against storing plain text credentials in configuration files.

- Preconditions:
    - An application or autoscaler is deployed using `cyclecloud-scalelib` that relies on `autoscale.json` for CycleCloud API authentication.
    - The `autoscale.json` file is created and stored on a file system accessible to potential attackers.
    - The attacker gains unauthorized access to the file system where `autoscale.json` is stored.

- Source Code Analysis:
    1. **File Creation**: The vulnerability stems from how the `autoscale.json` file is created and handled by the `hpc.autoscale.cli initconfig` command, as seen in `/code/example-celery/specs/broker/cluster-init/scripts/01.install.packages.sh`. This script uses the `hpc.autoscale.cli` to generate the configuration file.
    2. **Credential Storage**: The `initconfig` command, defined in `/code/src/hpc/autoscale/cli.py` and `/code/src/hpc/autoscale/clilib.py`, takes username and password as arguments and stores them directly in the `autoscale.json` file in plain text format.
    3. **File Permissions**: The `install.sh` script and example installation scripts do not explicitly set restrictive permissions on the created `autoscale.json` file, leading to the potential for default, less secure permissions to be applied by the operating system.
    4. **CLI Usage**: The `azscale` CLI tool, created by `/code/util/install_azscale.sh`, is designed to use the `autoscale.json` configuration file. This means that any application using `azscale` and relying on default installation practices will be vulnerable if the `autoscale.json` file is compromised.

    ```python
    # /code/src/hpc/autoscale/cli.py - _initconfig method in ScaleLibCLI class

    def _initconfig(self, config: Dict) -> None:
        pass # No explicit permission setting here for autoscale.json

    # /code/example-celery/specs/broker/cluster-init/scripts/01.install.packages.sh

    python -m hpc.autoscale.cli initconfig \
                      --cluster-name $(jetpack config cyclecloud.cluster.name) \
                      --username     $(jetpack config cyclecloud.config.username) \
                      --password     $(jetpack config cyclecloud.config.password) \
                      --url          $(jetpack config cyclecloud.config.web_server) \
                      ... > \
                      $INSTALLDIR/autoscale.json # autoscale.json is created here without explicit permission setting
    ```

- Security Test Case:
    1. **Environment Setup**: Deploy the example Celery cluster as described in `/code/example-celery/README.md` on an Azure CycleCloud instance. Ensure you have SSH access to the broker node.
    2. **Access Broker Node**: SSH into the broker node of the deployed Celery cluster.
    3. **Check `autoscale.json` Permissions**: Run the command `ls -l /opt/cycle/scalelib/autoscale.json` to check the file permissions. Observe the permissions; they are likely to be world-readable or readable by users beyond just the application owner.
    4. **Read `autoscale.json` Content**: Run the command `cat /opt/cycle/scalelib/autoscale.json` to read the content of the configuration file.
    5. **Extract Credentials**: In the output of `autoscale.json`, locate and extract the values for `"username"` and `"password"`. These are the CycleCloud API credentials.
    6. **Attempt API Access with Extracted Credentials**:
        - **Using `az cyclecloud` CLI (if available on the broker node or attacker machine):**
            ```bash
            az cyclecloud user list --cluster-name <cluster_name_from_autoscale.json> --username <username_from_autoscale.json> --password <password_from_autoscale.json> --url <url_from_autoscale.json>
            ```
        - **Using `curl` to directly access the CycleCloud REST API:**
            ```bash
            curl -u "<username_from_autoscale.json>:<password_from_autoscale.json>" "<url_from_autoscale.json>/api/v2/clusters"
            ```
    7. **Verify Unauthorized Access**: If the commands in step 6 successfully return cluster information or user lists, it confirms that the extracted credentials can be used to access the CycleCloud API without proper authorization beyond local machine access, thus validating the vulnerability.
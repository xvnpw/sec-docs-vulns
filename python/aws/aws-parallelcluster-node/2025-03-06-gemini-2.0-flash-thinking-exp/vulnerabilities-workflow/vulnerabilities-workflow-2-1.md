- Vulnerability Name: Command Injection in Slurm Node Management Scripts

- Description:
  The `aws-parallelcluster-node` package uses subprocess calls to execute Slurm commands for node management. Improper validation of arguments passed to these subprocess calls could lead to command injection vulnerabilities. An attacker might be able to manipulate cluster configuration parameters or user-provided input (if any) in a way that leads to the execution of arbitrary commands on the EC2 instance when the node package processes this data.

  1. An attacker could potentially manipulate cluster configuration (e.g., through a compromised configuration file or man-in-the-middle attack during configuration retrieval).
  2. This manipulated configuration could contain malicious commands embedded within parameters that are later used as arguments in subprocess calls within the `aws-parallelcluster-node` package.
  3. When the node package processes this configuration, specifically in scripts or daemons responsible for node management (like `clustermgtd`, `computemgtd`, `slurm_resume`, `slurm_suspend`), the malicious commands could be injected into the subprocess calls.
  4. Due to the command injection vulnerability, these malicious commands would be executed on the EC2 instance with the privileges of the user running the `aws-parallelcluster-node` processes (typically root or a cluster admin user).

- Impact:
  Successful command injection can allow an attacker to execute arbitrary commands on the EC2 instance. This can lead to:
    - Full control of the compute node.
    - Data exfiltration from the compute node or the cluster's shared storage.
    - Modification or deletion of critical system files.
    - Use of the compute node as a pivot point for further attacks within the AWS environment.
    - Denial of service by disrupting the compute node's functionality.

- Vulnerability Rank: Critical

- Currently Implemented Mitigations:
  - The changelog for version 3.5.0 mentions "Add validators to prevent malicious string injection while calling the subprocess module." This indicates that mitigations have been implemented in version 3.5.0 and later to address command injection vulnerabilities. However, the specific locations and effectiveness of these mitigations require further source code analysis.

- Missing Mitigations:
  - While validators have been added, it's crucial to ensure comprehensive and consistent input validation across all subprocess calls within the `aws-parallelcluster-node` package. Further analysis is needed to confirm if all potential injection points are properly secured.
  - Consider using safer alternatives to `subprocess.run` where possible, such as direct function calls or libraries that avoid shell execution when dealing with external commands.
  - Implement principle of least privilege, ensuring that the `aws-parallelcluster-node` processes run with the minimum necessary privileges to reduce the impact of potential command injection exploits.

- Preconditions:
  - An attacker needs to be able to manipulate cluster configuration parameters or influence input processed by the `aws-parallelcluster-node` package. This could be achieved through:
    - Compromising the cluster's configuration storage or delivery mechanisms.
    - Man-in-the-middle attacks during configuration retrieval.
    - Exploiting other vulnerabilities to inject malicious input into the system.

- Source Code Analysis:
  The `CHANGELOG.md` file for version 3.5.0 states: "Add validators to prevent malicious string injection while calling the subprocess module." This enhancement suggests that previous versions were potentially vulnerable to command injection.

  To analyze the mitigation, we would need to examine the source code changes introduced in version 3.5.0. Specifically, we would look for:
    - Code modifications related to subprocess calls within `src/slurm_plugin` directory, especially in files like `clustermgtd.py`, `computemgtd.py`, `resume.py`, `suspend.py`, and potentially within `common/schedulers/slurm_commands.py`.
    - Implementation of validation functions in `common/utils.py` or similar modules, such as `validate_subprocess_argument` and `validate_absolute_path` mentioned in `tests/common/test_utils.py`.
    - Usage of these validation functions before making subprocess calls to sanitize potentially malicious input.

  Without access to the exact source code diff from version 3.4.1 to 3.5.0, a precise code walkthrough is not possible. However, the presence of tests like `tests/common/test_utils.py` and the changelog entry strongly suggest that the developers have addressed command injection risks by implementing input validation for subprocess arguments.

- Security Test Case:
  To create a security test case, we would need to identify specific locations in the code where subprocess calls are made with arguments derived from configuration or input.  Assuming a hypothetical vulnerable code path in an older version (prior to 3.5.0) within `clustermgtd.py` that constructs a Slurm command using a configuration parameter, the test steps would be:

  1. Set up a vulnerable environment: Deploy an older version of `aws-parallelcluster-node` (prior to 3.5.0) in a test ParallelCluster.
  2. Manipulate cluster configuration: Modify the cluster configuration (e.g., using `pcluster configure`) to include a malicious payload in a configuration parameter that is known to be used in subprocess calls. For example, if a queue name parameter is used in a subprocess call, set the queue name to: `test_queue; touch /tmp/pwned`.
  3. Trigger the vulnerable code path: Initiate a cluster management action that triggers the execution of the vulnerable code path in `clustermgtd.py` (e.g., starting or stopping the compute fleet).
  4. Observe the exploit: Check for the execution of the injected command on the head node. In this example, verify if the file `/tmp/pwned` is created on the head node, indicating successful command injection.
  5. Verify mitigation in newer versions: Repeat steps 1-4 with the latest version of `aws-parallelcluster-node` (3.5.0 or later). Verify that the vulnerability is no longer exploitable and the malicious command is not executed due to implemented input validation.

  **Note:** This test case is theoretical and needs to be adapted based on the actual vulnerable code paths identified through source code analysis of versions prior to 3.5.0. Due to the project files provided being the latest version, this test case serves as a general guideline to verify command injection vulnerabilities and their mitigations if older versions of the code were available.
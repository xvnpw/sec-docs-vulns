- Vulnerability Name: Command Injection in `upload-node.sh`

- Description:
An attacker could potentially inject arbitrary commands into the `upload-node.sh` script via the `--scope` parameter. The script uses `aws s3 cp` command to upload the node package to an S3 bucket. The `--scope` parameter is used to construct the S3 key path without proper sanitization. If an attacker can control the value of the `--scope` parameter, they could inject shell commands that would be executed during the `aws s3 cp` command execution.

Steps to trigger vulnerability:
1. An attacker identifies that the `upload-node.sh` script is used to upload the `aws-parallelcluster-node` package.
2. The attacker analyzes the script and finds that the `--scope` parameter is concatenated into the `_key_path` variable, which is later used in the `aws s3 cp` command.
3. The attacker crafts a malicious `--scope` value containing shell commands, for example: `--scope "test; touch /tmp/pwned;"`.
4. The attacker executes the `upload-node.sh` script with the crafted `--scope` parameter.
5. The `aws s3 cp` command will be executed with the injected shell command, leading to arbitrary command execution on the system where the script is run.

- Impact:
Successful exploitation of this vulnerability could allow an attacker to execute arbitrary shell commands on the system where the `upload-node.sh` script is executed. This could lead to:
1. Unauthorized access to sensitive data on the system.
2. Modification or deletion of critical files.
3. Installation of malware or backdoors.
4. Privilege escalation, depending on the user context the script is run under.

- Vulnerability Rank: high

- Currently Implemented Mitigations:
No mitigations are currently implemented in the `upload-node.sh` script to prevent command injection via the `--scope` parameter. The script directly uses the parameter value in a shell command without any sanitization or validation.

- Missing Mitigations:
Input sanitization and validation for the `--scope` parameter should be implemented to prevent command injection. Specifically:
1. Validate the `--scope` parameter to ensure it only contains alphanumeric characters, underscores, hyphens, or other safe characters.
2. Use parameterized commands or shell quoting to prevent command injection when constructing the `aws s3 cp` command.

- Preconditions:
1. The attacker needs to be able to execute the `upload-node.sh` script or provide the `--scope` parameter to someone who executes the script.
2. The AWS CLI tools must be installed and configured on the system where the script is executed.

- Source Code Analysis:
1. File: `/code/util/upload-node.sh`
2. Lines 90-92:
```bash
    _key_path="parallelcluster/${_version}/node"
    if [ -n "${_scope}" ]; then
        _key_path="${_key_path}/${_scope}"
    fi
```
This code block constructs the `_key_path` variable by directly concatenating the `--scope` parameter value. No sanitization is performed on `_scope`.
3. Lines 95, 97, 99:
```bash
    aws ${_profile} --region "${_region}" s3 cp aws-parallelcluster-node-${_version}.tgz s3://${_bucket}/${_key_path}/aws-parallelcluster-node-${_version}.tgz || _error_exit 'Failed to push node to S3'
    aws ${_profile} --region "${_region}" s3 cp aws-parallelcluster-node-${_version}.md5 s3://${_bucket}/${_key_path}/aws-parallelcluster-node-${_version}.md5 || _error_exit 'Failed to push node md5 to S3'
    aws ${_profile} --region "${_region}" s3 cp aws-parallelcluster-node-${_version}.tgz.date s3://${_bucket}/${_key_path}/aws-parallelcluster-node-${_version}.tgz.date || _error_exit 'Failed to push node date'
```
This code block executes `aws s3 cp` commands using the `_key_path` variable. Since `_key_path` is constructed using the unsanitized `--scope` parameter, it is vulnerable to command injection.

- Security Test Case:
1. Pre-requisites:
    - Ensure you have AWS CLI installed and configured with credentials that have permission to create and write to S3 buckets.
    - You need to have access to the `/code/util/upload-node.sh` script.
2. Steps:
    - Navigate to the `/code/util/` directory.
    - Execute the `upload-node.sh` script with a malicious `--scope` parameter:
    ```bash
    ./upload-node.sh --bucket <your-s3-bucket-name> --srcdir ../code --scope "$(touch /tmp/pwned)"
    ```
    Replace `<your-s3-bucket-name>` with the name of an S3 bucket you control.
    - Check if the file `/tmp/pwned` has been created on the system where you executed the script.
3. Expected result:
    - If the vulnerability is present, the file `/tmp/pwned` will be created, indicating that the injected command `touch /tmp/pwned` was successfully executed by the `aws s3 cp` command.
    - The script may also fail to upload the node package as the S3 key path will be malformed due to the injected command.
    - The script should exit with an error message like `Failed to push node to S3` or `Failed to push node md5 to S3` or `Failed to push node date`.
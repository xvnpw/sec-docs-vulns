## Vulnerability List for aws-parallelcluster-node

- Vulnerability Name: **Command Injection in `upload-node.sh` via `--scope` parameter**
- Description:
    1. The `upload-node.sh` script is used to upload the `aws-parallelcluster-node` package to an S3 bucket.
    2. The script takes a `--scope` parameter, which is intended to disambiguate the S3 path and avoid collisions.
    3. The value of the `--scope` parameter is directly incorporated into the `_key_path` variable without proper sanitization.
    4. This `_key_path` variable is then used in `aws s3 cp` commands.
    5. An attacker could inject malicious commands through the `--scope` parameter, leading to command injection when the script executes the `aws s3 cp` commands.
    6. For example, an attacker could provide a `--scope` value like `"test; touch /tmp/pwned"` or `"test\`touch /tmp/pwned\`"`.
    7. When the script executes `aws s3 cp aws-parallelcluster-node-${_version}.tgz s3://${_bucket}/${_key_path}/aws-parallelcluster-node-${_version}.tgz`, the injected command would be executed.
- Impact:
    - **Critical**. Successful command injection allows an attacker to execute arbitrary commands on the system where `upload-node.sh` is being run. In a CI/CD pipeline or developer's machine, this could lead to compromised credentials, data exfiltration, or further malicious activities.
- Vulnerability Rank: **Critical**
- Currently Implemented Mitigations:
    - None identified in the provided files.
- Missing Mitigations:
    - **Input Sanitization**: Sanitize the `--scope` parameter to prevent command injection. This could involve:
        - **Allowlisting**: Only allow alphanumeric characters and hyphens in the scope string.
        - **Input validation**: Validate the `--scope` parameter against a regular expression to ensure it conforms to the expected format.
        - **Encoding**: Properly encode the scope value when constructing the S3 key to prevent shell interpretation of special characters.
    - **Secure Coding Practices**: Avoid directly incorporating user-provided input into shell commands. Use parameterized commands or safer alternatives to shell execution when possible.
- Preconditions:
    - The attacker needs to be able to execute the `upload-node.sh` script and control the `--scope` parameter. This is likely in a development or CI/CD environment where the script is used to package and upload the node package.
- Source Code Analysis:
    1. **File**: `/code/util/upload-node.sh`
    2. **Line**: `_scope="$2"; shift;;` and `_scope="${1#*=}";;` inside the `case` statement for `--scope`. This part reads the `--scope` parameter directly into the `_scope` variable.
    3. **Line**: `_key_path="parallelcluster/${_version}/node"` and `_key_path="${_key_path}/${_scope}"` constructs the S3 key path by directly concatenating the `_scope` variable.
    4. **Line**: `aws ${_profile} --region "${_region}" s3 cp aws-parallelcluster-node-${_version}.tgz s3://${_bucket}/${_key_path}/aws-parallelcluster-node-${_version}.tgz` and similar lines use the `_key_path` variable in the `aws s3 cp` command, which is executed using `bash`. This allows command injection via the unsanitized `_scope` variable.
    ```sh
    _key_path="parallelcluster/${_version}/node"
    if [ -n "${_scope}" ]; then
        _key_path="${_key_path}/${_scope}" # Unsanitized _scope is concatenated into _key_path
    fi
    aws ${_profile} --region "${_region}" s3 cp aws-parallelcluster-node-${_version}.tgz s3://${_bucket}/${_key_path}/aws-parallelcluster-node-${_version}.tgz # _key_path used in command
    ```
- Security Test Case:
    1. **Environment**: Set up a test environment where `upload-node.sh` can be executed. This could be a local machine with AWS CLI configured or a CI/CD pipeline environment.
    2. **Malicious Scope**: Prepare a malicious scope value designed for command injection, for example: `test\`touch /tmp/pwned\``.
    3. **Execute Script**: Execute the `upload-node.sh` script with the malicious scope value and other required parameters like `--bucket`, `--srcdir`. For example:
       ```bash
       ./upload-node.sh --bucket your-s3-bucket --srcdir /path/to/aws-parallelcluster-node --scope "test\`touch /tmp/pwned\`"
       ```
    4. **Verify Exploit**: Check if the injected command `touch /tmp/pwned` was executed. In this case, verify if the file `/tmp/pwned` was created.
    5. **Expected Result**: If the vulnerability exists, the file `/tmp/pwned` should be created, demonstrating successful command injection.
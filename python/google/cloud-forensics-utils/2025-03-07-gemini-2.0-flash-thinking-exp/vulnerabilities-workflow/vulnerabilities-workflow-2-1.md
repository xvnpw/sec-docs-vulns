- vulnerability name: Command Injection in EBS Snapshot Copy Script
- description: |
    The `ebs_snapshot_copy_aws.sh` script, used for copying EBS snapshots to S3, is vulnerable to command injection. The script takes the `snapshot` ID and S3 `bucket` name as input and uses them in shell commands without proper sanitization. An attacker who can control these inputs, for example by crafting malicious arguments to the `cloudforensics` CLI tool, can inject arbitrary shell commands that will be executed on the analysis VM during the snapshot copying process.

    Steps to trigger the vulnerability:
    1. An attacker crafts a malicious S3 destination path containing a command to be executed, such as `s3://bucket/$(touch /tmp/pwned)`.
    2. The attacker uses the `cloudforensics aws` CLI tool with the `imageebssnapshottos3` command, providing the malicious S3 destination path and a snapshot ID.
    3. The `cloudforensics` tool, without proper sanitization, passes this malicious S3 destination path to the `ebs_snapshot_copy_aws.sh` script via userdata.
    4. The `ebs_snapshot_copy_aws.sh` script executes commands, including `aws s3 cp - $bucket/$snapshot/image.bin`, where the attacker-controlled `$bucket` variable is used without sanitization.
    5. The injected command `touch /tmp/pwned` is executed on the analysis VM with the privileges of the user running the `cloudforensics` tool.
- impact: |
    Critical. Successful command injection allows an attacker to execute arbitrary commands on the analysis VM. This can lead to:
    * Unauthorized access to data on the analysis VM.
    * Privilege escalation within the analysis VM.
    * Lateral movement to other cloud resources accessible from the analysis VM's context.
    * Data exfiltration from the investigated cloud environment.
    * Complete compromise of the analysis VM, potentially hindering or corrupting the forensic investigation.
- vulnerability rank: critical
- currently implemented mitigations: No mitigations are currently implemented in the `ebs_snapshot_copy_aws.sh` script or in the Python code that calls it.
- missing mitigations: |
    Input sanitization is missing for the `snapshot` and `bucket` variables in the `ebs_snapshot_copy_aws.sh` script.

    Recommended mitigations include:
    * **Input Validation:** Implement strict validation of the `snapshot` and `bucket` parameters to ensure they conform to expected formats and do not contain shell- Metacharacters or command separators.
    * **Output Encoding:** Properly encode the `snapshot` and `bucket` variables when used in shell commands to prevent interpretation of malicious characters.
    * **Using Parameterized Queries/Functions:** If possible, refactor the script to use safer alternatives to shell commands, or use parameterized functions that prevent command injection by design (although this might be challenging with `aws s3 cp`).
    * **Principle of Least Privilege:** Ensure that the analysis VM and the user running the `cloudforensics` tool operate with the minimum privileges necessary to perform their tasks, limiting the impact of a successful command injection.
- preconditions: |
    To trigger this vulnerability, the following preconditions must be met:
    * The attacker must be able to influence the arguments passed to the `cloudforensics aws imageebssnapshottos3` CLI command. This is typically possible for a user who is authorized to use the CLI tool.
    * The `cloudforensics` tool must be executed by a user with sufficient privileges to create and manage AWS resources in the target account.
    * The analysis VM must be launched with the vulnerable `ebs_snapshot_copy_aws.sh` script.
- source code analysis: |
    1. In the file `/code/libcloudforensics/scripts/ebs_snapshot_copy_aws.sh`, the script initializes shell variables `snapshot` and `bucket` directly from the script arguments:
    ```bash
    snapshot={0:s}
    bucket={1:s}
    ```
    These variables are intended to hold the snapshot ID and S3 bucket name, respectively, which are provided as input to the script.

    2. Further down in the script, these variables are used within an `aws s3 cp` command:
    ```bash
    dc3dd if=/dev/xvdh hash=sha512 hash=sha256 hash=md5 log=/tmp/log.txt hlog=/tmp/hlog.txt mlog=/tmp/mlog.txt | aws s3 cp - $bucket/$snapshot/image.bin
    ```
    Here, `$bucket` and `$snapshot` are directly interpolated into the shell command without any sanitization or encoding. This allows for command injection if an attacker can control the values of `snapshot` or `bucket`.

    3. The Python code in `/code/libcloudforensics/providers/aws/forensics.py` constructs the userdata script by formatting the `ebs_snapshot_copy_aws.sh` script with the `snapshot_id` and `s3_destination` parameters:
    ```python
    script = utils.ReadStartupScript(
        utils.EBS_SNAPSHOT_COPY_SCRIPT_AWS).format(snapshot_id, s3_destination)
    ```
    The `s3_destination` parameter, which is derived from user-controlled input to the `ImageEBSSnapshotToS3` CLI command, is passed unsanitized into the shell script.

    4. This formatted script is then passed as userdata to the EC2 instance:
    ```python
    aws_account.ec2.GetOrCreateVm(
        ...,
        userdata=startup_script,
        ...)
    ```
    This results in the execution of the vulnerable `ebs_snapshot_copy_aws.sh` script on the newly created EC2 instance, with attacker-controlled input being used in shell commands.

- security test case: |
    1. Prerequisites:
        * Ensure you have AWS credentials configured for the target AWS account.
        * Ensure you have the `cloudforensics` CLI tool installed and configured.
        * Identify a valid AWS zone (e.g., `us-east-1`).
        * Identify a test S3 bucket name where you have write access (replace `test-bucket` with your bucket name in the command below).

    2. Execute the following `cloudforensics` CLI command to trigger the vulnerability. This command attempts to copy a snapshot (replace `test-snapshot` with a dummy snapshot id or any valid snapshot id in your account as this value is not actually used in exploit but just needs to be syntactically valid) and uses a malicious S3 destination path designed to inject a command:
    ```bash
    cloudforensics aws <zone> imageebssnapshottos3 --snapshot_id=test-snapshot --s3_destination="s3://test-bucket/pwn$(touch /tmp/pwned)"
    ```
    Replace `<zone>` with a valid AWS zone, and `test-snapshot` with a valid snapshot ID.

    3. Examine the execution environment:
        * **Check for file creation on the analysis VM (if VM is created):** If the command injection is successful and an analysis VM is launched, the injected command `touch /tmp/pwned` should execute on the VM. You would need to access the analysis VM (e.g., via SSH if you configured a key) and check for the existence of the `/tmp/pwned` file. Note that depending on the execution flow and permissions, the VM might not fully initialize or be accessible.
        * **Check for command execution by observing S3 bucket activity:** Even if the VM creation or access fails, the command injection may still occur during the userdata execution phase. In this case, you can observe the S3 bucket `test-bucket`. If the command injection is successful, you might see unexpected objects or directories created in your `test-bucket` S3 bucket due to the injected commands interacting with `aws s3 cp`. For example, if you replace `touch /tmp/pwned` with `mkdir s3://test-bucket/pwned_dir`, you would check if a `pwned_dir` directory is created in your S3 bucket.

    4. Expected result:
        * If the vulnerability is successfully exploited, the injected command `touch /tmp/pwned` (or a variation thereof) will be executed on the analysis VM or have side effects observable in the S3 bucket, demonstrating command injection.
        * If no `pwned` file is created in `/tmp` on the analysis VM and no unexpected changes occur in the S3 bucket, the vulnerability may not be exploitable with this specific test case, or mitigations might be in place (though none are evident from the source code).

    **Note:** This test case assumes that the user running `cloudforensics` has sufficient AWS permissions to create EC2 instances and interact with S3. The success of the command injection depends on the privileges of the user context under which `ebs_snapshot_copy_aws.sh` is executed within the analysis VM.
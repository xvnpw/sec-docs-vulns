- Vulnerability Name: **Unvalidated Input in VM Name Parameter leading to Command Injection**
- Description:
    - An attacker could socially engineer a user into using a modified version of the `cgpu-h100-auto-onboarding.sh` script.
    - The attacker modifies the script to introduce malicious code that gets executed due to insufficient input validation on the `vmname_prefix` parameter.
    - Specifically, the `vmname_prefix` parameter is used to construct the VM name in a loop. If this parameter contains shell- Metacharacters, they are not properly sanitized before being used in the `az vm create` command within the script.
    - A malicious user could inject commands by providing a `vmname_prefix` like `"test-vm\`\`command_injection\`\`"`.
    - When the script iterates and constructs the VM name, the injected commands within backticks will be executed by the shell during variable assignment.
- Impact:
    - **High**
    - Arbitrary command execution on the user's machine with the privileges of the user running the script.
    - In a successful exploit, an attacker could potentially gain initial access, escalate privileges, or compromise the Azure environment by manipulating Azure CLI commands execution context.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - None. The script does not perform any input validation or sanitization on the `vmname_prefix` parameter.
- Missing Mitigations:
    - Input validation and sanitization for the `vmname_prefix` parameter in `cgpu-h100-auto-onboarding.sh` to prevent command injection.
    - Use of parameterized queries or functions for Azure CLI commands to avoid direct string concatenation of user inputs into shell commands.
- Preconditions:
    - The attacker needs to successfully socially engineer a user into downloading and executing a modified version of the `cgpu-h100-auto-onboarding.sh` script.
    - The user must execute the modified script without inspecting its contents and with sufficient Azure CLI permissions to create VMs.
- Source Code Analysis:
    - In `/code/src/cgpu-h100-auto-onboarding.sh`, the `vmname_prefix` variable is directly used in a string to construct the `vmname` variable within a loop.
    - Lines 301-308 show the VM name construction:
    ```bash
    for ((current_vm_count=1; current_vm_count <= total_vm_number; current_vm_count++))
    do
        is_success="Succeeded"
        if [ $current_vm_count == 1 ];
        then
            vmname="${vmname_prefix}";
        else
            vmname_ending=$(($current_vm_count));
            vmname="${vmname_prefix}-${vmname_ending}"
        fi
    ```
    - The `vmname` variable is then used in the `az vm create` command in `create_vm()` function (line 406 onwards), specifically in the `--name` parameter:
    ```bash
    az vm create \
        --resource-group $rg \
        --name $vmname \
        ...
    ```
    - If `vmname_prefix` contains backticks or other command substitution characters, these will be interpreted by the shell during variable assignment, leading to command injection.
- Security Test Case:
    1. **Prepare Malicious Script**: Modify `cgpu-h100-auto-onboarding.sh` or create a separate script that mimics its parameter parsing but includes a command injection payload in the `vmname_prefix`.
        - Example modified script (simplified for demonstration):
        ```bash
        #!/bin/bash
        vmname_prefix="test-vm\`\`touch /tmp/pwned\`\`"
        rg="test-rg"
        location="eastus2"
        image_name="Canonical:0001-com-ubuntu-confidential-vm-jammy:22_04-lts-cvm"
        image_version="latest"
        adminuser_name="testuser"
        public_key_path_with_at="@/path/to/your/public_key.pub" # Replace with a valid public key path

        vmname="${vmname_prefix}"

        az vm create \
            --resource-group $rg \
            --name $vmname \
            --location $location \
            --image $image_name:$image_version \
            --public-ip-sku Standard \
            --admin-username $adminuser_name \
            --ssh-key-values $public_key_path_with_at \
            --security-type ConfidentialVM \
            --os-disk-security-encryption-type DiskWithVMGuestState \
            --enable-secure-boot true \
            --enable-vtpm true \
            --size Standard_NCC40ads_H100_v5 \
            --os-disk-size-gb 100 \
            --verbose
        ```
    2. **Social Engineering**:  Assume the role of an attacker and trick a user into downloading and running this modified script. This step is based on the assumed attack vector and is not directly tested here, but is a necessary precondition.
    3. **Execute the Malicious Script**: The user executes the modified script: `bash modified-cgpu-h100-auto-onboarding.sh -t "<tenant ID>" -s "<subscription ID>" -r "test-rg" -p "/path/to/your/public_key.pub" -i "/path/to/your/private_key" -c "./cgpu-onboarding-package.tar.gz" -a "testuser" -v "ignored-prefix" -n 1` (Replace placeholders with actual values, the `-v` parameter is ignored in the modified example but included for context).
    4. **Verify Command Injection**: After running the script, check if the command `touch /tmp/pwned` was executed. In a Linux environment, you can SSH into the machine where the script was run and check for the existence of the `/tmp/pwned` file. If the file exists, command injection was successful. Alternatively, observe the output logs for any unexpected commands being executed or errors indicating command execution.
    5. **Expected Result**: The file `/tmp/pwned` should be created, demonstrating that the injected command in `vmname_prefix` was executed during script execution. This confirms the command injection vulnerability.
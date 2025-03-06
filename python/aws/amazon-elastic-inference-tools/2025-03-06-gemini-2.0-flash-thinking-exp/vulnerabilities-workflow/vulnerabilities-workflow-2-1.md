### Vulnerability List

- Vulnerability Name: SSH Command Injection via Key Pair Name

- Description:
    1. The `amazonei_setup.py` script generates an SSH command to connect to the launched EC2 instance.
    2. This command is constructed using string formatting, including the selected key pair name.
    3. If an attacker can somehow influence the key pair names available in the AWS account (which is a separate security issue outside of this script's scope), they could create a key pair with a malicious name containing shell command injection payloads.
    4. When a user runs `amazonei_setup.py` and selects this maliciously named key pair, the script will generate an SSH command string that includes the malicious payload.
    5. If the user blindly copies and executes this generated SSH command in their terminal, the injected commands will be executed on their local machine.

- Impact:
    - Execution of arbitrary commands on the local machine of the user who executes the generated SSH command.
    - This could lead to data theft, malware installation, or complete compromise of the user's local system, depending on the injected commands.

- Vulnerability Rank: Medium (due to preconditions and user interaction required for exploitation, it's not directly exploitable on the EC2 instance itself, but on the user's local machine)

- Currently Implemented Mitigations:
    - None. The script does not perform any sanitization or validation of the key pair name before including it in the SSH command string.

- Missing Mitigations:
    - Input sanitization: The script should sanitize the key pair name retrieved from AWS before including it in the SSH command string. This could involve removing or escaping shell-sensitive characters.
    - Output encoding: While generating the SSH command, ensure proper encoding or quoting of the key pair name to prevent shell injection, even if the key pair name contains special characters.
    - User warning: Display a clear warning to the user, advising them to carefully review the generated SSH command before executing it, especially if they are unsure about the source or integrity of the key pair names in their AWS account. However, relying on user awareness is generally not a robust mitigation.

- Preconditions:
    1. An attacker must be able to influence the key pair names available in the AWS account being used to run the `amazonei_setup.py` script. This is a significant precondition and likely requires a separate compromise of the AWS account.
    2. A user must run the `amazonei_setup.py` script and select the maliciously named key pair.
    3. The user must blindly copy and execute the generated SSH command in their local terminal without reviewing it.

- Source Code Analysis:
    1. In `EC2.get_instance_ssh_command(self, instance_id, platform, key_pair)` function, the `ssh_command` is constructed using f-string formatting:
    ```python
    ssh_command = 'ssh -i "{}.pem" {}@{}'.format(key_pair,user,dns)
    ```
    2. The `key_pair` variable comes directly from the user's selection in `UserInput.get_key_pair()`:
    ```python
    def get_key_pair(self):
        response = self._ec2.get_keypairs()
        key_pairs = response['KeyPairs']
        ...
        return key_pairs[selection]['KeyName']
    ```
    3. If a key pair with a name like `test"; whoami > /tmp/pwned #` exists in the AWS account and is selected by the user, the generated `ssh_command` will be:
    ```
    ssh -i "test"; whoami > /tmp/pwned #.pem" ec2-user@<dns>
    ```
    4. When a user executes this command in a shell, the shell will interpret `;` as a command separator and execute `whoami > /tmp/pwned` before attempting the SSH command (which will likely fail due to the modified syntax).

- Security Test Case:
    1. **Pre-Setup (Manual in AWS Console):**
        - Create an EC2 Key Pair in the AWS region you intend to use with a malicious name, for example: `test\"; touch /tmp/pwned #`. Note: AWS might have restrictions on allowed characters in key pair names, so a simpler name like `test";command #` might be necessary if AWS restricts special characters. If AWS console prevents this, try AWS CLI to create keypair with malicious name. If even AWS CLI prevents, then this vulnerability becomes theoretical. Assuming key pair name can be created with `;`.
    2. **Run the `amazonei_setup.py` script:**
        ```bash
        python amazonei_setup.py --region <your_region> --instance-type m5.large
        ```
        - Follow the prompts and select the maliciously named key pair (`test\"; touch /tmp/pwned #` or similar).
        - Continue with the setup process until the script generates the SSH command and prints it to the console.
    3. **Copy and Execute the Generated SSH Command:**
        - Carefully copy the generated SSH command from the script's output and paste it into your local terminal.
        - Execute the command.
    4. **Verify Command Injection:**
        - Check if the injected command was executed. In this example, check if the file `/tmp/pwned` was created on your local machine.
        ```bash
        ls /tmp/pwned
        ```
        - If the file `/tmp/pwned` exists, it confirms that command injection occurred due to the maliciously crafted key pair name and execution of the generated SSH command.
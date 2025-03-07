### Vulnerability List

- Vulnerability Name: Command Injection in Certificate Generation
- Description: The `cert_gen` function in `setup_ota_update.py` uses `os.system` to execute openssl commands for certificate generation. User-provided email address is incorporated into the openssl configuration file. By injecting shell commands into the email address input, a malicious user can execute arbitrary commands on the system when `os.system` is called. Specifically, the vulnerability lies in the `cert_gen` function where the user-provided `email_address` is used to create a certificate configuration file (`cert_config.txt`) which is then passed to the `openssl req` command via `os.system`.  Unsanitized input in `email_address` allows for command injection through shell metacharacters.
- Impact: Successful command injection allows an attacker to execute arbitrary commands on the system running the script with the privileges of the script's user. This can lead to severe consequences, including unauthorized access to AWS credentials, manipulation of AWS resources, data exfiltration, and complete system compromise.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations: None. The code directly uses user input in a system command without any input sanitization or validation.
- Missing Mitigations:
    - Input validation and sanitization for the email address. Validate that the email address conforms to expected email format and crucially, sanitize or reject any input containing shell metacharacters (e.g., `;`, `&`, `|`, `$`, `` ` ``, `\`, newline).
    - Avoid using `os.system`. Replace `os.system` with safer alternatives like `subprocess.run` with proper argument handling to prevent shell injection. Ideally, use a Python library for certificate generation to avoid calling external commands altogether.
- Preconditions:
    - The attacker must be able to execute the `setup_ota_update.py` script.
    - The attacker must choose to create a new ACM Certificate when prompted by the script.
- Source Code Analysis:
    1. In `/code/source/setup_ota_update.py`, the `cert_gen` function is defined, taking `email_address` as input:
    ```python
    def cert_gen(aws_proxy, email_address="emailAddress"):
        email = {'email': email_address}
        with open("cert_template.txt", "r", encoding="utf-8") as cert_template:
            src = Template(cert_template.read())
            result = src.substitute(email)
        with open("cert_config.txt", "w", encoding="utf-8") as cert_config:
            cert_config.write(result)

        os.system("openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
                   -pkeyopt ec_param_enc:named_curve -outform PEM -out ecdsasigner-priv-key.pem")
        os.system("openssl req -new -x509 -config cert_config.txt -extensions my_exts \
                   -nodes -days 365 -key ecdsasigner-priv-key.pem -out ecdsasigner.crt")
        ...
    ```
    2. The `email_address` parameter, obtained directly from user input during script execution, is embedded within the `cert_config.txt` file through template substitution.
    3. The `cert_config.txt` file is then passed as an argument to the `openssl req` command via `os.system`.
    4. A malicious email address containing shell command separators, such as `"; touch /tmp/pwned"`, will be written into `cert_config.txt`. When `os.system` executes `openssl req`, the shell interprets the semicolon as a command separator, executing `touch /tmp/pwned` after the intended `openssl req` command.
- Security Test Case:
    1. Execute the script `setup_ota_update.py`: `python3 setup_ota_update.py`.
    2. When the script prompts "Create a new ACM Certificate." or "Use an existing ACM Certificate.", select "Create a new ACM Certificate" by entering 'a'.
    3. When prompted "Enter an email to use for the certificate", input the following payload: `"; touch /tmp/pwned"`.
    4. Proceed through the rest of the script's prompts with valid inputs as needed to allow the `cert_gen` function to execute.
    5. After the script completes, verify the existence of the file `/tmp/pwned`. If this file exists, the command injection was successful.
### Vulnerability Report

#### 1. Command Injection in `https-rewrite.py` via `cert_name`

- **Description:**
    - The `https-rewrite.py` script, used during the `SetupInstanceHttps` API call in Amazon Lightsail, takes a certificate name as a command-line argument (`cert_name`).
    - This `cert_name` is directly embedded into a shell command: `f'certbot certificates | grep "Certificate Name: {cert_name}" -A{LINES_AFTER} | grep "Domains: "'`.
    - The command is executed using `subprocess.run` with `shell=True`, allowing shell metacharacters in `cert_name` to be interpreted as commands.
    - An attacker controlling the `cert_name` argument can inject malicious shell commands. For example, a `cert_name` like `"test"; whoami #` injects the `whoami` command.

- **Impact:**
    - Arbitrary shell command execution on the Lightsail instance.
    - Full compromise of the instance is possible, leading to unauthorized data access, malware installation, data modification, denial of service, and potential lateral movement in AWS.

- **Vulnerability Rank:** Critical

- **Currently Implemented Mitigations:**
    - None. No input validation or sanitization is performed on the `cert_name` argument.

- **Missing Mitigations:**
    - **Input Validation and Sanitization:** Validate `cert_name` to allow only safe characters (alphanumeric, hyphens, dots).
    - **Use `shlex.quote`:** If `shell=True` is necessary, use `shlex.quote` to escape `cert_name`.
    - **Avoid `shell=True`:**  Pass commands and arguments as a list to `subprocess.run` to prevent shell interpretation. Rewrite the command to avoid shell usage entirely, processing `certbot certificates` output directly in Python.

- **Preconditions:**
    - Attacker can control the `cert_name` parameter passed to `https-rewrite.py` via the `SetupInstanceHttps` API call.

- **Source Code Analysis:**
    - File: `/code/https-rewrite.py`
    - Function: `main()`
    - Line: `cert_name = argv[1]` - Unvalidated input from command-line argument.
    - Line: `returncode, stdout, stderr = run_cmd(f'certbot certificates | grep "Certificate Name: {cert_name}" -A{LINES_AFTER} | grep "Domains: "')` - Vulnerable command construction with `shell=True` and unsanitized `cert_name`.

    ```
    [Untrusted Input: cert_name from API] --> argv[1] --> cert_name (Unsanitized) -->
    f-string command construction: 'certbot certificates | grep "Certificate Name: {cert_name}" ...' -->
    subprocess.run(..., shell=True, command) -->
    [Operating System Shell] --> [Arbitrary Command Execution]
    ```

- **Security Test Case:**
    1. Setup: Prepare a Lightsail instance and monitor `https-rewrite.py` execution.
    2. Craft Malicious `certificateName`:  `"test-cert"; touch /tmp/pwned_https_rewrite #"`
    3. Trigger `SetupInstanceHttps` API: Invoke the API with the malicious `certificateName`.
    4. Observe Instance: Check for `/tmp/pwned_https_rewrite` on the instance via SSH.
    5. Verify Command Execution: Presence of the file confirms command injection.
    6. Check Logs (Optional): Examine script logs for injected command execution.

#### 2. Insecure File Permissions on SSL Certificate and Private Key Files

- **Description:**
    - Scripts for HTTPS setup on Lightsail WordPress instances using Let's Encrypt and Certbot do not explicitly enforce secure permissions on SSL certificate (`fullchain.pem`) and private key (`privkey.pem`) files.
    - Default permissions might be overly permissive in shared Lightsail environments.
    - A local attacker gaining unauthorized instance access can read these files.
    - Access to the private key allows website impersonation, man-in-the-middle attacks, and decryption of HTTPS traffic.

- **Impact:**
    - Website impersonation for phishing or malware distribution.
    - Man-in-the-middle attacks compromising sensitive data.
    - Loss of confidentiality and integrity of website traffic.
    - Brand reputation damage due to data breaches.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
    - None. Scripts rely on default file permissions set by Certbot and the OS.

- **Missing Mitigations:**
    - **Explicitly set restrictive permissions:**
        - `privkey.pem`: `0600` (owner read/write only, root owner).
        - `fullchain.pem`: `0644` (owner read/write, group/others read) or `0640` (owner/group read/write), root owner, root or dedicated SSL group.
    - **File permission checks:** Implement checks in scripts to verify and alert on insecure permissions.
    - **Documentation:** Warn users about secure file permissions and provide manual verification/setting instructions.

- **Preconditions:**
    - WordPress instance on Lightsail with HTTPS enabled via provided scripts.
    - Successful certificate generation using Certbot.
    - Local attacker gains unauthorized access to the instance.

- **Source Code Analysis:**
    - Scripts `/code/https-rewrite.py` and `/code/le-cert-renewal.py` lack logic to set file permissions for SSL certificate files.
    - Scripts rely on default permissions from Certbot and OS.

- **Security Test Case:**
    1. Deploy WordPress instance on Lightsail.
    2. Set up HTTPS using `https-rewrite.py <your_certificate_name>`.
    3. SSH into the instance as `bitnami` user.
    4. Navigate to `/etc/letsencrypt/live/<your_domain>/`.
    5. List file permissions: `ls -l privkey.pem fullchain.pem`.
    6. Attempt to read private key: `cat privkey.pem`.
    7. Vulnerability confirmed if `bitnami` user can read `privkey.pem`. Secure config requires `privkey.pem` to be readable only by root (permissions `0600`).
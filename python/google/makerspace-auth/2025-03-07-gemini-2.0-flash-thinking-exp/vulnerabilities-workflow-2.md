## Vulnerabilities Found

### Command Injection via Configuration

- **Vulnerability Name:** Command Injection via Configuration

- **Description:**
    - The application uses a configuration file to define commands that are executed by the system.
    - The `_get_command_line` function in `software/two_button.py` and `software/lockbox.py` constructs command lines from configuration values using `shlex.split` and string formatting.
    - Specifically, the configuration options such as `auth.command`, `auth.extend_command`, `auth.deauth_command`, and `sounds.command` are vulnerable.
    - An attacker who can modify the configuration file (e.g., by compromising the Raspberry Pi or through other means if configuration is externally managed) can inject arbitrary commands into these configuration values.
    - When the application executes these commands (e.g., during badge scan or button press), the injected commands will be executed by the system.
    - For example, if the `auth.command` is set to `/bin/echo 'User: {}' && malicious_command`, and the badge ID is scanned, the `malicious_command` will be executed in addition to the intended `echo` command.

- **Impact:**
    - **High/Critical**: Successful command injection can allow an attacker to execute arbitrary code on the Raspberry Pi running the authbox software.
    - This can lead to full system compromise, including:
        - Unauthorized access to the tool controlled by the authbox.
        - Data exfiltration from the Raspberry Pi.
        - Installation of malware or backdoors.
        - Denial of service by crashing the system or disrupting operations.
        - Privilege escalation if the authbox software is running with elevated privileges (though the provided systemd service example runs as user `pi`).

- **Vulnerability Rank:** Critical

- **Currently Implemented Mitigations:**
    - **None**: The code does not implement any specific mitigations against command injection in the `_get_command_line` function or when handling configuration values that are used to construct commands.
    - The use of `shlex.split` is intended for safer command line parsing, but it does not prevent command injection if the configuration values themselves are malicious.

- **Missing Mitigations:**
    - **Input Validation and Sanitization**: The application should validate and sanitize configuration values, especially those used to construct commands.  Restrict allowed characters and command structures in configuration.
    - **Principle of Least Privilege**: Ensure the authbox software runs with the minimum necessary privileges. The provided systemd script runs as user `pi`, which is a good starting point, but further privilege reduction might be possible.
    - **Configuration File Protection**: Secure the configuration file (`.authboxrc`) to prevent unauthorized modifications. File system permissions should restrict write access to only the administrative user.
    - **Sandboxing/Isolation**: Consider running the command execution in a sandboxed environment or container to limit the impact of successful command injection.
    - **Code Review**: Thoroughly review all code paths that involve command execution, especially those that use configuration values as part of the command.

- **Preconditions:**
    - **Configuration File Modification**: An attacker must be able to modify the configuration file (`.authboxrc`). This could be achieved through:
        - Direct access to the Raspberry Pi's file system (e.g., via SSH if enabled with default credentials, physical access, or exploiting other vulnerabilities to gain access).
        - If the configuration is managed remotely, compromising the remote management system.

- **Source Code Analysis:**
    - **File: `software/two_button.py` and `software/lockbox.py`**
    - Function: `_get_command_line(self, section, key, format_args)`

    ```python
    def _get_command_line(self, section, key, format_args):
        value = self.config.get(section, key) # [1] Retrieve configuration value
        pieces = shlex.split(value)          # [2] Split into arguments
        return [p.format(*format_args) for p in pieces] # [3] Format each piece
    ```
    - **Step 1**: `value = self.config.get(section, key)` retrieves the command string from the configuration file based on the `section` and `key` provided (e.g., `auth.command`).
    - **Step 2**: `pieces = shlex.split(value)` uses `shlex.split` to parse the command string into a list of arguments. While `shlex.split` helps to handle quoting and escaping, it doesn't prevent injection if the entire `value` is maliciously crafted.
    - **Step 3**: `return [p.format(*format_args) for p in pieces]` iterates through the parsed pieces and applies string formatting using `format_args`. In the context of `badge_scan`, `format_args` is `[badge_id]`.
    - **Vulnerability**: If the configuration value retrieved in **Step 1** is attacker-controlled and contains malicious commands or format specifiers, and if the scripts called by `auth.command` are also vulnerable to command injection, then arbitrary commands can be executed. Even if scripts are safe, malicious commands can be directly embedded in the configuration value itself.

- **Security Test Case:**
    - **Pre-Test Setup**:
        - Assume a Raspberry Pi is running the `two_button.py` script.
        - Access the Raspberry Pi's filesystem (e.g., via SSH or directly if possible for testing purposes).
        - Locate the configuration file, typically `~/.authboxrc`.
    - **Step 1**: Modify the configuration file (`~/.authboxrc`) and change the `auth.command` value in the `[auth]` section to include a malicious command. For example:
        ```ini
        [auth]
        command = /bin/touch /tmp/pwned_{}
        duration = 20s
        warning = 10s
        extend = 20s
        deauth_command = rm -f enabled
        ```
    - **Step 2**: Scan any RFID badge using the badge reader connected to the Raspberry Pi.
    - **Step 3**: Check if the malicious command was executed. In this example, check if a file named `pwned_<badge_id>` (where `<badge_id>` is the scanned badge ID) was created in the `/tmp/` directory on the Raspberry Pi.
    - **Expected Result**: If the vulnerability exists, the file `/tmp/pwned_<badge_id>` will be created, indicating successful command injection.
    - **Cleanup**: Remove the modified `auth.command` from the configuration file and delete the created test file `/tmp/pwned_<badge_id>`.

### Command Injection via Badge ID in Shell Script Execution

- **Vulnerability Name:** Command Injection via Badge ID in Shell Script Execution

- **Description:**
    1. The Python scripts `lockbox.py` and `two_button.py` use the `_get_command_line` method to construct shell commands from configuration parameters like `auth.command`, `auth.extend_command`, and `auth.deauth_command`.
    2. The `_get_command_line` method uses `shlex.split` to parse the command string from the configuration.
    3. The badge ID, obtained from the badge reader, is directly passed as an argument to the shell command using string formatting (`p.format(*format_args)`).
    4. If a malicious badge ID containing shell metacharacters (e.g., `;`, `$()`, `` ` ``) is scanned, these characters will be passed to the shell command without proper sanitization.
    5. When `subprocess.call(command)` is executed, the shell will interpret these metacharacters, leading to command injection.
    6. An attacker can craft a badge ID that, when scanned and processed by the system, executes arbitrary shell commands on the Raspberry Pi.

- **Impact:**
    - An attacker can execute arbitrary commands on the Raspberry Pi client.
    - This can lead to unauthorized access to the tool, bypassing the intended authorization mechanism.
    - The attacker could potentially escalate privileges, access sensitive data, or disrupt the system's operation.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
    - None. The code uses `shlex.split` for parsing the command, which is intended for safe command-line argument parsing, but it does not sanitize the badge ID input itself before formatting it into the command.

- **Missing Mitigations:**
    - Input validation and sanitization for the badge ID in the Python scripts before passing it to the shell command.
    - Use parameterized queries or similar safe mechanisms when constructing shell commands to prevent injection. Instead of string formatting, consider using `subprocess.Popen` with a list of arguments where the badge ID is passed as a separate argument, which is generally safer as `subprocess` handles escaping.

- **Preconditions:**
    - The attacker needs to be able to present a crafted badge to the RFID reader.
    - The system must be configured to use shell scripts for authorization (`auth.command`, etc.). This is the default configuration with `sample_auth_check.sh` in the example.

- **Source Code Analysis:**
    1. **File: `/code/software/two_button.py` (and `/code/software/lockbox.py`)**
    2. **Function: `_get_command_line(self, section, key, format_args)`**
    ```python
    def _get_command_line(self, section, key, format_args):
        """Constructs a command line, safely.

        ...
        """
        value = self.config.get(section, key)
        pieces = shlex.split(value)
        return [p.format(*format_args) for p in pieces]
    ```
    - The code retrieves the command string from the config file using `self.config.get(section, key)`.
    - It uses `shlex.split(value)` to split the command string into a list of arguments. `shlex.split` is designed to safely split command lines into arguments, respecting quotes and escapes, but it does not sanitize the *content* of the arguments themselves.
    - `return [p.format(*format_args) for p in pieces]` : This line formats each piece of the command with the provided `format_args`. In `badge_scan`, `format_args` is `[badge_id]`. This is where the unsanitized badge ID is inserted into the command.

    3. **Function: `badge_scan(self, badge_id)`**
    ```python
    def badge_scan(self, badge_id):
        # Malicious badge "numbers" that contain spaces require this extra work.
        command = self._get_command_line('auth', 'command', [badge_id])
        # TODO timeout
        # TODO test with missing command
        rc = subprocess.call(command)
        ...
    ```
    - The `badge_scan` function calls `_get_command_line` to construct the command with the `badge_id`.
    - `subprocess.call(command)` executes the constructed command using the shell.

    **Visualization:**

    ```
    Configuration File (.authboxrc):
    [auth]
    command = /path/to/sample_auth_check.sh {0} tool_name auth_duration

    Python Code (two_button.py - badge_scan):
    badge_id = "; touch /tmp/pwned #"  <- Malicious Badge ID
    command_pieces = shlex.split("/path/to/sample_auth_check.sh {0} tool_name auth_duration")
    command_with_badge_id = [p.format(badge_id) for p in command_pieces]
    command_with_badge_id becomes:
    ['/path/to/sample_auth_check.sh', '; touch /tmp/pwned #', 'tool_name', 'auth_duration']
    subprocess.call(command_with_badge_id)

    Shell Execution:
    /bin/sh -c '/path/to/sample_auth_check.sh '; touch /tmp/pwned #'; 'tool_name' 'auth_duration'
    ```

- **Security Test Case:**
    1. **Precondition:** Ensure the system is set up to use `sample_auth_check.sh` (or similar script-based authorization).
    2. **Action:** Craft a badge ID containing a shell command injection payload, for example: `; touch /tmp/pwned #`.
    3. **Action:** Present this crafted badge to the RFID reader.
    4. **Expected Result:**
        - The `sample_auth_check.sh` script will be executed.
        - The injected command `touch /tmp/pwned` will also be executed by the shell.
        - Verify the command injection by checking if the file `/tmp/pwned` is created on the Raspberry Pi.
        - Check the logs (e.g., `log.txt` if used by `sample_auth_check.sh`) to observe the execution flow and potential errors.
    5. **Cleanup:** Remove the `/tmp/pwned` file after the test.

### RFID Badge Replay Attack

- **Vulnerability Name:** RFID Badge Replay Attack

- **Description:**
  1. An attacker with a simple RFID reader (easily obtainable online) can passively eavesdrop and record the RFID signals transmitted by legitimate users' badges when they authenticate with the system.
  2. The attacker can then replay these recorded signals to the RFID reader connected to the access control system at a later time.
  3. The system, upon receiving the replayed RFID signal, processes it as if it were from a legitimate user.
  4. If the replayed badge ID corresponds to an authorized user, the system grants unauthorized access to the controlled tool or resource.

- **Impact:**
  - Unauthorized access to tools and resources controlled by the RFID access control system.
  - Circumvention of intended access control policies, potentially leading to misuse, damage, or theft of equipment.
  - Compromise of safety measures if access to dangerous tools is granted to untrained or unauthorized individuals.
  - Loss of accountability and audit trails, as unauthorized access may be logged under a legitimate user's identity.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
  - None. Based on the provided project files, there are no explicit mitigations implemented to prevent RFID badge replay attacks. The system relies on simple badge ID checks without any cryptographic protection or dynamic elements to prevent replay attacks.

- **Missing Mitigations:**
  - **Mutual Authentication:** Implement a mutual authentication protocol between the RFID badge and the reader. This would involve cryptographic challenge-response mechanisms to verify the authenticity of both the badge and the reader in each transaction, preventing replay attacks.
  - **Encryption:** Encrypt the communication between the RFID badge and reader. This would make it harder for attackers to eavesdrop and understand the transmitted data, although encryption alone might not prevent replay attacks if the encryption scheme is static or predictable.
  - **Rolling Codes/One-Time Passwords:** Utilize RFID badges that generate rolling codes or one-time passwords for each authentication attempt. This would invalidate previously captured signals, rendering replay attacks ineffective.
  - **Time-based Tokens:** Implement time-based tokens or session identifiers that are validated by the access control system. These tokens would expire after a short period, limiting the window of opportunity for replay attacks.
  - **Anomaly Detection:** Implement monitoring and anomaly detection mechanisms to identify unusual access patterns, such as multiple access attempts from the same badge ID within a short timeframe from geographically distant locations, which could indicate a replay attack.

- **Preconditions:**
  1. An attacker must be within the reading range of the RFID badge reader when a legitimate user authenticates.
  2. The attacker must possess an RFID reader capable of capturing and replaying RFID signals (easily and cheaply available).
  3. The attacker must target a badge ID that belongs to an authorized user for the specific tool or resource they wish to access.

- **Source Code Analysis:**

  1. **Badge Reading:** The project uses `HIDKeystrokingReader` (`software/authbox/badgereader_hid_keystroking.py`) or `WiegandGPIOReader` (`software/authbox/badgereader_wiegand_gpio.py`) to read badge IDs. These readers, as implemented, simply capture and transmit the static badge ID.
  ```python
  # software/authbox/badgereader_hid_keystroking.py - Extracts badge ID as keystrokes
  class HIDKeystrokingReader(BaseDerivedThread):
      # ...
      def read_input(self):
          rfid = ""
          # ...
          for event in device.read_loop():
              # ... extracts characters and appends to rfid string
          return rfid

  # software/authbox/badgereader_wiegand_gpio.py - Reads badge ID bits from GPIO pins
  class WiegandGPIOReader(BaseWiegandPinThread):
      # ...
      def read_input(self):
          # ... reads bits from GPIO and constructs badge id string
          return "".join(bits)
  ```
  Neither of these readers implements any security measures to prevent signal cloning or replay. They are designed to simply read and pass on the static badge ID.

  2. **Authentication Scripts:** The core logic relies on external scripts (e.g., `sample_auth_check.sh`, `sample_extend.sh`, `sample_deauth.sh`) configured in the `.authboxrc` file.  The `two_button.py` and `lockbox.py` scripts use `_get_command_line` to execute these scripts.
  ```python
  # software/two_button.py and software/lockbox.py - Command execution
  class Dispatcher(BaseDispatcher):
      # ...
      def _get_command_line(self, section, key, format_args):
          value = self.config.get(section, key)
          pieces = shlex.split(value)
          return [p.format(*format_args) for p in pieces]

      def badge_scan(self, badge_id):
          command = self._get_command_line('auth', 'command', [badge_id]) # Constructs command from config
          rc = subprocess.call(command) # Executes the command
          # ...
  ```
  The `sample_auth_check.sh` script performs a very basic check by grepping for the badge ID in a local `authorized.txt` file.
  ```bash
  #!/bin/bash
  # software/sample_auth_check.sh
  # ...
  user=$1 # badge id is passed as the first argument
  # ...
  grep -qw "$user" authorized.txt # simple check if badge id exists in authorized.txt
  ```
  These sample scripts lack any mechanism to verify the freshness or authenticity of the RFID signal. They simply check if the provided badge ID is authorized, making them vulnerable to replay attacks.

  3. **Configuration:** The configuration files (`.authboxrc`, example `SAMPLE_CONFIG` in `test_two_button.py`) define the hardware components and authentication commands.  There are no configuration options related to security measures against replay attacks.

  **Visualization:**

  ```mermaid
  sequenceDiagram
      participant Attacker RFID Reader
      participant Legitimate User Badge
      participant RFID Reader System
      participant Auth Script
      participant Controlled Tool

      Note over Attacker RFID Reader, Legitimate User Badge: Eavesdropping Phase
      Legitimate User Badge ->> Attacker RFID Reader: RFID Signal (Badge ID)
      Attacker RFID Reader -->> Attacker RFID Reader: Record RFID Signal

      Note over Attacker RFID Reader, RFID Reader System: Replay Attack Phase
      Attacker RFID Reader ->> RFID Reader System: Replayed RFID Signal (Badge ID)
      RFID Reader System ->> Auth Script: Execute Auth Script with Replayed Badge ID
      Auth Script -->> Auth Script: Check Authorized Users (e.g., authorized.txt)
      Auth Script -->> RFID Reader System: Authorization Success (if badge ID is valid)
      RFID Reader System ->> Controlled Tool: Enable Tool Access
      Attacker RFID Reader ->> Controlled Tool: Gain Unauthorized Access
  ```

- **Security Test Case:**

  1. **Setup:**
     a. Set up the Makerspace Auth system using the provided code, including a functional RFID reader and a tool controlled by a relay.
     b. Configure the system with `sample_auth_check.sh` and an `authorized.txt` file containing at least one authorized badge ID.
     c. Have a legitimate user with an authorized RFID badge.
     d. Prepare an RFID signal capturing and replaying tool (e.g., Proxmark3, or a simple RFID cloner/reader capable of replay).

  2. **Capture Legitimate Badge Signal:**
     a. Position the attacker's RFID reader near the Makerspace Auth system's RFID reader.
     b. Have the legitimate user present their authorized RFID badge to the system's reader to gain access (perform a normal authorized access).
     c. Simultaneously, use the attacker's RFID reader to capture and record the RFID signal transmitted by the legitimate user's badge during this authentication process.

  3. **Replay Attack:**
     a. After the legitimate user has finished and access is no longer needed, have the attacker approach the Makerspace Auth system with their RFID replay tool.
     b. Use the replay tool to transmit the previously recorded RFID signal to the system's RFID reader.
     c. Observe if the Makerspace Auth system grants access to the controlled tool upon receiving the replayed signal, even though it is not from the legitimate user's badge at the present time.

  4. **Verification:**
     a. If the system grants access after replaying the captured RFID signal, this confirms the RFID badge replay vulnerability. The attacker has successfully bypassed the intended access control by replaying a previously captured legitimate signal.
     b. Verify that the access logs, if implemented, show the unauthorized access attempt as being associated with the legitimate user's badge ID, further highlighting the impact of the replay attack.
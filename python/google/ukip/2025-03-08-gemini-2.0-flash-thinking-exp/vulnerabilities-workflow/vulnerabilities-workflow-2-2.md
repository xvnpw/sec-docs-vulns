- Vulnerability Name: **ABNORMAL_TYPING Threshold Misconfiguration**
- Description:
    - The `ABNORMAL_TYPING` threshold, which determines the maximum inter-keystroke time considered normal, is configurable during installation via the `setup.sh` script.
    - An administrator may misconfigure this value to be excessively high (e.g., 1 second or more).
    - If the threshold is set too high, an attacker can craft a keystroke injection attack that injects keystrokes at a speed slower than this configured threshold, yet still fast enough to be an attack.
    - UKIP will then fail to detect the attack, as the inter-keystroke timings will fall within the configured "normal" range.
    - Step-by-step trigger:
        1. User downloads the UKIP project files.
        2. User edits the `setup.sh` file and sets the `NEW_ABNORMAL_TYPING` variable to a high value, for example, `1000000` (milliseconds, representing 1 second).
        3. User executes the `setup.sh` script to install UKIP. This script will configure `src/ukip.py` with the high `ABNORMAL_TYPING` value.
        4. An attacker gains physical access to the system and connects a USB keystroke injection device.
        5. The attacker configures the injection device to send keystrokes with inter-arrival times slightly below the configured `ABNORMAL_TYPING` threshold (e.g., 900 milliseconds).
        6. The attacker initiates the keystroke injection attack.
        7. UKIP monitors the keystroke timings, but because the inter-arrival times are below the high `ABNORMAL_TYPING` threshold, it incorrectly classifies the injected keystrokes as normal typing.
        8. UKIP does not trigger the hardening or monitoring mode, and the keystroke injection attack is successful.
- Impact:
    - Successful keystroke injection attack.
    - Depending on the injected commands, the attacker could potentially:
        - Execute arbitrary commands with the privileges of the logged-in user.
        - Install malware.
        - Exfiltrate sensitive data.
        - Disrupt system operations.
        - Gain persistence on the system.
- Vulnerability Rank: Medium
- Currently Implemented Mitigations:
    - Documentation in `README.md`: The `README.md` file advises users to adjust the `ABNORMAL_TYPING` variable and explains the trade-offs between false positives and false negatives. It suggests a default value of `50000` (microseconds, 50 milliseconds) and recommends adjusting it based on user typing speed.
    - Location: `/code/README.md` - "1) Adjust the `ABNORMAL_TYPING` variable on top of the `setup.sh` file."
- Missing Mitigations:
    - Automated threshold configuration: UKIP lacks an automated mechanism to determine a reasonable `ABNORMAL_TYPING` threshold based on user typing behavior.
    - Runtime feedback or warnings: UKIP does not provide runtime feedback or warnings if the configured `ABNORMAL_TYPING` threshold is considered too high or insecure.
    - Input validation in `setup.sh`: The `setup.sh` script does not validate the user-provided `NEW_ABNORMAL_TYPING` value to ensure it falls within a reasonable range.
- Preconditions:
    - UKIP must be installed on a Linux system.
    - The user must misconfigure the `ABNORMAL_TYPING` variable in `setup.sh` to a high value before installation.
    - An attacker must have physical access to the system to connect a USB keystroke injection device.
- Source Code Analysis:
    - `setup.sh`:
        ```bash
        NEW_ABNORMAL_TYPING=50000 # Default value
        # ...
        sed -i 's/ABNORMAL_TYPING = [^0-9]*\([0-9]\+\)/ABNORMAL_TYPING = '$NEW_ABNORMAL_TYPING'/g' src/ukip.py
        ```
        - The `setup.sh` script sets a default value for `NEW_ABNORMAL_TYPING` (50000).
        - It uses `sed` to replace the `ABNORMAL_TYPING` variable in `src/ukip.py` with the value of `NEW_ABNORMAL_TYPING`.
        - There is no input validation or range checking on `NEW_ABNORMAL_TYPING`.
    - `src/ukip.py`:
        ```python
        # Abnormal typing threshold in milliseconds (Linux emits keystroke timings in
        # microsecond precision).
        # Lower: More True Positives.
        # Higher: More False Positives.
        ABNORMAL_TYPING = 50000 # Default value is overwritten by setup.sh

        def check_for_attack(event_device_path: Text, device: usb.core.Device) -> bool:
            # ...
            for value in reversed_buffer:
                for prev in reversed_buffer:
                    if value - prev <= ABNORMAL_TYPING: # Vulnerable comparison
                        attack_counter += 1
                    value = prev
                break  # Exit after the first backward iteratation.
            # ...
        ```
        - `ABNORMAL_TYPING` is defined in `src/ukip.py` and its default value is overwritten by `setup.sh`.
        - The `check_for_attack` function compares the inter-keystroke times (`value - prev`) with the `ABNORMAL_TYPING` threshold using `<=` operator. If the difference is less than or equal to `ABNORMAL_TYPING`, it is counted as part of a potential attack.
        - A high value for `ABNORMAL_TYPING` directly weakens the attack detection capability.

- Security Test Case:
    1. **Environment Setup**: Set up a virtual machine or a test system with Linux installed. Install necessary prerequisites as mentioned in `README.md` (Python 3.7+, python dev package, virtualenv, PIP3).
    2. **Modify `setup.sh`**:
        - Open the `setup.sh` file located in the `/code` directory.
        - Locate the line `NEW_ABNORMAL_TYPING=50000`.
        - Change the value to a high number, for example, `NEW_ABNORMAL_TYPING=1000000`. This sets the abnormal typing threshold to 1000 milliseconds (1 second).
    3. **Install UKIP**:
        - Open a terminal, navigate to the `/code` directory.
        - Make `setup.sh` executable: `chmod +x setup.sh`.
        - Run the setup script: `./setup.sh`. Follow any on-screen instructions.
    4. **Prepare Keystroke Injection Attack**:
        - Use a programmable USB device capable of keystroke injection (e.g., a USB Rubber Ducky or similar).
        - Program the device to inject a sequence of commands, for example, opening a terminal and executing `whoami`.
        - Configure the injection speed of the device such that the inter-keystroke delay is around 900 milliseconds (or any value below the configured `ABNORMAL_TYPING` threshold of 1000ms). This speed is slower than a typical injection attack but still faster than normal human typing.
    5. **Execute Attack and Verify Vulnerability**:
        - Log in to the test system as a normal user.
        - Plug in the programmed USB keystroke injection device.
        - Observe the system behavior.
    6. **Expected Result**:
        - The programmed keystroke injection attack should be successful. A terminal should open, and the `whoami` command should be executed.
        - UKIP should **not** detect the attack and should **not** block or monitor the USB device.
        - Verify using `systemctl status ukip.service` that the UKIP service is running and check syslog (`/var/log/syslog` or similar) for any UKIP logs related to device blocking or monitoring; there should be none for this attack.
    7. **Cleanup**: After testing, it is recommended to revert the `ABNORMAL_TYPING` value in `setup.sh` to the default or a more secure value and reinstall UKIP to restore the intended protection level.
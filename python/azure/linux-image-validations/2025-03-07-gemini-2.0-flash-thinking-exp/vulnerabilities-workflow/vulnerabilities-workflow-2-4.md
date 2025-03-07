- Vulnerability name: Command Injection in `LoadDriver.sh` via OS detection

- Description:
  1. The `validate.py` script, executed within the validation VM, invokes `LoadDriver.sh` script.
  2. `LoadDriver.sh` script determines the OS version by executing `OS_details.sh 1` and stores the output in the `OS` variable.
  3. `OS_details.sh` script reads various OS release files within the VHD image like `/etc/oracle-release`, `/etc/redhat-release`, `/etc/SuSE-release`, `/etc/os-release`, `/etc/lsb-release`, `/etc/debian_version` to identify the OS.
  4. The identified `OS` variable is then used in a `wget` command to download a driver: `wget https://rheldriverssa.blob.core.windows.net/involflt-`tr [A-Z] [a-z] <<< $OS`/$drvName`.
  5. If an attacker crafts a malicious VHD image and modifies the OS release files (e.g., `/etc/oracle-release`) to inject a command into the output of `OS_details.sh`, this injected command will be executed as part of the `wget` command line.
  6. For example, by modifying `/etc/oracle-release` to contain `Oracle Linux Server release 7; touch /tmp/pwned`, the `OS_details.sh` script will output `OL7-64; touch /tmp/pwned`.
  7. This output, when assigned to the `OS` variable in `LoadDriver.sh`, will lead to the execution of `wget https://rheldriverssa.blob.core.windows.net/involflt-`tr [A-Z] [a-z] <<< 'OL7-64; touch /tmp/pwned'`/$drvName`.
  8. Due to shell command substitution, the `touch /tmp/pwned` command will be executed on the validation VM, achieving command injection.

- Impact:
  - Arbitrary command execution on the validation virtual machine.
  - An attacker can gain full control of the validation VM, potentially exfiltrate sensitive information, or use it as a pivot to attack other Azure resources.

- Vulnerability rank: Critical

- Currently implemented mitigations:
  - None. The code directly uses the output of `OS_details.sh` in a shell command without any sanitization or validation.

- Missing mitigations:
  - Input sanitization and validation for the output of `OS_details.sh` before using it in shell commands.
  - Securely constructing the `wget` command, avoiding shell command injection vulnerabilities. For example, by using array arguments for `wget` instead of a single string.
  - Consider using a safer way to determine OS version that is less prone to manipulation from within the VHD image itself.

- Preconditions:
  - An attacker must be able to create a malicious VHD image.
  - The validation pipeline must be executed on this malicious VHD image.

- Source code analysis:
  - File: `/code/validations/image_validator/ASR/LoadDriver.sh`
  ```sh
  #!/bin/sh

  DIR=`dirname $0`
  OS=`${DIR}/OS_details.sh 1`  # Vulnerable line: Output of OS_details.sh is directly used

  if lsmod | grep -iq involflt; then
      echo "involflt module is already loaded"
      exit 1
  fi

  # ... (OS version detection logic) ...

  echo "Downloading the driver $drvName"
  wget https://rheldriverssa.blob.core.windows.net/involflt-`tr [A-Z] [a-z] <<< $OS`/$drvName # Vulnerable line: OS variable used in command injection

  # ... (rest of the script) ...
  ```
  - File: `/code/validations/image_validator/ASR/scripts/OS_details.sh` (Example of OS detection logic)
  ```sh
  #!/bin/sh

  if [ -f /etc/oracle-release ]; then # Attacker can modify /etc/oracle-release
      if grep -q 'Oracle Linux Server release 6.*' /etc/oracle-release; then
          VERSION=`sed "s/[^0-9]*//g" /etc/oracle-release`
          if [ `uname -m` = "x86_64" -a $VERSION -ge 64 ]; then
              OS="OL6-64"
          fi
      elif grep -q 'Oracle Linux Server release 7.*' /etc/oracle-release; then # Attacker can inject command here
          if [ `uname -m` = "x86_64" ]; then
              OS="OL7-64" # If /etc/oracle-release contains "Oracle Linux Server release 7; touch /tmp/pwned", OS will be "OL7-64; touch /tmp/pwned"
          fi
      # ... (rest of OS detection logic) ...
  fi

  if [ $# -gt 0 ]
  then
      echo $OS # Output is used in LoadDriver.sh
  fi
  ```
  **Visualization:**

  ```mermaid
  sequenceDiagram
      participant Malicious VHD
      participant Validation VM
      participant LoadDriver.sh
      participant OS_details.sh
      participant wget

      Malicious VHD->>Validation VM: VHD Image with malicious /etc/oracle-release
      Validation VM->>LoadDriver.sh: Execute LoadDriver.sh
      LoadDriver.sh->>OS_details.sh: Execute OS_details.sh 1
      OS_details.sh->>Malicious VHD: Read /etc/oracle-release (malicious content)
      OS_details.sh->>LoadDriver.sh: Return "OL7-64; touch /tmp/pwned" (Command Injection)
      LoadDriver.sh->>wget: Execute wget ... `tr ... <<< 'OL7-64; touch /tmp/pwned'` ...
      wget-->>Validation VM: Execute injected command: touch /tmp/pwned
      Validation VM-->>Malicious VHD: Command executed successfully
  ```

- Security test case:
  1. Create a new directory for the malicious VHD.
  2. Create a dummy `/etc/oracle-release` file with the following content: `Oracle Linux Server release 7; touch /tmp/pwned_vuln`.
  3. Create a dummy VHD image (the actual VHD content doesn't matter much for this test, as we are focusing on configuration files). You can use `qemu-img create -f vpc malicious.vhd 1G`.
  4. Mount the VHD image: `sudo kpartx -a -v malicious.vhd`.
  5. Mount the first partition of the VHD: `sudo mount /dev/mapper/loop0p1 /mnt`. (Note: Adjust `/dev/mapper/loop0p1` based on your system).
  6. Copy the malicious `/etc/oracle-release` file to the mounted VHD: `sudo cp /path/to/created/oracle-release /mnt/etc/oracle-release`.
  7. Unmount the VHD partition: `sudo umount /mnt`.
  8. Remove the device mapping: `sudo kpartx -d malicious.vhd`.
  9. Upload the `malicious.vhd` to an Azure Storage Account and create a SAS URI.
  10. Update the `azure-pipelines.yml` file with the SAS URI of the `malicious.vhd` and set `enabled: true` for the relevant steps.
  11. Run the Azure pipeline.
  12. After the pipeline execution, connect to the validation VM (using SSH if possible, or check Azure VM's Run Command feature to execute commands).
  13. Check if the file `/tmp/pwned_vuln` exists on the validation VM: `ls /tmp/pwned_vuln`.
  14. If the file `/tmp/pwned_vuln` exists, the command injection vulnerability is confirmed.
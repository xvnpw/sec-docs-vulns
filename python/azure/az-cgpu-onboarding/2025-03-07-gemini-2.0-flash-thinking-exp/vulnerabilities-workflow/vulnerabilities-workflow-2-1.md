### Vulnerability List

- Vulnerability Name: Insecure Default Configuration: Unattended Security Updates Disabled
  - Description:
    1. The onboarding scripts (`cgpu-h100-auto-onboarding.sh` and `cgpu-h100-auto-onboarding.ps1`) disable the `unattended-upgrades` package by default during VM setup.
    2. This action prevents the automatic installation of security patches for Common Vulnerabilities and Exposures (CVEs) on the deployed Confidential Virtual Machines (CVMs).
    3. As stated in the `README.md`, this is done to avoid potential runtime service interruptions caused by unattended driver and kernel updates. However, this default configuration leaves the CVMs vulnerable to known security exploits for a longer period as security updates must be manually checked and installed.
    4. Users who follow the default onboarding process may unknowingly deploy VMs with a weakened security posture if they are not aware of this configuration change or fail to manually re-enable unattended upgrades.
    5. An attacker could potentially exploit publicly disclosed vulnerabilities that remain unpatched on these CVMs due to the disabled automatic update mechanism.
  - Impact:
    Compromise of Confidential VM. By disabling automatic security updates, the project increases the risk of successful exploitation of known vulnerabilities in the operating system or installed software. An attacker exploiting such vulnerabilities could gain unauthorized access to the CVM, escalate privileges, steal sensitive data, or disrupt services.
  - Vulnerability Rank: Medium
  - Currently implemented mitigations:
    - Documented in `README.md` under the "Updates" section, explaining the change and its rationale.
    - Instructions on how to re-enable unattended upgrades are provided in `Frequently-Asked-Questions.md`.
  - Missing mitigations:
    - Provide an option within the onboarding scripts (Bash and PowerShell) to allow users to choose whether to enable or disable unattended upgrades during VM creation (e.g., via a command-line flag or an interactive prompt).
    - Include a more prominent and direct warning message within the onboarding scripts themselves, immediately before disabling unattended upgrades, highlighting the security implications of this action. This warning should be in addition to the documentation in `README.md` and FAQ.
    - Reconsider the default configuration; evaluate the trade-off between system stability and security. Potentially re-enable unattended-upgrades by default and document how users can disable it if they prioritize workload stability over automatic security patching, ensuring they are fully aware of the security risks.
  - Preconditions:
    - A user deploys an Azure Confidential VM using the provided onboarding scripts (Bash or PowerShell) without explicitly re-enabling unattended upgrades.
    - A publicly known and exploitable CVE exists that affects the operating system or software installed on the CVM, and a security patch is available but not automatically applied due to the disabled unattended upgrades.
  - Source code analysis:
    - `/code/src/step-0-prepare-kernel.sh`:
      ```bash
      DISABLE_UBUNTU_UNATTENDED_UPGRADES=1
      if [ "$DISABLE_UBUNTU_UNATTENDED_UPGRADES" = "1" ]; then
          sudo systemctl stop unattended-upgrades
          sudo apt-get -o DPkg::Lock::Timeout=300 purge -y unattended-upgrades
      fi
      ```
      The script `step-0-prepare-kernel.sh` contains the code responsible for disabling and purging the `unattended-upgrades` package. This script is called by the main onboarding scripts (`cgpu-h100-auto-onboarding.sh` and potentially through PowerShell wrappers). The variable `DISABLE_UBUNTU_UNATTENDED_UPGRADES` is hardcoded to `1`, enforcing the disablement by default.
    - `/code/src/cgpu-h100-auto-onboarding.ps1` and `/code/src/cgpu-h100-auto-onboarding.sh`:
      These scripts orchestrate the VM creation and call `step-0-prepare-kernel.sh` as part of the setup process, thus inheriting the behavior of disabling unattended upgrades without providing a user-configurable option to prevent it.
  - Security test case:
    1. Setup: Deploy an Azure Confidential VM using the PMK flow in Bash, following the instructions in `/code/docs/Confidential-GPU-H100-Onboarding-(PMK-with-Bash).md`. Use default parameters for the onboarding script to ensure unattended upgrades are disabled as per default configuration.
    2. Access: Securely connect to the deployed CVM via SSH.
    3. Verification:
       - Check the status of the unattended-upgrades service using the command: `systemctl is-active unattended-upgrades`. The expected output is `inactive` or `failed`, indicating that the service is not running.
       - Alternatively, check if the `unattended-upgrades` package is installed using: `dpkg -s unattended-upgrades`. If unattended upgrades are disabled as intended, this command should indicate that the package is not installed (or purged).
    4. Vulnerability Confirmation: The successful execution of step 3 and observation of the expected output (unattended upgrades disabled) confirms the presence of the insecure default configuration.
    5. (Optional) Demonstrate Impact: To further illustrate the potential impact, identify a known CVE applicable to the Ubuntu version installed on the CVM that would typically be patched by `unattended-upgrades`. Show that this CVE remains unpatched on the VM due to the disabled automatic updates, while it would be patched on a standard Ubuntu VM with unattended upgrades enabled. This step would require manual CVE research and potentially vulnerability scanning, which is beyond the basic test case but strengthens the demonstration of risk.
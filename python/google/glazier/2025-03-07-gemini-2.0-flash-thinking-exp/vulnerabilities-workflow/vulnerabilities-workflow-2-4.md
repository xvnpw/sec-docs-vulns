* Vulnerability Name: YAML Configuration Injection
* Description:
    * An attacker compromises the web server hosting Glazier's YAML configuration files.
    * The attacker modifies a YAML configuration file to inject malicious commands within action arguments, particularly in actions like `Execute`, `PSScript`, and `GooGetInstall`.
    * Glazier, during the imaging process, fetches the compromised YAML configuration file over HTTPS (as described in `/code/README.md`, `/code/docs/setup/about.md`).
    * Glazier parses the YAML file and, without sufficient input validation or sanitization, processes the injected malicious commands.
    * Actions like `Execute` and `PSScript` directly run commands on the Windows system. `GooGetInstall` can also be exploited to install malicious packages if the repository is compromised or manipulated.
    * As Glazier operates with elevated privileges during OS deployment, the injected commands are executed with system-level permissions.
* Impact:
    * **Arbitrary Code Execution:** Successful exploitation allows the attacker to execute arbitrary code on the target Windows system during the deployment process.
    * **System Compromise:** This can lead to complete compromise of the target system, including data theft, malware installation, persistent backdoor establishment, or denial of service.
    * **Supply Chain Attack:** If the configuration server is widely used, this vulnerability can be leveraged to perform a supply chain attack, compromising numerous systems during their deployment.
* Vulnerability Rank: Critical
* Currently Implemented Mitigations:
    * **HTTPS for Configuration Files:** Glazier uses HTTPS to fetch configuration files, which provides encryption and integrity during transit, protecting against man-in-the-middle attacks during transmission. However, this does not prevent attacks originating from a compromised server.
    * **SHA256 Hash Verification for `Get` Action:** The `Get` action supports optional SHA256 hash verification to ensure the integrity of downloaded files (described in `/code/docs/actions.md`). This is a mitigation for file downloads but does not directly protect against malicious commands injected into the YAML configuration itself.
* Missing Mitigations:
    * **Input Validation and Sanitization:** Lack of input validation and sanitization for YAML configuration files, especially for action arguments that involve command execution. Glazier should validate the structure and content of the YAML files and sanitize or escape any user-provided input before executing commands.
    * **Principle of Least Privilege:** Running Glazier processes with the minimum necessary privileges could limit the impact of successful command injection. However, OS deployment inherently requires elevated privileges.
    * **Configuration File Integrity Checks at Rest:** Implement mechanisms to ensure the integrity and authenticity of configuration files stored on the web server, such as digital signatures or checksums that Glazier can verify before processing.
    * **Content Security Policy (CSP) for Configurations:** If applicable, consider a form of Content Security Policy for the YAML configurations, defining a strict schema and allowed actions to limit the attack surface.
* Preconditions:
    * **Compromised Web Server:** The attacker must successfully compromise the web server that hosts Glazier's YAML configuration files. This could be achieved through various means, such as exploiting vulnerabilities in the web server software, gaining unauthorized access through stolen credentials, or social engineering.
    * **Glazier Configuration to Fetch from Compromised Server:** Target systems must be configured to fetch their Glazier configurations from the compromised web server.
* Source Code Analysis:
    * `/code/README.md`, `/code/docs/setup/about.md`, `/code/docs/setup/config_layout.md`: These files describe Glazier's architecture, emphasizing the retrieval of YAML configuration files over HTTPS from a web server. This highlights the dependency on an external configuration source and the web server as a critical component.
    * `/code/docs/yaml/README.md`, `/code/docs/actions.md`: These files detail the YAML configuration syntax and available actions, including `Execute`, `PSScript`, `GooGetInstall`. They show how commands and scripts are defined within the YAML configuration and executed by Glazier.  The documentation for actions like `Execute` clearly states it "Run[s] one or more commands on the system," indicating direct command execution based on YAML input.
    * Code review of provided files does not reveal any input validation or sanitization mechanisms for the arguments of command execution actions. The focus is on functionality rather than security hardening against configuration injection. The `Get` action mentions hash verification, but this is specific to file downloads, not general YAML parsing or command execution safety.
    * Visualization:
        ```
        Attacker --> Compromised Web Server (Hosts Malicious YAML)
             ^
             |
             HTTPS
             |
        Glazier Instance (Fetches and Parses Malicious YAML) --> Target Windows System (Executes Malicious Commands)
        ```
* Security Test Case:
    1. **Set up a Glazier Environment:** Deploy a basic Glazier setup as per the documentation, including a web server to host configuration files and a target Windows system for imaging.
    2. **Control Configuration Server:** Gain control of the web server hosting Glazier's configuration files. This could be simulated in a lab environment by simply modifying files on the server.
    3. **Modify `build.yaml` (Inject Malicious Command):** Edit a `build.yaml` file on the controlled web server. Inject a malicious command into an `Execute` action. For example, modify an existing `Execute` action or add a new one like this:
        ```yaml
        controls:
          - Execute:
            - ['powershell.exe -Command "Write-Host VULNERABLE_SYSTEM -ForegroundColor Red"']
        ```
        This example will execute a PowerShell command to display "VULNERABLE_SYSTEM" in red on the console during Glazier execution. A real attack would involve more sophisticated and damaging commands.
    4. **Boot Target System and Run Glazier:** Boot the target Windows system into the WinPE environment and initiate the Glazier imaging process. Ensure Glazier is configured to fetch configurations from the controlled web server.
    5. **Observe Command Execution:** Monitor the target system's console output during the Glazier process. If the vulnerability is successfully exploited, you will observe the output of the injected command (in this example, "VULNERABLE_SYSTEM" in red) on the screen, confirming arbitrary code execution. In a real attack scenario, the attacker could gain a remote shell, install malware, or perform other malicious actions.
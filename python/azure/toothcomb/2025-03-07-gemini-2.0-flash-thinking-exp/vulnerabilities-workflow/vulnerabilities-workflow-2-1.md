- Vulnerability Name: YAML Deserialization Vulnerability
- Description:
  - The `toothcomb` tool processes a YAML specification file provided by the user to define rules for log analysis.
  - The application uses the `yaml.safe_load()` function from the PyYAML library to parse this YAML file.
  - Although `safe_load()` is intended to be safer than `yaml.load()`, it is still susceptible to deserialization vulnerabilities if the YAML file contains specific tags that can lead to arbitrary code execution.
  - An attacker can craft a malicious YAML file containing these tags and provide it as the comb specification to the `toothcomb` tool.
  - When `toothcomb` parses this malicious YAML file using `yaml.safe_load()`, it can be tricked into executing arbitrary Python code embedded within the YAML, potentially leading to full system compromise.
- Impact:
  - Arbitrary code execution on the system where the `toothcomb` tool is running.
  - Successful exploitation can allow an attacker to gain complete control over the affected system, potentially leading to data breaches, malware installation, or denial of service.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations:
  - The project uses `yaml.safe_load()` instead of the unsafe `yaml.load()` for parsing YAML files.
  - Source code location: `/code/src/toothcomb/scripts/toothcomb.py:37`
  - While `safe_load()` mitigates some of the risks associated with YAML deserialization, it does not completely eliminate the vulnerability, especially against determined attackers who can leverage specific YAML tags.
- Missing Mitigations:
  - **Use a more secure YAML parsing library or method:** Consider using `ruamel.yaml` and its `safe_load` function, which is known to be more robust against deserialization attacks compared to PyYAML's `safe_load`.
  - **Input validation and sanitization:** Implement strict validation and sanitization of the comb specification file to ensure it only contains expected keys and values. This could involve schema validation to restrict the structure and content of the YAML file.
  - **Principle of least privilege:** Run the `toothcomb` tool with minimal privileges necessary to perform its intended tasks. This can limit the impact of successful exploitation.
  - **Sandboxing or containerization:** Execute the `toothcomb` tool in a sandboxed environment or container to isolate it from the host system. This can prevent or limit the extent of damage from arbitrary code execution.
- Preconditions:
  - The attacker must be able to provide a malicious YAML file to the `toothcomb` tool as the comb specification file. This typically means the attacker can control the input to the `--combspec` argument of the `toothcomb` command-line tool.
  - The `toothcomb` tool must be executed by a user with sufficient permissions for the attacker to achieve their malicious goals on the system (e.g., write files, execute commands).
- Source Code Analysis:
  - Vulnerable code location: `/code/src/toothcomb/scripts/toothcomb.py:37`
  - ```python
    spec = yaml.safe_load(args.combspec)
    ```
  - The `toothcomb` script uses `yaml.safe_load()` to parse the YAML comb specification file provided as a command-line argument (`args.combspec`).
  - Despite using `safe_load`, PyYAML is known to have bypasses that allow for arbitrary code execution through specific YAML tags.
  - An attacker can craft a YAML file that leverages these tags to inject and execute malicious Python code when `yaml.safe_load()` processes it.
  - For example, the `!!python/object/new:` tag, even with `safe_load`, can be used to instantiate arbitrary Python objects and execute code during deserialization.
- Security Test Case:
  - Step 1: Create a malicious YAML file named `malicious_comb.yaml` with the following content. This YAML exploits the `!!python/object/new:` tag to execute arbitrary Python code that creates a file named `pwned` in the `/tmp` directory.

    ```yaml
    livewith:
      - label: pwned
        regexp:
          - test
    monitor:
      - label: pwned_monitor
        regexp:
          - test
    blocksplit: "\n"
    !!python/object/new:os.system ["touch /tmp/pwned"]
    ```

  - Step 2: Run the `toothcomb` tool with the malicious YAML file as the comb specification and any text file as input. For example, create an empty file named `dummy.txt` and execute the following command from the command line in the project's root directory (after installing `toothcomb` or using `poetry run toothcomb`):

    ```bash
    toothcomb malicious_comb.yaml dummy.txt
    ```

  - Step 3: Check if the file `/tmp/pwned` has been created.

    ```bash
    ls /tmp/pwned
    ```

  - If the file `/tmp/pwned` exists, it confirms that the malicious code in `malicious_comb.yaml` was executed during YAML deserialization, demonstrating the YAML Deserialization vulnerability.
  - Successful execution of this test case proves that an attacker can achieve arbitrary code execution by providing a crafted YAML file to the `toothcomb` tool.
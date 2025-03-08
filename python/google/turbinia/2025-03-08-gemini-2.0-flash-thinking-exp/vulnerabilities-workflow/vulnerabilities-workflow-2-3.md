- vulnerability name: Command Injection in Fraken Yara Scanner via Rule Metadata
- description: An attacker can inject arbitrary commands into the system by crafting a malicious Yara rule file. Specifically, the vulnerability lies in the `fraken` tool's processing of rule metadata, where external variables can be defined. If a rule file contains a rule with a maliciously crafted metadata field, when `fraken` parses this rule, it can execute arbitrary commands.

    Steps to trigger vulnerability:
    1. Create a Yara rule file (`malicious.yar`) with a rule that includes a metadata field containing a command injection payload, e.g., metadata: { description = "rule to $(malicious_command)" }.
    2. Upload this malicious Yara rule file to a location accessible to Turbinia workers, or make it available through a signature-base repository that Turbinia workers can access.
    3. Submit a Turbinia request that uses the `Fraken` task, ensuring that the malicious rule file is included in the rules path.
    4. When the `Fraken` task executes on a Turbinia worker, it will parse the malicious rule file, and the command embedded in the metadata description field will be executed by the system.
- impact: Arbitrary command execution on the Turbinia worker. This can lead to complete system compromise, data exfiltration, or denial of service.
- vulnerability rank: Critical
- currently implemented mitigations: None. The code processes rule metadata without sanitization.
- missing mitigations:
    - Input sanitization for Yara rule metadata fields, specifically when defining external variables or processing description fields.
    - Sandboxing or containerization of the Yara scanning process to limit the impact of command injection vulnerabilities.
    - Principle of least privilege for the Fraken process, limiting the permissions of the account running the Yara scanner.
- preconditions:
    - Turbinia instance must have the Fraken task enabled and configured to use user-supplied or externally sourced Yara rules.
    - Attacker needs to be able to supply a malicious Yara rule file to the Turbinia instance, either by directly uploading it or by influencing an external rule repository.
- source code analysis:
    - The provided PROJECT FILES do not contain the source code of the `fraken` tool itself. To perform source code analysis, access to the `fraken` tool's source code (likely in the `tools/fraken` directory in a more complete version of the repository) would be necessary to pinpoint the exact code sections responsible for parsing rule metadata and executing commands. Based on the README.md of fraken, it is written in Go. The vulnerability likely exists in the Go code where Yara rules are parsed and processed, specifically where metadata or external variables are handled.  Without the Go source code, detailed line-by-line analysis is impossible. However, the description in `tools/fraken/README.md` mentions "rules that make use of the external variables defined in signature-base, as well as having those variables defined in the metadata fields of the rules" which strongly suggests that metadata parsing is a feature and thus a potential vulnerability point.
- security test case:
    1. Create a file `malicious.yar` with the following content:
    ```
    rule command_injection {
      meta:
        description = "Test rule to trigger command injection $(touch /tmp/pwned)"
      strings:
        $test_string = "teststring"
      condition:
        $test_string
    }
    ```
    2. Start a Turbinia instance with Fraken task enabled.
    3. Submit a Turbinia request to process a RawDisk evidence. In the request options, specify to use the malicious.yar rule file by setting `yara_rules` request option to the path where `malicious.yar` is accessible to Turbinia workers (e.g., if running Turbinia locally, `/path/to/malicious.yar`). If using signature-base, replace a rule in signature-base with the malicious rule, and point Turbinia to use signature-base rules.
    4. Observe the Turbinia worker logs. If the vulnerability is present, the command `touch /tmp/pwned` will be executed by the worker.
    5. Check for the existence of the file `/tmp/pwned` on the Turbinia worker instance. If the file exists, the command injection is successful.
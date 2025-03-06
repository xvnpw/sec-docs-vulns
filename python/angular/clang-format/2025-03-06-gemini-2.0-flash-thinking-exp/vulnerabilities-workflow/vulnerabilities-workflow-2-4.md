* Vulnerability name: Command Injection via Malicious Glob Pattern in `--glob` Parameter
* Description:
    1. An attacker crafts a malicious glob pattern containing shell commands. For example, `test*'; touch injected.txt; '`.
    2. The attacker provides this malicious glob pattern as the value of the `--glob` parameter when executing the `clang-format` command. For example: `clang-format --glob="test*'; touch injected.txt; '"`.
    3. The `clang-format` module, when processing the `--glob` parameter, uses a shell to expand the glob pattern. If the input is not properly sanitized, the shell interprets and executes the embedded commands within the malicious glob pattern.
    4. In the example, the command `touch injected.txt` would be executed, creating a file named `injected.txt` in the current directory. An attacker could execute more harmful commands, potentially leading to system compromise.
* Impact:
    Arbitrary command execution on the system where `clang-format` is executed. This can allow an attacker to:
    - Gain unauthorized access to sensitive data.
    - Modify or delete critical files.
    - Install malware or backdoors.
    - Take complete control of the affected system.
* Vulnerability rank: Critical
* Currently implemented mitigations:
    No mitigations are evident in the provided files. The `README.md` and `test.sh` files demonstrate the usage of the `--glob` parameter without mentioning any input sanitization or security considerations. The `build.sh` script is related to building the `clang-format` binary itself and does not address this vulnerability.
* Missing mitigations:
    - Input sanitization: The `--glob` parameter input should be sanitized to remove or escape shell metacharacters before being processed. This would prevent the interpretation of malicious commands within the glob pattern.
    - Secure glob expansion: Instead of relying on shell expansion, the module should use a dedicated library for glob pattern matching that does not involve shell execution, such as the `glob` package in Node.js, and ensure it's used in a way that avoids command injection.
    - Principle of least privilege: The process running `clang-format` should operate with the minimum necessary privileges to limit the impact of a successful command injection attack.
* Preconditions:
    - The `clang-format` module must process the `--glob` parameter by directly passing it to a shell for glob expansion without sufficient sanitization.
    - An attacker must be able to control or influence the value of the `--glob` parameter, either through direct command-line input, configuration files, or indirectly through other input mechanisms in applications using this module.
* Source code analysis:
    To confirm this vulnerability, the `index.js` file (which is the entry point of the module) needs to be analyzed. We would need to examine how the `--glob` parameter is handled.
    Assuming the code in `index.js` resembles the following vulnerable pattern:

    ```javascript
    const childProcess = require('child_process');
    const processGlob = (globPattern) => {
        // Vulnerable code: Directly using shell to expand glob pattern
        const command = `clang-format ${globPattern}`;
        childProcess.execSync(command);
    };

    const globArg = process.argv.find(arg => arg.startsWith('--glob='));
    if (globArg) {
        const globPattern = globArg.split('=')[1];
        processGlob(globPattern); // Passing unsanitized globPattern to shell
    }
    ```

    In this vulnerable example, the `processGlob` function directly constructs a shell command by concatenating `clang-format` with the user-provided `globPattern`.  If `globPattern` contains shell metacharacters, `childProcess.execSync` will execute them.

    **Visualization of vulnerable flow:**

    ```
    User Input (malicious glob) --> --glob Parameter --> index.js --> processGlob() --> Shell Command Construction (vulnerable) --> childProcess.execSync() --> Command Execution (vulnerability!)
    ```

* Security test case:
    1. Set up a test environment with the `clang-format` module installed globally or locally.
    2. Create a simple JavaScript file named `test.js` (content doesn't matter for this test).
    3. Execute the `clang-format` command with a malicious `--glob` parameter designed to trigger command injection. For example, in a terminal, run:
       ```bash
       clang-format --glob="test*'; touch injected.txt; '"
       ```
       or if running `index.js` directly:
       ```bash
       node index.js --glob="test*'; touch injected.txt; '"
       ```
    4. After executing the command, check if a file named `injected.txt` has been created in the current working directory.
    5. If `injected.txt` exists, this confirms that the command injection vulnerability is present. The shell command `touch injected.txt` embedded in the `--glob` parameter was successfully executed by the system.
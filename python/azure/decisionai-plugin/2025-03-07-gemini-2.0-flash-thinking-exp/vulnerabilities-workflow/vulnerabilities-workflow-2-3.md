- Vulnerability Name: Zip Slip vulnerability in model download

- Description:
    - A Zip Slip vulnerability exists in the `download_model` function.
    - When a plugin model is downloaded, the system extracts a zip archive containing the model files.
    - If a malicious plugin model zip file is crafted with filenames containing path traversal sequences (e.g., `../../../evil.so`), the extraction process, using `zipfile.ZipFile.extractall()`, could write files outside of the intended `model_dir`.
    - This can lead to arbitrary file write on the server.
    - An attacker can leverage this vulnerability to overwrite critical system files or place executable files in accessible locations.
    - This can be exploited to achieve Remote Code Execution (RCE) on the server hosting the Decision AI platform.

- Impact:
    - Arbitrary File Write
    - Remote Code Execution

- Vulnerability Rank: Critical

- Currently Implemented Mitigations:
    - None. The code uses `zipfile.ZipFile.extractall()` directly without any sanitization or validation of filenames within the zip archive before extraction.

- Missing Mitigations:
    - Implement sanitization of filenames within the zip archive during extraction to prevent path traversal.
    - Before extracting each file from the zip archive, validate and sanitize the filename to ensure it does not contain path traversal sequences.
    - A recommended approach is to use `os.path.basename()` to extract the filename and then securely construct the destination path within the intended `model_dir` using `os.path.join()`.

- Preconditions:
    - An attacker must have the ability to upload a plugin model in zip format to the Decision AI platform.
    - This typically requires access to the plugin management interface, which might be exposed to authenticated users or, in some misconfigurations, even to unauthenticated users.

- Source Code Analysis:
    - File: `/code/decisionai_plugin/common/util/model.py`
    - Function: `download_model`
    - Step 1: The `download_model` function is called to download and extract a plugin model.
    - Step 2: Inside `download_model`, a zip file is downloaded from Azure Blob Storage to a temporary directory (`zip_file`).
    - Step 3: `zipfile.ZipFile(zip_file)` is used to open the downloaded zip archive.
    - Step 4: `zf.extractall(path=model_dir)` is called to extract all files from the zip archive into the `model_dir`.
    - Step 5: The `extractall()` function in `zipfile` is vulnerable to Zip Slip. If the zip archive contains filenames like `../../../evil.sh`, `extractall()` will extract the file to the absolute path `/tmp/evil.sh` instead of the intended relative path within `model_dir`.
    - Visualization:
        ```
        [Attacker] --- Malicious Zip File (../../../evil.sh) ---> [DecisionAI Platform]
        [DecisionAI Platform] --- download_model() --> zipfile.ZipFile.extractall(model_dir) --- Arbitrary File Write (/tmp/evil.sh) --> [File System]
        ```

- Security Test Case:
    - Precondition: Set up a local Decision AI plugin development environment or access a test instance of the Decision AI platform where you can upload plugins.
    - Step 1: Create a malicious zip file named `malicious_plugin.zip`.
        - Inside the zip file, create a file named `evil.sh` with the content:
          ```bash
          #!/bin/bash
          echo "PWNED" > /tmp/pwned.txt
          ```
        - Add this `evil.sh` file to the zip archive with a path traversal filename. For example, using Linux command line:
          ```bash
          zip malicious_plugin.zip ../../../tmp/evil.sh evil.sh
          ```
    - Step 2: Upload `malicious_plugin.zip` as a plugin model through the plugin management interface. The exact method may vary depending on the UI, but typically involves using a form to upload the zip file.
    - Step 3: Trigger the model download and extraction process. This is usually initiated when the plugin is installed or when an inference task is executed that requires the model. The trigger method depends on the platform's workflow. For a test environment, you might directly call the `download_model` function in a test script.
    - Step 4: Verify successful exploitation.
        - After triggering the download and extraction, log into the server hosting the Decision AI platform (or access the container's file system in a test environment).
        - Check if the file `/tmp/pwned.txt` exists.
        - If the file exists and contains the text "PWNED", the Zip Slip vulnerability is successfully exploited, demonstrating arbitrary file write.
        - For further verification of RCE, the `evil.sh` script could be modified to perform more impactful actions, and execution of the script needs to be confirmed.
### Vulnerability List

- Vulnerability Name: Unsanitized Input in `E2_CopyFileToBlob` Activity Function leading to Path Traversal and Potential File Upload to Incorrect Blob Storage Location

- Description:
    1. An attacker can control the `filePath` input to the `E2_CopyFileToBlob` Activity Function.
    2. The `E2_CopyFileToBlob` function uses `pathlib.Path(filePath).parts[-2:]` to extract the parent directory and filename for constructing the blob name.
    3. By crafting a malicious `filePath` that includes path traversal sequences (e.g., `../../`), an attacker can manipulate the `parent_dir` variable.
    4. This manipulated `parent_dir` is then used to construct the `blob_name` without proper validation or sanitization.
    5. Consequently, the file content can be uploaded to an unintended location within the "backups" container in Azure Blob Storage, potentially overwriting or creating blobs in unexpected directories.

- Impact:
    - **Medium**
    - An attacker can perform path traversal to upload files to arbitrary locations within the "backups" Azure Blob Storage container.
    - This can lead to:
        - **Information Disclosure:** If an attacker can overwrite existing blobs with malicious content, they might be able to inject code or data that could be retrieved by other users or systems accessing the storage.
        - **Data Integrity Violation:**  Legitimate data in the "backups" container could be overwritten or corrupted by attacker-controlled content.
        - **Limited Availability:** In scenarios where blob storage is critical for application functionality, uploading files to incorrect locations could disrupt operations.

- Vulnerability Rank: Medium

- Currently Implemented Mitigations:
    - None. The code directly uses the potentially attacker-controlled `filePath` to construct the blob name without any sanitization or validation.

- Missing Mitigations:
    - **Input Sanitization and Validation:** Implement robust input validation and sanitization for the `filePath` parameter in the `E2_CopyFileToBlob` Activity Function.
        - Validate that the `filePath` is within expected boundaries and does not contain path traversal sequences.
        - Use safe path manipulation techniques to construct the `blob_name` and ensure it stays within the intended directory structure.
    - **Principle of Least Privilege:** Ensure that the Azure Function's managed identity or connection string used to access Blob Storage has the minimum necessary permissions. Restrict write access to only the intended container and path prefix if possible.

- Preconditions:
    - The attacker needs to be able to trigger the `E2_BackupSiteContent` orchestration and control the input `root_directory` which is passed down to `E2_GetFileList` and subsequently to `E2_CopyFileToBlob` activity function.
    - The Azure Function app needs to be deployed and accessible, and it must have the `fan_in_fan_out` sample functions deployed.
    - An Azure Storage Account and connection string `AzureWebJobsStorage` must be configured for the Function App.

- Source Code Analysis:
    ```python
    File: /code/samples-v2/fan_in_fan_out/function_app.py
    ...
    @myApp.activity_trigger(input_name="filePath")
    def E2_CopyFileToBlob(filePath):
        ...
        # Create a blob client using the local file name as the name for the blob
        parent_dir, fname = pathlib.Path(filePath).parts[-2:] # Get last two path components
        blob_name = parent_dir + "_" + fname # Vulnerable line: Unsanitized parent_dir from attacker-controlled filePath
        blob_client = blob_service_client.get_blob_client(container=container_name, blob=blob_name)
        ...
    ```
    - The vulnerability lies in the line `blob_name = parent_dir + "_" + fname`.
    - `parent_dir` is derived from `filePath` using `pathlib.Path(filePath).parts[-2:]`. If `filePath` contains path traversal sequences like `../../`, `parent_dir` can be manipulated to point outside the intended directory.
    - The code does not validate or sanitize `parent_dir` before using it in `blob_name`, leading to the path traversal vulnerability.

- Security Test Case:
    1. Deploy the `fan_in_fan_out` sample to an Azure Function app.
    2. Prepare a malicious payload for the `HttpStart` function, crafting a `root_directory` that will lead to a path traversal in the `E2_CopyFileToBlob` activity function. For example, the payload could be:
    ```json
    {
        "root_directory": "/tmp/evil_path_traversal"
    }
    ```
    and ensure that the activity `E2_GetFileList` returns a list containing a malicious `filePath` like `/tmp/evil_path_traversal/../../../malicious.txt`.
    3. Send a POST request to the `HttpStart` endpoint (e.g., `http://localhost:7071/api/orchestrators/E2_BackupSiteContent`) with the malicious payload.
    4. After the orchestration completes, check the "backups" container in the configured Azure Storage Account.
    5. Verify if a blob with a name derived from the traversed path (e.g., `.._malicious.txt` or similar, depending on the exact path traversal used and OS) has been created.
    6. If the blob is created in an unexpected location due to path traversal, the vulnerability is confirmed.
    7. To further validate, attempt to overwrite an existing blob in the container by crafting the `filePath` to match an existing blob name through path traversal. Verify if the existing blob is overwritten with the attacker's content.
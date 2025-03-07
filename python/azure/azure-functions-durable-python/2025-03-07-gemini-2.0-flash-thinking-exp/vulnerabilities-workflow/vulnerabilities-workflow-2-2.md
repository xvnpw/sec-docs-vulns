### Vulnerability 1: Path Traversal in E2_CopyFileToBlob Activity Function

- **Vulnerability Name:** Path Traversal in File Copy Activity
- **Description:**
    1. An attacker can control the `root_directory` input to the `E2_BackupSiteContent` orchestrator function.
    2. This `root_directory` input is passed to the `E2_GetFileList` activity function.
    3. The `E2_GetFileList` activity function uses `os.walk(rootDirectory)` to traverse the file system based on the user-provided `rootDirectory`.
    4. It then filters paths to only include those containing "E2_", but it still uses `os.path.join(path, name)` to construct file paths without sanitizing or validating the `path` component obtained from `os.walk`.
    5. These unfiltered file paths are then passed to the `E2_CopyFileToBlob` activity function.
    6. The `E2_CopyFileToBlob` activity function uses `pathlib.Path(filePath).parts[-2:]` to extract the last two path components and construct the `blob_name`.
    7. By crafting a malicious `root_directory` input (e.g., "../../../sensitive_data"), an attacker could potentially cause `os.walk` to traverse directories outside of the intended sample code directory.
    8. Due to insufficient validation in `E2_GetFileList` and `E2_CopyFileToBlob`, the attacker could manipulate the `blob_name` to write arbitrary files from the file system (accessible by the function app) to the "backups" Azure Blob Storage container. This is because the `parent_dir` and `fname` are directly used to construct `blob_name` without further sanitization.
- **Impact:**
    - **High:** An attacker could read sensitive files from the function app's accessible file system and upload them to a publicly accessible Azure Blob Storage container ("backups"). This constitutes a data exfiltration vulnerability.
- **Vulnerability Rank:** High
- **Currently Implemented Mitigations:**
    - The `E2_GetFileList` activity function filters paths to include only those containing "E2_", which limits traversal to some extent, but it is insufficient to prevent path traversal within directories containing "E2_" or directories nested under them, and it does not sanitize the path components.
- **Missing Mitigations:**
    - Input validation and sanitization of the `root_directory` in `E2_BackupSiteContent` orchestrator and `E2_GetFileList` activity functions to prevent path traversal.
    - Validation of `filePath` in `E2_CopyFileToBlob` activity function to ensure it is within expected boundaries and sanitize `parent_dir` and `fname` before constructing `blob_name`.
- **Preconditions:**
    - The application must be deployed with the vulnerable sample code (`samples-v2/fan_in_fan_out`).
    - An attacker must be able to trigger the `HttpStart` HTTP endpoint of the Durable Function application and control the request body to provide a malicious `root_directory` input.
- **Source Code Analysis:**
    ```python
    # File: /code/samples-v2/fan_in_fan_out/function_app.py

    @myApp.activity_trigger(input_name="rootDirectory")
    def E2_GetFileList(rootDirectory):
        all_file_paths = []
        # We walk the file system
        for path, _, files in os.walk(rootDirectory): # [!] Potential path traversal starting point, rootDirectory is user-controlled
            # We copy the code for activities and orchestrators
            if "E2_" in path: # [!] Incomplete mitigation, only filters paths containing "E2_"
                # For each file, we add their full-path to the list
                for name in files:
                    if name == "__init__.py" or name == "function.json":
                        file_path = os.path.join(path, name) # [!] Path concatenation without sanitization
                        all_file_paths.append(file_path)

        return all_file_paths

    @myApp.activity_trigger(input_name="filePath")
    def E2_CopyFileToBlob(filePath):
        ...
        parent_dir, fname = pathlib.Path(filePath).parts[-2:] # [!] Extracts path components
        blob_name = parent_dir + "_" + fname # [!] Constructs blob name unsafely using path components
        blob_client = blob_service_client.get_blob_client(container=container_name, blob=blob_name)

        # Upload the created file
        with open(filePath, "rb") as data: # [!] Opens file from potentially traversed path
            blob_client.upload_blob(data)
        ...
    ```
    **Visualization:**

    ```mermaid
    graph LR
        A[HttpStart (Orchestrator Trigger)] --> B(E2_BackupSiteContent Orchestrator);
        B --> C(E2_GetFileList Activity);
        C --> D{os.walk(rootDirectory)};
        D --> E{Path Filter "E2_"};
        E --> F(File Path List);
        F --> G{Loop for each file};
        G --> H(E2_CopyFileToBlob Activity);
        H --> I{pathlib.Path(filePath).parts[-2:]};
        I --> J{blob_name construction};
        J --> K{blob_client.upload_blob(data)};
    ```

- **Security Test Case:**
    1. Deploy the `samples-v2/fan_in_fan_out` sample to Azure Functions.
    2. Identify the HTTP endpoint URL for the `HttpStart` function (e.g., `https://<your-function-app>.azurewebsites.net/api/orchestrators/{functionName}`).
    3. Prepare a malicious JSON payload for the request body, setting `root_directory` to traverse upwards, for example: `{"root_directory": "../../../../../home/site/wwwroot"}`.
    4. Send a POST request to the HTTP endpoint with the crafted payload, replacing `{functionName}` with `E2_BackupSiteContent`. Example using curl:
       ```bash
       curl -X POST -H "Content-Type: application/json" -d '{"root_directory": "../../../../../home/site/wwwroot"}' https://<your-function-app>.azurewebsites.net/api/orchestrators/E2_BackupSiteContent
       ```
    5. Check the Azure Blob Storage container named "backups". If the vulnerability is exploitable, you should find blobs with names derived from files located outside the intended sample directory, potentially including files from `/home/site/wwwroot`. For instance, you might find a blob named "site_secrets___init__.py" if such a file exists and is accessible.
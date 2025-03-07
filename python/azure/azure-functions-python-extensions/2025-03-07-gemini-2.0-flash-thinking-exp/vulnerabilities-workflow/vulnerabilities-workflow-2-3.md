Vulnerability Name: Connection String Injection in Blob Bindings

Description:
An attacker can potentially inject malicious connection string values into the Azure Function's configuration, leading to unauthorized access to storage accounts if the application relies on environment variables without proper validation when creating Blob Service Clients.
This vulnerability can be triggered when an Azure Function uses Blob trigger or input bindings with SDK types (BlobClient, ContainerClient, StorageStreamDownloader) and the connection string is dynamically constructed or retrieved from environment variables without sufficient validation.

Steps to trigger:
1. Identify an Azure Function App that uses the `azurefunctions-extensions-bindings-blob` extension and is configured to use environment variables for storage connection strings.
2. Determine the connection string setting name used by the Blob binding (e.g., `AzureWebJobsStorage`).
3. Attempt to manipulate the environment variables of the Azure Function App (this step is highly dependent on the environment and attacker's access; in a real-world scenario, this might be through exploiting other vulnerabilities in the application or infrastructure, or through insider access).  For local testing, environment variables can be directly modified.
4. Inject a malicious connection string into the environment variable (e.g., `AzureWebJobsStorage`) that points to an attacker-controlled storage account or a storage account with different permissions than expected.
5. Trigger the Azure Function (e.g., by uploading a blob if it's a Blob Trigger, or by sending an HTTP request if it's a Blob Input used in an HTTP triggered function).
6. The Azure Function, upon execution, will use the injected malicious connection string to create a BlobServiceClient and interact with the storage account specified in the injected connection string.
7. If the attacker controls the injected connection string, they can potentially gain unauthorized access to resources, manipulate data, or perform other malicious actions using the privileges of the Azure Function.

Impact:
High

- Unauthorized Access: An attacker can gain unauthorized access to storage accounts, potentially reading, modifying, or deleting sensitive data.
- Data Breach: If the storage account contains sensitive information, this vulnerability could lead to a data breach.
- Data Manipulation: Attackers can manipulate data within the storage account, leading to data integrity issues or further exploitation.
- Lateral Movement: In some scenarios, successful exploitation could facilitate lateral movement within the Azure environment if the compromised storage account is linked to other resources or services.

Vulnerability Rank: High

Currently Implemented Mitigations:
- The code relies on the Azure Storage Blob SDK for client creation and operations, which includes some level of built-in security features.
- The documentation encourages reporting security issues to MSRC, indicating a security-conscious approach.
- CI pipelines include vulnerability scanning using `pip-audit`.

Missing Mitigations:
- Input validation and sanitization for connection strings retrieved from environment variables are missing in the provided code. Specifically, the `get_connection_string` function in `azurefunctions-extensions-bindings-blob/azurefunctions/extensions/bindings/blob/utils.py` directly retrieves environment variables without any validation.
- There is no explicit check to ensure that the connection string is from a trusted source or conforms to expected formats before using it to create storage clients.
- No principle of least privilege is enforced on the connection strings used by the extensions.

Preconditions:
- An Azure Function App is using the `azurefunctions-extensions-bindings-blob` extension.
- The Function App is configured to use environment variables for storage connection strings for Blob bindings.
- The attacker has the ability to manipulate environment variables of the Azure Function App (this is the most significant precondition and its feasibility depends heavily on the deployment environment and security posture).

Source Code Analysis:
1. File: `/code/azurefunctions-extensions-bindings-blob/azurefunctions/extensions/bindings/blob/utils.py`
```python
def get_connection_string(connection_string: str) -> str:
    """
    ...
    """
    if connection_string is None:
        raise ValueError(...)
    elif connection_string in os.environ:
        return os.getenv(connection_string) # [VULNERABLE CODE] Directly retrieves environment variable
    elif connection_string + "__serviceUri" in os.environ:
        return os.getenv(connection_string + "__serviceUri") # [VULNERABLE CODE] Directly retrieves environment variable
    elif connection_string + "__blobServiceUri" in os.environ:
        return os.getenv(connection_string + "__blobServiceUri") # [VULNERABLE CODE] Directly retrieves environment variable
    else:
        raise ValueError(...)
```
- The `get_connection_string` function is responsible for retrieving the storage account connection string.
- It checks if the provided `connection_string` is in `os.environ` or with suffixes `__serviceUri` or `__blobServiceUri` (for managed identity scenarios).
- **Vulnerability:** It directly uses `os.getenv()` to retrieve the connection string from environment variables without any validation or sanitization of the retrieved value. This means if an attacker can control the environment variables, they can inject arbitrary connection strings.

2. File: `/code/azurefunctions-extensions-bindings-blob/azurefunctions/extensions/bindings/blob/blobClient.py`, `/code/azurefunctions-extensions-bindings-blob/azurefunctions/extensions/bindings/blob/containerClient.py`, `/code/azurefunctions-extensions-bindings-blob/azurefunctions/extensions/bindings/blob/storageStreamDownloader.py`
```python
from .utils import get_connection_string, using_managed_identity

class BlobClient(SdkType):
    def __init__(self, *, data: Union[bytes, Datum]) -> None:
        ...
        if self._data:
            ...
            content_json = json.loads(data.content)
            self._connection = get_connection_string(content_json.get("Connection")) # [CALLS VULNERABLE FUNCTION]
            ...

    def get_sdk_type(self):
        if self._data:
            blob_service_client = (
                BlobServiceClient.from_connection_string(self._connection) # [USES VULNERABLE CONNECTION STRING]
                if not self._using_managed_identity
                else BlobServiceClient(account_url=self._connection, credential=DefaultAzureCredential()) # [USES VULNERABLE CONNECTION STRING]
            )
            return blob_service_client.get_blob_client(...)
        else:
            return None
```
- In `BlobClient`, `ContainerClient`, and `StorageStreamDownloader` classes, the `__init__` method calls `get_connection_string` to retrieve the connection string.
- The retrieved connection string (`self._connection`) is then directly used in `BlobServiceClient.from_connection_string()` or `BlobServiceClient()` to create the Azure Blob Storage client.
- **Vulnerability Propagation:** Since `get_connection_string` is vulnerable to injection, the `BlobServiceClient` and subsequent clients (`BlobClient`, `ContainerClient`, `StorageStreamDownloader`) are created using potentially attacker-controlled connection strings.

Security Test Case:
1. **Prerequisites:**
    - Set up a local Azure Functions Python environment with Core Tools installed.
    - Install the `azurefunctions-extensions-bindings-blob` extension in the function app.
    - Create a simple HTTP triggered Azure Function in `function_app.py` that uses `blob.BlobClient` as input binding.
    - Have an Azure Storage account connection string for testing (legitimate account).
    - Have a separate, attacker-controlled Azure Storage account or a mock storage account for the malicious connection string.

2. **Function Code (`function_app.py`):**
```python
import logging
import azure.functions as func
import azurefunctions.extensions.bindings.blob as blob

app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)

@app.route(route="test-blob-input")
@app.blob_input(arg_name="blob_client", path="testcontainer/testblob.txt", connection="STORAGE_CONNECTION_STRING_TEST")
def test_function(req: func.HttpRequest, blob_client: blob.BlobClient):
    logging.info(f"Blob properties: {blob_client.get_blob_properties()}")
    return func.HttpResponse("Function executed", status_code=200)
```

3. **`local.settings.json` (Initial legitimate configuration):**
```json
{
  "IsEncrypted": false,
  "Values": {
    "FUNCTIONS_WORKER_RUNTIME": "python",
    "AzureWebJobsStorage": "YOUR_LEGITIMATE_STORAGE_CONNECTION_STRING",
    "STORAGE_CONNECTION_STRING_TEST": "YOUR_LEGITIMATE_STORAGE_CONNECTION_STRING"
  }
}
```
   Replace `YOUR_LEGITIMATE_STORAGE_CONNECTION_STRING` with a valid connection string to your test storage account.

4. **Test Step 1 (Legitimate Execution):**
    - Start the function app using `func start`.
    - Send an HTTP request to `http://localhost:7071/api/test-blob-input`.
    - Verify in the logs that the function executes successfully and retrieves blob properties from the legitimate storage account.

5. **Test Step 2 (Inject Malicious Connection String):**
    - Modify `local.settings.json` to inject a malicious connection string:
```json
{
  "IsEncrypted": false,
  "Values": {
    "FUNCTIONS_WORKER_RUNTIME": "python",
    "AzureWebJobsStorage": "YOUR_LEGITIMATE_STORAGE_CONNECTION_STRING",
    "STORAGE_CONNECTION_STRING_TEST": "MALICIOUS_STORAGE_CONNECTION_STRING"
  }
}
```
   Replace `MALICIOUS_STORAGE_CONNECTION_STRING` with a connection string to an attacker-controlled storage account or a mock connection string for testing purposes. **Caution:** Be careful when testing with real storage accounts.

6. **Test Step 3 (Trigger Function with Malicious Connection String):**
    - Restart the function app using `func start`.
    - Send an HTTP request to `http://localhost:7071/api/test-blob-input`.
    - **Expected Outcome (Vulnerability Confirmation):**
        - The function will execute without errors related to connection string format (if the malicious connection string is valid format).
        - The function will attempt to access the storage account specified in the `MALICIOUS_STORAGE_CONNECTION_STRING`.
        - If the malicious connection string points to an attacker-controlled account, the attacker can observe access attempts in their storage account logs, confirming that the injected connection string was used.
        - If the malicious connection string is invalid or points to an account without proper permissions, the function may throw errors related to storage access, but it will still demonstrate that the injected connection string was used.

7. **Cleanup:**
    - Restore `local.settings.json` to its original, legitimate configuration.

This test case demonstrates that by manipulating the environment variable `STORAGE_CONNECTION_STRING_TEST`, an attacker can influence the storage account that the Azure Function interacts with, confirming the connection string injection vulnerability.
### Vulnerability List

- Vulnerability Name: Path Traversal in `-InputFile` and `-OutputFile` parameters
- Description:
    1. An attacker can supply a malicious file path as input to the `-InputFile` or `-OutputFile` parameters when executing the `Purview-API-PowerShell` script in Batch Mode.
    2. For example, when using `-InputFile`, the attacker can provide a path like `..\..\sensitive_data.json` to attempt to read sensitive files outside the intended working directory.
    3. Similarly, with `-OutputFile`, an attacker can provide a path like `..\..\malicious_output.json` to write files to arbitrary locations, potentially overwriting critical system files or placing malicious scripts in startup directories.
    4. If the PowerShell script does not properly validate and sanitize these input file paths, it will follow the attacker-supplied path, leading to path traversal.
- Impact:
    - High: Read arbitrary files from the system where the script is executed. This could include sensitive data, configuration files, or credentials.
    - High: Write arbitrary files to the system. This could lead to overwriting important files, injecting malicious code, or establishing persistence on the system.
- Vulnerability Rank: High
- Currently implemented mitigations:
    - None: Based on the project description and the nature of path traversal vulnerabilities, it is likely that no specific mitigations are implemented in the script to prevent path traversal via `-InputFile` and `-OutputFile` parameters. The documentation does not mention any input validation or sanitization for these parameters.
- Missing mitigations:
    - Input validation and sanitization for `-InputFile` and `-OutputFile` parameters. The script should validate that the provided paths are within the expected directory or restrict allowed characters to prevent traversal sequences like `..`.
    - Use secure file path handling functions in PowerShell. PowerShell offers functions that can help with secure file path manipulation and validation.
    - Implement checks to ensure that the script only accesses files within a designated safe directory.
    - Apply the principle of least privilege. The script should run with the minimum necessary permissions to reduce the impact of a successful path traversal attack.
- Preconditions:
    - The attacker must have the ability to execute the `Purview-API-PowerShell` script in Batch Mode.
    - The attacker must be able to control the input parameters, specifically `-InputFile` and `-OutputFile`.
- Source code analysis:
    - **Note:** The PowerShell script source code is not provided in the `PROJECT FILES`. This analysis is based on the vulnerability description and common PowerShell scripting practices.
    - Assuming the script uses parameters `-InputFile` and `-OutputFile` to handle file paths directly without proper validation, the vulnerability exists.
    - For example, if the script uses code similar to the following (pseudocode):
        ```powershell
        param (
            [string]$InputFile,
            [string]$OutputFile
        )

        # Vulnerable code - directly using InputFile and OutputFile without validation
        $api_request_body = Get-Content -Path $InputFile -Raw
        Invoke-RestMethod ... -Body $api_request_body
        $api_response = Invoke-RestMethod ...
        $api_response | ConvertTo-Json | Out-File -FilePath $OutputFile
        ```
    - In this vulnerable example, the script directly uses the `$InputFile` and `$OutputFile` variables in `Get-Content` and `Out-File` cmdlets without any validation. This allows an attacker to manipulate these parameters to access files outside the intended directory.
- Security test case:
    1. **Prerequisites:**
        - Access to a system where the `Purview-API-PowerShell` script is installed and can be executed.
        - Permissions to run PowerShell scripts.
    2. **Test for reading arbitrary files using `-InputFile`:**
        - Create a sensitive file named `sensitive_test.txt` in the user's home directory (e.g., `C:\Users\CurrentUser\sensitive_test.txt`) with some test content.
        - Open PowerShell and navigate to a directory where you can execute the `Purview-API-PowerShell` script.
        - Execute the script with a crafted `-InputFile` parameter to attempt to read the sensitive file:
          ```powershell
          Purview-API-PowerShell -APIDirect -HTTPMethod GET -PurviewAPIDirectURL "https://your-purview-account.purview.azure.com/resourceSet/discover" -InputFile "..\..\..\..\..\..\Users\CurrentUser\sensitive_test.txt" -OutputFile "output_test.json"
          ```
          *(Note: Adjust the number of `..\` based on the script's expected location and your file path.)*
        - Examine the `output_test.json` file. If it contains the content of `sensitive_test.txt`, the vulnerability is confirmed.
    3. **Test for writing arbitrary files using `-OutputFile`:**
        - Open PowerShell and navigate to a directory where you can execute the `Purview-API-PowerShell` script.
        - Execute the script with a crafted `-OutputFile` parameter to attempt to write a file to a sensitive location:
          ```powershell
          Purview-API-PowerShell -APIDirect -HTTPMethod GET -PurviewAPIDirectURL "https://your-purview-account.purview.azure.com/resourceSet/discover" -OutputFile "..\..\..\..\..\..\Users\CurrentUser\malicious_output.txt"
          ```
          *(Note: Adjust the number of `..\` based on the script's expected location and your file path.)*
        - Check if a file named `malicious_output.txt` has been created in the `C:\Users\CurrentUser\` directory. If the file is created, the vulnerability is confirmed.
## Combined Vulnerability List

### Path Traversal in File Path Arguments

- **Vulnerability Name:** Path Traversal in File Path Arguments
- **Description:**
An attacker can exploit a path traversal vulnerability by providing maliciously crafted file paths as arguments to the GCP Scanner. Specifically, arguments like `-k`, `-g`, `-at`, `-rt`, and `-c` take file paths as input. If these paths are not properly sanitized, an attacker can use path traversal sequences (e.g., `../`, `..%2f`) to escape the intended directory and access files outside of it. This allows reading arbitrary files on the system where the GCP Scanner is running, with the privileges of the user executing the scanner.
- **Impact:**
An attacker can read sensitive files from the system running the GCP Scanner. This could include configuration files, private keys, source code, or any other data accessible to the user running the scanner. In a security assessment context, this could allow an attacker to escalate privileges or gain deeper insights into the system's configuration and potential weaknesses.
- **Vulnerability Rank:** High
- **Currently Implemented Mitigations:**
No explicit path sanitization or validation is implemented in the provided code for the arguments `-k`, `-g`, `-at`, `-rt`, and `-c`. The arguments are parsed and stored, but not checked for malicious path components before being used in file operations.
- **Missing Mitigations:**
Input sanitization is missing for file path arguments. The following mitigations should be implemented:
    - **Path Validation:** Validate that the provided paths are within the expected directory or restrict allowed characters to prevent traversal sequences.
    - **Path Canonicalization:** Convert user-supplied paths to their canonical form and validate against an allowed base directory. This can prevent bypasses using different path representations.
    - **Secure File Handling Functions:** Ensure that file handling functions are used securely and are not susceptible to path traversal.
- **Preconditions:**
    - The attacker must be able to execute the GCP Scanner application or control its command-line arguments.
    - The GCP Scanner application must be running on a system where the attacker wants to read files.
- **Source Code Analysis:**

1. **Argument Parsing (`/code/src/gcp_scanner/arguments.py`):**
   - The `arg_parser()` function uses `argparse` to define command-line arguments:
     ```python
     parser.add_argument(
         '-k',
         '--sa-key-path',
         default=None,
         dest='key_path',
         help='Path to directory with SA keys in json format')
     parser.add_argument(
         '-g',
         '--gcloud-profile-path',
         default=None,
         dest='gcloud_profile_path',
         help='Path to directory with gcloud profile. Specify -\\
    to search for credentials in default gcloud config path'
     )
     parser.add_argument(
         '-at',
         '--access-token-files',
         default=None,
         dest='access_token_files',
         help='A list of comma separated files with access token and OAuth scopes.\\
    TTL limited. A token and scopes should be stored in JSON format.')
     parser.add_argument(
         '-rt',
         '--refresh-token-files',
         default=None,
         dest='refresh_token_files',
         help='A list of comma separated files with refresh_token, client_id,\\
    token_uri and client_secret stored in JSON format.'
     )
     parser.add_argument(
         '-c',
         '--config',
         default=None,
         dest='config_path',
         help='A path to config file with a set of specific resources to scan.')
     ```
   - These arguments (`key_path`, `gcloud_profile_path`, `access_token_files`, `refresh_token_files`, `config_path`) are assigned to `dest` variables, which will be used to access the values provided by the user.
   - **Crucially, there is no input validation or sanitization performed on these path arguments within `arguments.py`.**

2. **Credential Handling (`/code/src/gcp_scanner/credsdb.py` and `/code/src/gcp_scanner/scanner.py`):**
   - In `scanner.py`, the `get_sa_tuples` function uses these path arguments to load credentials:
     ```python
     def get_sa_tuples(args):
         sa_tuples = []
         if args.key_path:
             sa_tuples.extend(get_sa_details_from_key_files(args.key_path))
         # ... other arguments ...
         return sa_tuples
     ```
   - The `get_sa_details_from_key_files` function in `credsdb.py` then uses `os.listdir` and `os.path.join` to process files within the provided `key_path`:
     ```python
     def get_sa_details_from_key_files(key_path):
         malformed_keys = []
         sa_details = []
         for keyfile in os.listdir(key_path): # Potential Path Traversal if key_path is attacker-controlled
             if not keyfile.endswith('.json'):
                 malformed_keys.append(keyfile)
                 continue

             full_key_path = os.path.join(key_path, keyfile) # Path is joined without sanitization
             try:
                 account_name, credentials = credsdb.get_creds_from_file(full_key_path) # File is opened based on unsanitized path
                 if credentials is None:
                     logging.error('Failed to retrieve credentials for %s', account_name)
                     continue

                 sa_details.append((account_name, credentials, []))
             except (MalformedError, JSONDecodeError, Exception):
                 malformed_keys.append(keyfile)
         # ...
         return sa_details
     ```
   - Similarly, `creds_from_access_token` and `creds_from_refresh_token` functions directly open files using paths from `access_token_files` and `refresh_token_files` arguments:
     ```python
     def creds_from_access_token(access_token_file):
         with open(access_token_file, encoding="utf-8") as f: # File is opened based on unsanitized path
             creds_dict = json.load(f)
         # ...

     def creds_from_refresh_token(refresh_token_file):
         with open(refresh_token_file, encoding="utf-8") as f: # File is opened based on unsanitized path
             creds_dict = json.load(f)
         # ...
     ```
   - The `args.config_path` is used in `scanner.main` to load the configuration file:
     ```python
     if args.config_path is not None:
         with open(args.config_path, 'r', encoding='utf-8') as f: # File is opened based on unsanitized path
             scan_config = json.load(f)
     ```

   - **Visualization:**

     ```
     User Input (Path Argument) --> arguments.py (Argument Parsing, No Sanitization) --> scanner.py (Passes Path) --> credsdb.py/scanner.py (File Operations with Unsanitized Path) --> File System Access
     ```

3. **Vulnerability Point:**
   - The vulnerability lies in the lack of sanitization of the file paths provided through command-line arguments and the direct use of these paths in file operations (`open()`, `os.path.join()`). An attacker can provide paths like `/etc/passwd`, `../../../../etc/passwd`, etc., to read arbitrary files.

- **Security Test Case:**

1. **Prerequisites:**
   - Have the GCP Scanner application installed and accessible via command-line.
   - Have access to a terminal where you can execute the GCP Scanner.

2. **Steps to reproduce:**
   - Open a terminal.
   - Execute the GCP Scanner with a path traversal payload for the `-k` argument (or `-g`, `-at`, `-rt`, `-c`). For example, to read `/etc/passwd`, use:
     ```bash
     python scanner.py -o output_dir -k "../../../../../../../../../etc/"
     ```
     or if using the installed package:
     ```bash
     gcp-scanner -o output_dir -k "../../../../../../../../../etc/"
     ```
     Note: The number of `../` needed might vary depending on the execution path and where the scanner is run from. Ensure the output directory exists.

   - Check the output directory (`output_dir`). While the scanner might fail to process `/etc/passwd` as a valid SA key, attempt to locate any error messages or log files (if logging is enabled with `-lf`) that might reveal attempts to access files outside the intended directory.

   - To further confirm, you can try to read a file that is expected to be a JSON file to trigger the `json.load` part and see if it throws an error or if you can observe any content from the target file in the logs or output (though the scanner is not designed to display file content).

   - A more direct test is to provide a path like `-at "../../../../../../../../../etc/passwd"` and check for error messages that indicate the system tried to open `/etc/passwd` as an access token file.

3. **Expected Result:**
   - Ideally, the application should throw an error indicating that the provided path is invalid or outside the allowed scope, and it should *not* attempt to access or process the file at the traversed path.
   - In the vulnerable state, you might observe errors related to JSON parsing if the scanner tries to parse `/etc/passwd` as a JSON key file, but the key point is that it attempts to access the file at the given path.
   - By observing error logs or application behavior, you can confirm that the application is attempting to access files based on the traversed path, thus validating the vulnerability.

This vulnerability allows an attacker to bypass intended file access restrictions and potentially read any file accessible to the user running the GCP Scanner, posing a significant security risk.

### Sensitive Information Exposure via Output Files

- **Vulnerability Name:** Sensitive Information Exposure via Output Files
- **Description:** The `gcp_scanner` tool outputs scan results into JSON files in the directory specified by the `-o` or `--output-dir` argument. These files contain sensitive information about GCP resources and the access level of the provided credentials. If the output directory is not properly secured (e.g., world-readable permissions, stored in a publicly accessible location), an attacker gaining access to these files can learn about the organization's GCP infrastructure and the scope of permissions granted to the scanned credentials.
- **Impact:** Exposure of sensitive GCP resource information, potentially leading to unauthorized access to GCP resources if the compromised credentials are also exposed or misused based on the information gathered from the output files.
- **Vulnerability Rank:** High
- **Currently Implemented Mitigations:** None within the `gcp_scanner` project itself. The tool relies on the user to secure the output directory.
- **Missing Mitigations:**
    - Documentation emphasizing the need to secure the output directory and handle JSON files with care.
    - Option to encrypt output files.
    - Option to redact sensitive information from output files (though this might reduce the tool's utility).
- **Preconditions:**
    - A user runs `gcp_scanner` and generates output files.
    - The output directory or the generated JSON files are not adequately secured.
    - An attacker gains access to the output directory or the JSON files.
- **Source Code Analysis:**
    - `scanner.py`: The `save_results` function in `/code/src/gcp_scanner/scanner.py` is responsible for writing the scan results to JSON files.
    ```python
    def save_results(res_data: Dict, res_path: str, is_light: bool):
      """The function to save scan results on disk in json format.

      Args:
        res_data: scan results as a dictionary of entries
        res_path: full path to save data in file
        is_light: save only the most interesting results
      """

      if is_light is True:
        # returning the light version of the scan based on predefined schema
        for gcp_resource, schema in LIGHT_VERSION_SCAN_SCHEMA.items():
          projects = res_data.get('projects', {})
          for project_name, project_data in projects.items():
            scan_results = project_data.get(gcp_resource, {})
            light_results = list()
            for scan_result in scan_results:
              light_results.append({key: scan_result.get(key) for key in schema})

            project_data.update({gcp_resource: light_results})
            projects.update({project_name: project_data})
          res_data.update({'projects': projects})

      # Write out results to json DB
      sa_results_data = json.dumps(res_data, indent=2, sort_keys=False)

      with open(res_path, 'a', encoding='utf-8') as outfile:
        outfile.write(sa_results_data)
    ```
    The function takes the output directory path (`res_path`) as an argument but does not implement any security measures for these files. It simply writes the JSON data to the specified path.
    - `arguments.py`: The `arg_parser` function in `/code/src/gcp_scanner/arguments.py` defines the `-o` and `--output-dir` arguments, allowing users to specify the output directory, but without security considerations.
    ```python
      required_named.add_argument(
        '-o',
        '--output-dir',
        required=True,
        dest='output',
        default='scan_db',
        help='Path to output directory')
    ```
- **Security Test Case:**
    1. Run `gcp_scanner` with the `-o /tmp/gcp_scan_results` option, using any available credential method (e.g., `-m`).
    ```bash
    python3 scanner.py -m -o /tmp/gcp_scan_results
    ```
    2. After the scan completes, change the permissions of the output directory to world-readable.
    ```bash
    chmod -R 777 /tmp/gcp_scan_results
    ```
    3. As an attacker, access the system and navigate to the `/tmp/gcp_scan_results` directory.
    ```bash
    cd /tmp/gcp_scan_results
    ```
    4. Open and read one of the JSON output files (e.g., `<project-id>-<timestamp>.json`).
    ```bash
    cat <project-id>-<timestamp>.json
    ```
    5. Observe the sensitive information about GCP resources (e.g., instance names, storage bucket names, IAM policy details) and infer the access level of the scanned credentials.
    6. Success: The attacker has successfully accessed sensitive information from the output files due to the lack of security measures on these files and insecure directory permissions.

### Insecure Output Directory

- **Vulnerability Name:** Insecure Output Directory
- **Description:**
  1. An attacker socially engineers a victim to run `gcp_scanner`.
  2. The attacker convinces the victim to specify an attacker-controlled directory as the output directory using the `-o OUTPUT_DIR` parameter. This could be a directory accessible to the attacker, such as a publicly writable directory or a directory the attacker has gained access to through other means.
  3. The victim executes `gcp_scanner` with their GCP credentials, and the scan results, which may contain sensitive information about their GCP environment, are written to the attacker-controlled output directory.
  4. The attacker accesses the output directory and retrieves the scan results, gaining unauthorized access to sensitive information.
- **Impact:** Unauthorized access to sensitive information about the victim's GCP environment. This may include details about GCP resources, configurations, and potentially IAM policies, depending on the scanner's output. This information could be used for further attacks on the victim's GCP environment.
- **Vulnerability Rank:** High
- **Currently Implemented Mitigations:** None in the code itself. The `README.md` implicitly warns about the sensitivity of the output data by describing what the tool does, but it doesn't explicitly warn against using attacker-controlled output directories.
- **Missing Mitigations:**
  - Explicit warning in the `README.md` about the security risks of using attacker-controlled output directories.
  - Security warning message printed to the console when the tool starts, highlighting the risk of writing sensitive data to untrusted directories.
- **Preconditions:**
  - The attacker needs to socially engineer a victim to run `gcp_scanner`.
  - The attacker needs to convince the victim to specify an attacker-controlled output directory using the `-o OUTPUT_DIR` parameter.
- **Source Code Analysis:**
  - `src/gcp_scanner/arguments.py`: The `arg_parser` function defines the `-o` or `--output-dir` argument, taking user-specified path without validation.
  ```python
    required_named = parser.add_argument_group('Required parameters')
    required_named.add_argument(
        '-o',
        '--output-dir',
        required=True,
        dest='output',
        default='scan_db',
        help='Path to output directory')
  ```
  - `src/gcp_scanner/scanner.py`: The `save_results` function saves scan output to the directory specified by `-o` parameter without validation.
  ```python
  def save_results(res_data: Dict, res_path: str, is_light: bool):
    ...
    with open(res_path, 'a', encoding='utf-8') as outfile:
      outfile.write(sa_results_data)
  ```
- **Security Test Case:**
  1. Attacker sets up a publicly writable directory, for example `/tmp/attacker_output_dir` on a shared hosting service or locally for testing.
  2. Attacker crafts a social engineering message to the victim, instructing them to run `gcp_scanner` with their GCP credentials.
  3. The attacker instructs the victim to use the following command, replacing `[VICTIM_GCP_CREDENTIALS]` with the victim's actual credential options and `[ATTACKER_OUTPUT_DIR]` with `/tmp/attacker_output_dir`. For example, if victim uses gcloud profile:
     `python3 scanner.py -o /tmp/attacker_output_dir -g -`
  4. The victim executes the command.
  5. `gcp_scanner` runs and writes the scan results to `/tmp/attacker_output_dir`.
  6. The attacker accesses the `/tmp/attacker_output_dir` and retrieves the JSON scan results file.
  7. Attacker opens the JSON scan results file and gains sensitive information about the victim's GCP environment.
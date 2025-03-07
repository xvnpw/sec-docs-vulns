- Vulnerability name: Sensitive Information Exposure via Output Files
- Description: The `gcp_scanner` tool outputs scan results into JSON files in the directory specified by the `-o` or `--output-dir` argument. These files contain sensitive information about GCP resources and the access level of the provided credentials. If the output directory is not properly secured (e.g., world-readable permissions, stored in a publicly accessible location), an attacker gaining access to these files can learn about the organization's GCP infrastructure and the scope of permissions granted to the scanned credentials.
- Impact: Exposure of sensitive GCP resource information, potentially leading to unauthorized access to GCP resources if the compromised credentials are also exposed or misused based on the information gathered from the output files.
- Vulnerability rank: High
- Currently implemented mitigations: None within the `gcp_scanner` project itself. The tool relies on the user to secure the output directory.
- Missing mitigations:
    - Documentation emphasizing the need to secure the output directory and handle JSON files with care.
    - Option to encrypt output files.
    - Option to redact sensitive information from output files (though this might reduce the tool's utility).
- Preconditions:
    - A user runs `gcp_scanner` and generates output files.
    - The output directory or the generated JSON files are not adequately secured.
    - An attacker gains access to the output directory or the JSON files.
- Source code analysis:
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
- Security test case:
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
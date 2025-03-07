- Vulnerability Name: Insecure Output Directory
- Description:
  1. An attacker socially engineers a victim to run `gcp_scanner`.
  2. The attacker convinces the victim to specify an attacker-controlled directory as the output directory using the `-o OUTPUT_DIR` parameter. This could be a directory accessible to the attacker, such as a publicly writable directory or a directory the attacker has gained access to through other means.
  3. The victim executes `gcp_scanner` with their GCP credentials, and the scan results, which may contain sensitive information about their GCP environment, are written to the attacker-controlled output directory.
  4. The attacker accesses the output directory and retrieves the scan results, gaining unauthorized access to sensitive information.
- Impact: Unauthorized access to sensitive information about the victim's GCP environment. This may include details about GCP resources, configurations, and potentially IAM policies, depending on the scanner's output. This information could be used for further attacks on the victim's GCP environment.
- Vulnerability Rank: High
- Currently Implemented Mitigations: None in the code itself. The `README.md` implicitly warns about the sensitivity of the output data by describing what the tool does, but it doesn't explicitly warn against using attacker-controlled output directories.
- Missing Mitigations:
  - Explicit warning in the `README.md` about the security risks of using attacker-controlled output directories.
  - Security warning message printed to the console when the tool starts, highlighting the risk of writing sensitive data to untrusted directories.
- Preconditions:
  - The attacker needs to socially engineer a victim to run `gcp_scanner`.
  - The attacker needs to convince the victim to specify an attacker-controlled output directory using the `-o OUTPUT_DIR` parameter.
- Source Code Analysis:
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
- Security Test Case:
  1. Attacker sets up a publicly writable directory, for example `/tmp/attacker_output_dir` on a shared hosting service or locally for testing.
  2. Attacker crafts a social engineering message to the victim, instructing them to run `gcp_scanner` with their GCP credentials.
  3. The attacker instructs the victim to use the following command, replacing `[VICTIM_GCP_CREDENTIALS]` with the victim's actual credential options and `[ATTACKER_OUTPUT_DIR]` with `/tmp/attacker_output_dir`. For example, if victim uses gcloud profile:
     `python3 scanner.py -o /tmp/attacker_output_dir -g -`
  4. The victim executes the command.
  5. `gcp_scanner` runs and writes the scan results to `/tmp/attacker_output_dir`.
  6. The attacker accesses the `/tmp/attacker_output_dir` and retrieves the JSON scan results file.
  7. Attacker opens the JSON scan results file and gains sensitive information about the victim's GCP environment.
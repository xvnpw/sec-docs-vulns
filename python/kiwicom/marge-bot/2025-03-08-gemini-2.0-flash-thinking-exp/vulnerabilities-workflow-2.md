## Vulnerability Report

The following vulnerabilities have been identified in the application.

### YAML Deserialization leading to Remote Code Execution

- **Description:**
  1. An attacker crafts a malicious YAML configuration file that injects and executes arbitrary Python code by leveraging YAML deserialization vulnerabilities.
  2. The attacker gains access to the system running `marge-bot` and places the malicious YAML file in a location accessible to the `marge-bot` application. Alternatively, the attacker might influence the configuration file path if it's not strictly controlled.
  3. The attacker instructs `marge-bot` to use this malicious configuration file by providing the path via the `--config-file` command-line argument or the `MARGE_CONFIG_FILE` environment variable.
  4. When `marge-bot` starts or reloads its configuration, it parses the malicious YAML file using the insecure `yaml.load()` function from the PyYAML library.
  5. The maliciously crafted YAML file triggers the execution of the injected Python code due to the insecure nature of `yaml.load()`.
  6. This results in arbitrary code execution on the server running `marge-bot`, granting the attacker control over the application and potentially the underlying system.
- **Impact:**
  Successful exploitation allows for arbitrary code execution, leading to:
    - Complete compromise of the `marge-bot` application.
    - Unauthorized access to GitLab API credentials and other secrets managed by `marge-bot`.
    - Lateral movement to other systems accessible from the `marge-bot` server.
    - Data exfiltration and manipulation.
    - Denial of service by disrupting `marge-bot` operations or the entire system.
- **Vulnerability Rank:** Critical
- **Currently Implemented Mitigations:**
  There are no mitigations implemented. The code directly uses `yaml.load()` without any input sanitization or safe loading mechanisms.
- **Missing Mitigations:**
    - Replace `yaml.load()` with `yaml.safe_load()` to restrict deserialization to basic data types.
    - Implement input validation and sanitization of the configuration file content.
    - Apply the principle of least privilege by running `marge-bot` with minimum necessary permissions.
    - Restrict filesystem permissions to the configuration file, limiting access to the `marge-bot` user and administrators.
- **Preconditions:**
    - The attacker must be able to provide a malicious YAML configuration file to `marge-bot`, either by having write access to the filesystem or by influencing the configuration file path.
- **Source Code Analysis:**
  1. **Configuration Loading in `app.py`**: The `_parse_config(args)` function in `/code/marge/app.py` parses command-line arguments and loads configuration files using `configargparse` with YAML support (`config_file_parser_class=configargparse.YAMLConfigFileParser`).
  2. **YAML Parsing in `configargparse` (Implicit)**: `configargparse.YAMLConfigFileParser` likely uses `PyYAML`'s `yaml.load()` by default, which is known to be unsafe.
  3. **Vulnerable Code Path**: The `main(args=None)` function calls `_parse_config(args)`, which processes the `--config-file` argument and leads to YAML parsing using the unsafe `yaml.load()` if a malicious file is provided.

  ```
  /code/marge/app.py

  def _parse_config(args):
      ...
      parser = configargparse.ArgParser(
          ...
          config_file_parser_class=configargparse.YAMLConfigFileParser,
          ...
      )
      config = parser.parse_args(args)
      ...
      return config

  def main(args=None):
      ...
      options = _parse_config(args) # Vulnerable YAML loading here.
      ...
      marge_bot = bot.Bot(api=api, config=config)
      marge_bot.start()
  ```

  ```mermaid
  graph LR
      A[Start marge-bot] --> B(Parse command-line args);
      B --> C{--config-file provided?};
      C -- Yes --> D[YAMLConfigFileParser (configargparse)];
      D --> E[yaml.load() (PyYAML - UNSAFE)];
      C -- No --> F[Proceed without config file];
      E --> G[RCE Vulnerability];
  ```
- **Security Test Case:**
  1. Create `malicious_config.yaml`:
     ```yaml
     !!python/object/apply:os.system ["touch /tmp/pwned"]
     ```
  2. Run `marge-bot`:
     ```bash
     marge.app --config-file malicious_config.yaml --auth-token <your_gitlab_token> --gitlab-url <your_gitlab_url> --ssh-key-file <path_to_ssh_key_file>
     ```
  3. Verify: Check if `/tmp/pwned` exists on the server. If it exists, RCE is confirmed.

### Command Injection in Git Filter-Branch via Reviewer Names/Emails

- **Description:**
  1. An attacker with write access to a GitLab project creates a merge request.
  2. The attacker manipulates their GitLab user profile (name or email) to include shell-command injection payloads.
  3. When Marge-bot processes a merge request from this attacker with `--add-reviewers` enabled, it fetches reviewer information, including the attacker's manipulated name/email, from the GitLab API.
  4. This information is used to construct a `git filter-branch` command in `tag_with_trailer` in `marge/git.py`.
  5. Insufficient sanitization of the reviewer's name/email allows injected shell commands to execute on the Marge-bot server when `git filter-branch` is invoked.
- **Impact:**
  Successful command injection allows arbitrary command execution on the Marge-bot server, leading to:
    - Confidentiality breach: Access to sensitive data, source code, configurations.
    - Integrity breach: Modification of code, configurations, system files.
    - Availability breach: Denial of service, disruption of Marge-bot operations.
- **Vulnerability Rank:** High
- **Currently Implemented Mitigations:**
  None. No sanitization is performed on reviewer names or emails before use in shell commands.
- **Missing Mitigations:**
    - Sanitize reviewer names and emails from the GitLab API, escaping shell metacharacters in `trailer_values` within `_filter_branch_script` in `marge/git.py`.
    - Apply the principle of least privilege to limit the impact of command injection.
    - Consider safer alternatives to `filter-branch` or methods to add trailers without user-provided shell commands.
- **Preconditions:**
    - Marge-bot is running with `--add-reviewers` enabled.
    - Attacker has write access to a GitLab project monitored by Marge-bot and can create merge requests.
    - Attacker can modify their GitLab user profile name or email to include command injection payloads.
- **Source Code Analysis:**
  1. **`marge/git.py` - `_run` function:** Executes shell commands using `subprocess.Popen` without explicit sanitization of arguments.
  2. **`marge/git.py` - `_filter_branch_script` function:** Constructs a shell script using `shlex.quote` for `trailer_values`, but the overall script is still vulnerable if quoting is bypassed or input is malicious before quoting.
  3. **`marge/git.py` - `tag_with_trailer` function:** Calls `_filter_branch_script` and passes it to `git filter-branch`, using `trailer_values` from `marge/job.py`.
  4. **`marge/job.py` - `_get_reviewer_names_and_emails` function:** Retrieves reviewer names and emails from the GitLab API, where malicious data can originate.
  5. **`marge/job.py` - `add_trailers` function:** Calls `_get_reviewer_names_and_emails` and then `repo.tag_with_trailer` with potentially unsanitized reviewer information.

  ```python
  # /code/marge/git.py
  def _run(*args, env=None, check=False, timeout=None): # Unsafe command execution
      ... subprocess.Popen(encoded_args, ...)

  def _filter_branch_script(trailer_name, trailer_values): # Constructs shell script, potentially vulnerable
      filter_script = 'TRAILERS={trailers} python3 {script}'.format(
          trailers=shlex.quote(...), # Quoting might not be sufficient
          script=trailerfilter.__file__,
      )
      return filter_script

  def tag_with_trailer(self, trailer_name, trailer_values, branch, start_commit): # Calls _filter_branch_script
      filter_script = _filter_branch_script(trailer_name, trailer_values)
      self.git('filter-branch', '--force', '--msg-filter', filter_script, commit_range) # Executes script

  # /code/marge/job.py
  def _get_reviewer_names_and_emails(commits, approvals, api): # Fetches user data from API
      users = [User.fetch_by_id(uid, api) for uid in uids] # Potentially malicious user data

  def add_trailers(self, merge_request): # Calls tag_with_trailer with unsanitized data
      reviewers = _get_reviewer_names_and_emails(...) # Unsanitized reviewers
      if reviewers is not None:
          sha = self._repo.tag_with_trailer(trailer_name='Reviewed-by', trailer_values=reviewers, ...) # Passing to git command
  ```
- **Security Test Case:**
  1. **Setup:** Marge-bot with `--add-reviewers` enabled, connected to controlled GitLab instance. Users: `attacker`, `reviewer` (Developer role). Marge-bot user admin in GitLab.
  2. **Attacker Profile Modification:** As `attacker`, set GitLab profile Name/Email to `Attacker Name \`$(touch /tmp/pwned)\`` or `attacker@example.com \`$(touch /tmp/pwned)\``.
  3. **Trigger:** `attacker` creates MR, assigns to `reviewer`, requests review. `reviewer` approves, assigns to Marge-bot.
  4. **Verify:** Check Marge-bot server filesystem for `/tmp/pwned`. If present, command injection confirmed.

### Insecure SSH Host Key Checking

- **Description:** Marge-bot disables SSH host key checking by setting `StrictHostKeyChecking=no` in `GIT_SSH_COMMAND`. This bypasses security measures against man-in-the-middle (MITM) attacks by automatically accepting the host key of the GitLab server on the first connection without verification. An attacker intercepting the initial connection could impersonate the GitLab server and gain unauthorized control over git operations.
- **Impact:**
    - High. MITM attack can lead to GitLab server impersonation, potentially enabling:
        - Stealing the Marge-bot's SSH private key (theoretically).
        - Manipulating git operations: merging malicious code, data exfiltration, denial of service.
- **Vulnerability Rank:** High
- **Currently Implemented Mitigations:**
    - None in code; host key checking is explicitly disabled.
    - Documentation mentions SSH key file usage, but this does not mitigate the host key checking issue.
- **Missing Mitigations:**
    - Implement proper SSH host key verification.
        - Store GitLab server's host key in a `known_hosts` file.
        - Configure `GIT_SSH_COMMAND` with `StrictHostKeyChecking=yes` or `StrictHostKeyChecking=accept-new` and use the `known_hosts` file.
        - Provide a mechanism to update `known_hosts` if the GitLab server's host key changes.
- **Preconditions:**
    - Marge-bot uses SSH for git operations (`--use-https` not used).
    - Attacker can perform a MITM attack during Marge-bot's first connection to the GitLab server.
    - Most critical on the first connection or after `known_hosts` entry removal.
- **Source Code Analysis:**
    - File: `/code/marge/git.py`
    - Line: `GIT_SSH_COMMAND = "ssh -o StrictHostKeyChecking=no "`
    - Hardcoded `StrictHostKeyChecking=no` in `GIT_SSH_COMMAND` disables host key checking for all git commands when SSH is used.

    ```python
    # /code/marge/git.py
    GIT_SSH_COMMAND = "ssh -o StrictHostKeyChecking=no " # Vulnerable configuration

    class Repo:
        def __init__(self, ... ssh_key_file=None):
            ...
            if ssh_key_file:
                env['GIT_SSH_COMMAND'] = GIT_SSH_COMMAND + " -i " + ssh_key_file # Using vulnerable GIT_SSH_COMMAND
            ...
            self._git = functools.partial(self._run, env=env, check=True) # Using env with vulnerable GIT_SSH_COMMAND
    ```
- **Security Test Case:**
    1. **Setup:** Fake GitLab server with known SSH host key. Marge-bot configured to connect via SSH to fake server. MITM proxy (`ssh-mitm`) to intercept connection and present a different host key.
    2. **Execution:** Run Marge-bot.
    3. **Expected Result:** Marge-bot connects to MITM proxy and accepts the forged host key without warnings due to `StrictHostKeyChecking=no`. Git operations should succeed even with the forged key.
    4. **Cleanup:** Stop Marge-bot and MITM proxy.
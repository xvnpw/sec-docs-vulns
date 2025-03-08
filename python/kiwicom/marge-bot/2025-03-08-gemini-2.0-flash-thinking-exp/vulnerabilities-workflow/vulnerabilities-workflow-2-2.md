### Vulnerability List:

- Vulnerability Name: Command Injection in Git Filter-Branch via Reviewer Names/Emails

- Description:
  1. An attacker with write access to a GitLab project can create a merge request.
  2. The attacker can then manipulate their GitLab user profile (name or email) to include shell-command injection payloads.
  3. When a merge request from this attacker is processed by Marge-bot and the `--add-reviewers` option is enabled, Marge-bot fetches reviewer information, including the attacker's manipulated name or email, from the GitLab API.
  4. This information is used to construct a `git filter-branch` command in the `tag_with_trailer` function in `marge/git.py`.
  5. Due to insufficient sanitization of the reviewer's name or email, the attacker's injected shell commands are executed on the server running Marge-bot when `git filter-branch` is invoked.

- Impact:
  - **High**: Successful command injection allows the attacker to execute arbitrary commands on the server hosting Marge-bot. This could lead to:
    - Confidentiality breach: Access to sensitive data, source code, environment variables, and configuration files.
    - Integrity breach: Modification of source code, configuration, or system files.
    - Availability breach: Denial of service, disruption of Marge-bot operations, or complete system compromise.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
  - None: The code does not implement any sanitization or input validation on reviewer names or emails before using them in the `git filter-branch` command.

- Missing Mitigations:
  - Input sanitization: Sanitize reviewer names and emails retrieved from the GitLab API before using them in shell commands. Specifically, escape shell metacharacters in the `trailer_values` within the `_filter_branch_script` function in `marge/git.py`.
  - Principle of least privilege: Run Marge-bot with minimal necessary privileges to limit the impact of command injection.
  - Consider using safer alternatives to `filter-branch` or methods to add trailers without constructing shell commands from user inputs.

- Preconditions:
  - Marge-bot is running with the `--add-reviewers` option enabled.
  - An attacker has write access to a GitLab project monitored by Marge-bot and can create a merge request.
  - The attacker can modify their GitLab user profile name or email to include command injection payloads.

- Source Code Analysis:
  1. **`marge/git.py` - `_run` function:**
     - The `_run` function executes shell commands using `subprocess.Popen`.
     - Arguments passed to `_run` are not explicitly sanitized.
     ```python
     def _run(*args, env=None, check=False, timeout=None):
         encoded_args = [a.encode('utf-8') for a in args] if sys.platform != 'win32' else args
         with subprocess.Popen(encoded_args, env=env, stdout=PIPE, stderr=PIPE) as process:
             # ... execution logic ...
     ```

  2. **`marge/git.py` - `_filter_branch_script` function:**
     - This function constructs a shell script using `shlex.quote` for `trailer_values` but the overall script is still vulnerable if `trailer_values` contains malicious content before quoting or if quoting is bypassed.
     ```python
     def _filter_branch_script(trailer_name, trailer_values):
         filter_script = 'TRAILERS={trailers} python3 {script}'.format(
             trailers=shlex.quote(
                 '\n'.join(
                     '{}: {}'.format(trailer_name, trailer_value)
                     for trailer_value in trailer_values or [''])
             ),
             script=trailerfilter.__file__,
         )
         return filter_script
     ```

  3. **`marge/git.py` - `tag_with_trailer` function:**
     - Calls `_filter_branch_script` to create the shell script and passes it to `git filter-branch`.
     - `trailer_values` comes directly from `marge/job.py`.
     ```python
     def tag_with_trailer(self, trailer_name, trailer_values, branch, start_commit):
         """Replace `trailer_name` in commit messages with `trailer_values` in `branch` from `start_commit`.
         """
         filter_script = _filter_branch_script(trailer_name, trailer_values)
         commit_range = start_commit + '..' + branch
         try:
             # --force = overwrite backup of last filter-branch
             self.git('filter-branch', '--force', '--msg-filter', filter_script, commit_range)
         except GitError:
             # ... error handling ...
             raise
         return self.get_commit_hash()
     ```

  4. **`marge/job.py` - `_get_reviewer_names_and_emails` function:**
     - Retrieves reviewer information (names and emails) from the GitLab API.
     - This is where potentially malicious user data is fetched.
     ```python
     def _get_reviewer_names_and_emails(commits, approvals, api):
         """Return a list ['A. Prover <a.prover@example.com', ...]` for `merge_request.`"""
         uids = approvals.approver_ids
         users = [User.fetch_by_id(uid, api) for uid in uids]
         self_reviewed = {commit['author_email'] for commit in commits} & {user.email for user in users}
         if self_reviewed and len(users) <= 1:
             raise CannotMerge('Commits require at least one independent reviewer.')
         return ['{0.name} <{0.email}>'.format(user) for user in users]
     ```

  5. **`marge/job.py` - `add_trailers` function:**
     - Calls `_get_reviewer_names_and_emails` and then `repo.tag_with_trailer` with the potentially unsanitized reviewer information.
     ```python
     def add_trailers(self, merge_request):
         log.info('Adding trailers for MR !%s', merge_request.iid)

         # add Reviewed-by
         should_add_reviewers = (
             self._options.add_reviewers and
             self._options.fusion is not Fusion.gitlab_rebase
         )
         reviewers = (
             _get_reviewer_names_and_emails(
                 merge_request.fetch_commits(),
                 merge_request.fetch_approvals(),
                 self._api,
             ) if should_add_reviewers
             else None
         )
         sha = None
         if reviewers is not None:
             sha = self._repo.tag_with_trailer(
                 trailer_name='Reviewed-by',
                 trailer_values=reviewers,
                 branch=merge_request.source_branch,
                 start_commit='origin/' + merge_request.target_branch,
             )
         # ... rest of the function ...
     ```

- Security Test Case:
  1. **Setup:**
     - Have a running instance of Marge-bot with `--add-reviewers` enabled and connected to a GitLab instance you control.
     - Create a GitLab project and add Marge-bot as a member.
     - Create two GitLab users: `attacker` and `reviewer`. Add both as members to the project with Developer role.
     - As the `attacker` user, modify your GitLab profile:
       - Set Name to: `Attacker Name \`$(touch /tmp/pwned)\``
       - Or Email to: `attacker@example.com \`$(touch /tmp/pwned)\``
     - Ensure the Marge-bot user has admin privileges in GitLab to enable `--add-reviewers`.

  2. **Trigger Vulnerability:**
     - As the `attacker` user, create a new merge request in the project, targeting the `master` branch.
     - Assign the merge request to the `reviewer` user and request a review.
     - As the `reviewer` user, approve the merge request and assign it to the Marge-bot user.

  3. **Verify Exploit:**
     - Check the Marge-bot server's filesystem.
     - If the vulnerability is successfully exploited, a file named `pwned` will be created in the `/tmp/` directory on the Marge-bot server.
     - Examine the Marge-bot logs for any error messages or signs of command execution failure, which might indicate successful or attempted injection.
     - If the file `/tmp/pwned` exists, this confirms command injection vulnerability.
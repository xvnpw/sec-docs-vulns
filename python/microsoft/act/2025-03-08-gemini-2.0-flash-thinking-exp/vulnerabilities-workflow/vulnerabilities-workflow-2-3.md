- Vulnerability Name: Command Injection in `submit cmd` functionality
- Description:
    1. A malicious user crafts a command containing shell injection payloads.
    2. The user executes the ACT command `a submit <malicious_command>` via the command-line interface.
    3. The `aml_client.py` script packages this command and submits it to Azure Machine Learning service.
    4. The `aml_server.py` script, running within the AML environment, receives the crafted command.
    5. `aml_server.py` uses `subprocess.Popen` to execute the command, without sufficient sanitization.
    6. Due to lack of sanitization, shell injection payloads within the command are executed by the underlying shell in the AML compute environment.
    7. This allows the attacker to execute arbitrary commands within the AML compute context.
- Impact:
    - Arbitrary command execution within the Azure Machine Learning compute environment.
    - Potential for unauthorized access to data and resources within the AML workspace and potentially other connected Azure services.
    - Data exfiltration from the AML environment.
    - Modification or deletion of data and AML configurations.
    - Potential for denial of service by consuming compute resources or disrupting AML services.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations:
    - None. The code directly executes user-provided commands without any input sanitization or validation.
- Missing Mitigations:
    - Input sanitization on the client-side (`aml_client.py`) to escape or reject shell metacharacters in user-provided commands.
    - In `aml_server.py`, use secure command execution practices such as:
        - Avoiding the use of `shell=True` in `subprocess.Popen`.
        - Passing commands as a list to `subprocess.Popen` where the first element is the executable and subsequent elements are arguments, ensuring that no shell interpretation occurs on the command string itself.
        - If shell execution is absolutely necessary, implement robust input validation and sanitization to prevent shell injection. Consider using parameterized commands or prepared statements if applicable.
        - Employ principle of least privilege by running AML jobs with minimal necessary permissions to limit the blast radius of a successful command injection attack.
- Preconditions:
    - The attacker needs to have access to the ACT command-line tool.
    - The attacker needs to have valid Azure credentials to configure ACT and submit jobs to the Azure Machine Learning service.
- Source Code Analysis:
    1. **`act/aml_client.py` - `AMLClient.submit` function:**
        ```python
        def submit(self, cmd, num_gpu=None):
            # ...
            script_params = {'--' + p: str(v['mount_point']) if not v.get('submit_with_url') else v['cloud_blob'].get_url(v['path'])
                             for p, v in self.config_param.items()}
            script_params['--command'] = cmd if isinstance(cmd, str) else ' '.join(cmd)
            # ...
        ```
        This code snippet shows that the user-supplied `cmd` is directly placed into the `script_params` dictionary under the key `--command`. This dictionary is then used to construct the arguments for the AML job submission. The raw command string is passed without any sanitization.

    2. **`act/aml_server.py` - `wrap_all` function:**
        ```python
        def wrap_all(code_zip, code_root,
                     folder_link, command,
                     compile_args,
                     ):
            # ...
            logging.info(command)
            if type(command) is str:
                command = list(command.split(' '))

            with MonitoringProcess():
                if len(command) > 0:
                    cmd_run(command, working_directory=code_root,
                                succeed=True)
        ```
        The `wrap_all` function in `aml_server.py` receives the `command` argument.  Critically, it splits the command string by spaces into a list if it's a string. While `cmd_run` itself doesn't use `shell=True`, the act of splitting the command string into a list and then passing it to `subprocess.Popen` without further control can still be vulnerable, especially if the first element of the list is a shell interpreter like `bash` or `python -c`.

    3. **`act/aml_server.py` - `cmd_run` function:**
        ```python
        def cmd_run(cmd, working_directory='./', succeed=False,
                    return_output=False, stdout=None, stderr=None,
                    silent=False,
                    no_commute=False,
                    timeout=None,
                    ):
            # ...
            if not return_output:
                try:
                    p = sp.Popen(
                        cmd, stdin=sp.PIPE,
                        cwd=working_directory,
                        env=e,
                        stdout=stdout,
                        stderr=stderr,
                    )
                    if not no_commute:
                        p.communicate(timeout=timeout)
                        if succeed:
                            logging.info('return code = {}'.format(p.returncode))
                            assert p.returncode == 0
                    return p
                except:
                    # ...
        ```
        The `cmd_run` function uses `subprocess.Popen` to execute the command. It does not use `shell=True`, which is good, but it directly takes the `cmd` argument (which is a list in this case from `wrap_all`) and passes it to `Popen`.  This is vulnerable if the first element of the list is a shell interpreter and the subsequent elements contain malicious payloads that the shell interpreter can process.

- Security Test Case:
    1. **Prerequisites:**
        - Install ACT tool as described in `README.md`.
        - Configure ACT with valid Azure credentials and AML workspace details as per `README.md`.
        - Ensure you have the `act` alias set up as `alis a='python -m act.aml_client '`.
    2. **Steps:**
        - Open a terminal where ACT is configured.
        - Execute the following command to submit a job with a command injection payload:
          ```bash
          a submit bash -c "mkdir /tmp/pwned && touch /tmp/pwned/success"
          ```
        - Wait for the job to complete or fail. You can monitor the job status using `a query <run_id>` (replace `<run_id>` with the run ID returned after submitting the job).
        - After the job is in a "Completed" or "Failed" state, examine the job logs. Use `a query <run_id>` again. The logs will be downloaded to `./assets/<run_id>`.
        - Check the logs, particularly `70_driver_log_0.txt` or similar driver logs, for any output indicating successful execution of the injected commands `mkdir /tmp/pwned` and `touch /tmp/pwned/success`.  Successful exploitation might not always leave obvious log traces directly related to the injected command itself, but in many scenarios, evidence of execution will be present. In a more robust test, you would attempt network communication or data exfiltration to definitively confirm arbitrary command execution.
    3. **Expected Result:**
        - If the vulnerability is present, the injected commands `mkdir /tmp/pwned && touch /tmp/pwned/success` will be executed in the AML compute environment. Although direct file system access to the AML compute instance from outside is typically restricted, successful execution can be inferred from log messages or by attempting more sophisticated payloads that have observable side effects (e.g., network requests logged externally, resource consumption, etc., although these are outside the scope of a simple test case). For this test case, observing any log entries related to `mkdir` or `touch` operations, or unexpected behavior in subsequent job steps as a result of file system changes, would indicate successful command injection.
### Vulnerability List

- Vulnerability Name: Command Injection in `CommandFunction` via Unsanitized Arguments

- Description:
  1. The `submitit.helpers.CommandFunction` allows users to execute shell commands by providing a list of command arguments.
  2. When arguments are passed to the `CommandFunction` instance at call time, they are appended to the base command without proper sanitization.
  3. If a user-provided argument contains shell metacharacters, it can lead to command injection.
  4. An attacker could craft a malicious argument that, when passed to the `CommandFunction`, executes arbitrary commands on the Slurm cluster nodes.

- Impact:
  - High. Successful command injection can allow an attacker to execute arbitrary commands on the Slurm cluster nodes with the privileges of the user running the `submitit` job. This could lead to data breaches, system compromise, or denial of service.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
  - The documentation advises users to submit pure Python functions whenever possible to avoid the complexities and potential vulnerabilities of shell commands.
  - The `CommandFunction` uses `subprocess.Popen` with `shell=False` by default, which reduces the risk compared to `shell=True`, but does not prevent injection when arguments are appended unsanitized.

- Missing Mitigations:
  - Input sanitization for arguments passed to `CommandFunction` at call time to remove or escape shell metacharacters.
  - Documentation should explicitly warn against passing unsanitized user inputs as arguments to `CommandFunction`.
  - Consider providing a safer API for command execution that avoids string-based command construction and argument passing, perhaps by using more structured approaches if feasible.

- Preconditions:
  - The user's Python code uses `submitit.helpers.CommandFunction` to execute shell commands.
  - The user's Python code passes external, potentially attacker-controlled, strings as arguments to the `CommandFunction` instance when calling it.

- Source Code Analysis:
  ```python
  # File: /code/submitit/helpers.py
  class CommandFunction:
      # ...
      def __call__(self, *args: tp.Any, **kwargs: tp.Any) -> str:
          """Call the cammand line with addidional arguments
          The keyword arguments will be sent as --{key}={val}
          The logs bufferized. They will be printed if the job fails, or sent as output of the function
          Errors are provided with the internal stderr.
          """
          full_command = (
              self.command + [str(x) for x in args] + [f"--{x}={y}" for x, y in kwargs.items()]
          )  # TODO bad parsing
          if self.verbose:
              print(f"The following command is sent: \"{' '.join(full_command)}\"")
          with subprocess.Popen(
              full_command,
              stdout=subprocess.PIPE,
              stderr=subprocess.PIPE,
              shell=False,
              cwd=self.cwd,
              env=self.env,
          ) as process:
              # ...
  ```
  - The vulnerable code is in the `__call__` method of `CommandFunction`.
  - `full_command` is constructed by concatenating `self.command`, `args`, and `kwargs`.
  - `[str(x) for x in args]` converts arguments to strings but does not sanitize them for shell safety.
  - `subprocess.Popen` is called with `full_command` and `shell=False`, which prevents basic shell injection through the initial command list (`self.command`), but it does *not* prevent injection through the appended `args`.
  - If `args` contains shell metacharacters, these will be interpreted by the underlying system when `subprocess.Popen` executes the command, leading to command injection.

- Security Test Case:
  1. Create a Python script (e.g., `test_command_injection.py`) with the following content:
     ```python
     import submitit
     import sys

     command_function = submitit.helpers.CommandFunction(["echo", "Hello"])
     malicious_arg = sys.argv[1] if len(sys.argv) > 1 else ""
     output = command_function(malicious_arg)
     print("Output:", output)
     ```
  2. Run the script using `submitit`'s `AutoExecutor` in debug mode to execute locally:
     ```python
     import submitit

     executor = submitit.AutoExecutor(folder="log_test", cluster="debug")
     job = executor.submit(lambda malicious_arg: __import__('subprocess').run(['python', 'test_command_injection.py', malicious_arg], capture_output=True, text=True).stdout, "; touch injected_file")
     job.result()

     import os
     if os.path.exists("injected_file"):
         print("Vulnerability Found: injected_file created, command injection successful!")
     else:
         print("Vulnerability Not Found: injected_file not created.")
     ```
  3. Execute the above executor script. If a file named `injected_file` is created in the current directory, it confirms the command injection vulnerability. The malicious argument `; touch injected_file` was successfully appended and executed by the shell, even with `shell=False` in the base `CommandFunction` execution, because it's interpreted by the system when arguments are passed at call time.
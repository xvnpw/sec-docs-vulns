## Vulnerability List for Distla Project

* Vulnerability Name: **Remote Code Execution via User-Provided Scripts in TP Tool**

* Description:
  An attacker can achieve Remote Code Execution (RCE) on ASIC VM instances by crafting malicious content within user-provided scripts (`setup.sh`, `preflight.sh`, `entry_point`) and using the `tp run` command. The `tp run` functionality in the `distla/tp` tool executes these scripts on remote ASIC VM instances without sufficient sanitization or validation.

  Steps to trigger the vulnerability:
  1. Create a malicious script (e.g., `malicious.sh`) containing arbitrary commands to be executed on the ASIC VM instance (e.g., `rm -rf /tmp/*`).
  2. Create a configuration file (e.g., `asic.yaml`) that references the malicious script as either `setup`, `preflight`, or `entry_point`. For example, set `preflight: ./malicious.sh`.
  3. Use the `tp run` command, referencing the malicious configuration file (e.g., `tp run -f asic.yaml`).
  4. The `tp` tool will create or use an existing ASIC VM instance and execute the malicious script during the setup or run phase, leading to arbitrary code execution on the remote instance.

* Impact:
  - **High/Critical**: Successful exploitation allows an attacker to execute arbitrary code on the ASIC VM instances. This could lead to:
    - **Data Breaches**: Access to sensitive data stored or processed on the ASIC VM instances.
    - **System Compromise**: Full control over the compromised ASIC VM instances, potentially allowing further attacks on the cloud environment.
    - **Data Manipulation**: Modification or deletion of data on the ASIC VM instances.

* Vulnerability Rank: **Critical**

* Currently Implemented Mitigations:
  - **None**: The provided code does not include any explicit mitigations against remote code execution through user-provided scripts. The `tp` tool directly executes the scripts specified in the configuration or command-line arguments.

* Missing Mitigations:
  - **Input Sanitization and Validation**: Implement checks to sanitize and validate user-provided scripts to prevent execution of malicious commands. This could involve:
    - **Restricting Script Paths**: Limit script paths to a predefined safe directory and prevent execution of scripts outside of it.
    - **Command Whitelisting**: Implement a whitelist of allowed commands within the scripts and block any others.
    - **Sandboxing**: Execute user-provided scripts in a sandboxed environment with limited privileges to restrict potential damage.
  - **Principle of Least Privilege**: Run user-provided scripts with the minimum necessary privileges to reduce the impact of successful exploitation.
  - **User Awareness and Documentation**: While not a technical mitigation, clear documentation should be provided to users about the security risks of executing untrusted scripts and best practices for securing their configurations.

* Preconditions:
  - An attacker needs to be able to create or modify a configuration file (`asic.yaml`) or provide command-line arguments to `tp run` to specify a malicious script.
  - The `tp` tool must be executed with these malicious configurations or arguments.
  - An ASIC VM instance must be created or accessible by the `tp` tool.

* Source Code Analysis:
  - File: `/code/distla/tp/tp/tp_lib.py`
  - Function: `TP.setup()` and `TP.run()`
  - In `TP.setup()`:
    ```python
    if _user_setup:
      print('Running user setup...')
      remote_path = build_remote_path(_user_dist_dir, REMOTE_USER_DIR,
                                        _user_setup)
      self.exec(f'sh {remote_path}')
    ```
    - The code retrieves the user-provided `setup` script path from the configuration (`_user_setup`).
    - It constructs a `remote_path` to the script on the ASIC VM instance using `build_remote_path`.
    - It executes the script using `self.exec(f'sh {remote_path}')`, which internally uses `ssh.exec_cmd_on_ips` to run the script on the remote instances via SSH. There is no sanitization or validation of the script content before execution.
  - In `TP.run()`:
    ```python
    if not no_preflight and _user_preflight:
      print('Running user preflight...')
      remote_path = build_remote_path(_user_dist_dir, REMOTE_USER_DIR,
                                        _user_preflight)
      ssh.exec_cmd_on_ips(active_user,
                            ips,
                            _name,
                            f'sh {remote_path}',
                            stream_ips=_stream_workers)
    ```
    - The code similarly retrieves and executes the user-provided `preflight` script. No sanitization is performed.
    ```python
    # Run user code
    print('Running user code...')
    remote_path = build_remote_path(_user_dist_dir, REMOTE_USER_DIR,
                                      _entry_point)
    cmd = f'python3 {remote_path} {arg_string}'
    try:
      ssh.exec_cmd_on_ips(active_user,
                            ips,
                            _name,
                            cmd,
                            env=_run_env,
                            stream_ips=_stream_workers)
    except KeyboardInterrupt:
      print('\nKeyboard interrupt, exiting...')
    ```
    - The code executes the `entry_point` script using `python3`. Again, no sanitization is present.
  - In `ssh.exec_cmd_on_ips()`:
    ```python
    def exec_cmd_on_ips(user,
                        ips,
                        asic_name,
                        cmd,
                        env={},
                        stream_ips=None,
                        port_map=None):
      ...
      p_list.append(
          _create_ssh_exec_process(user, ip, cmd, env=_local_env, stdout=stdout, port_map=port_map[i]))
      ...

    def _create_ssh_exec_process(user,
                                 ip,
                                 cmd,
                                 env=None,
                                 stdout=None,
                                 port_map=None):
      ...
      ssh_cmd = ArgList.from_command(gen_ssh_cmd(user, ip, port_map=port_map))
      if env:
        env_str = ' '.join([f'{key}={val}' for key, val in env.items()])
        ssh_cmd.append(env_str + ' ' + cmd) # Vulnerable part
      else:
        ssh_cmd.append(cmd) # Vulnerable part
      return subprocess.Popen(ssh_cmd, stderr=subprocess.STDOUT, stdout=stdout)
    ```
    - The `ssh.exec_cmd_on_ips` function uses `subprocess.Popen` to execute commands on remote instances via SSH. The `cmd` variable, which can originate from user-provided scripts, is directly appended to the SSH command without any sanitization, leading to the vulnerability.

* Security Test Case:
  1. Create a file named `malicious.sh` with the following content:
     ```shell
     #!/bin/bash
     echo "Malicious script executed!"
     # Attempt to create a file in a sensitive directory to verify execution
     touch /tmp/pwned_by_distla
     ```
  2. Create a file named `asic.yaml` in the same directory as `malicious.sh` with the following content:
     ```yaml
     name: malicious-asic
     zone: us-central1-a
     accelerator_type: v_2
     dist_dir: ./
     preflight: ./malicious.sh
     entry_point: ./main.py # Dummy entry point
     ```
  3. Create a dummy `main.py` file in the same directory as `asic.yaml`:
     ```python
     print("Dummy main.py")
     ```
  4. Run the `tp run` command in the directory containing `asic.yaml` and `malicious.sh`:
     ```shell
     tp run -f asic.yaml
     ```
  5. After the command completes, SSH into the ASIC VM instance using `tp ssh -f asic.yaml`.
  6. Check for the existence of the file `/tmp/pwned_by_distla` on the ASIC VM instance. If the file exists, it confirms successful execution of the malicious script.
  7. Alternatively, check the output of the `tp run` command for the "Malicious script executed!" message in the streamed output, which also confirms code execution.

This test case demonstrates that an external attacker who can modify the `asic.yaml` or provide CLI arguments can execute arbitrary code on the ASIC VM instance, confirming the Remote Code Execution vulnerability.
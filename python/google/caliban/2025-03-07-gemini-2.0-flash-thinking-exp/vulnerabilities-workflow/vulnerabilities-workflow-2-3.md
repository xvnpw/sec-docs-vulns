* Vulnerability Name: Command Injection via Experiment Configuration in `caliban run` and `caliban cloud`

* Description:
    1. An attacker can craft a malicious experiment configuration (e.g., in a JSON file provided via `--experiment_config` or stdin) that includes a command injection payload.
    2. When a user executes `caliban run` or `caliban cloud` with this malicious configuration, Caliban parses the configuration.
    3. During the experiment expansion and execution, if Caliban improperly handles the configuration values, the malicious payload can be injected into commands executed by `docker run` within the container.
    4. This can lead to arbitrary code execution within the Docker container with the privileges of the user running `caliban`.

* Impact:
    * High. Successful command injection allows an attacker to execute arbitrary commands within the Docker container. This could lead to:
        * Data exfiltration: Stealing sensitive data from the experiment environment or mounted volumes.
        * Container breakout: Potentially escaping the Docker container and gaining access to the host system, although less likely in standard Docker configurations.
        * Resource manipulation: Modifying or deleting experiment data, models, or other resources within the container.
        * Denial of service: Disrupting experiments or consuming excessive resources.

* Vulnerability Rank: High

* Currently Implemented Mitigations:
    * None apparent from the provided files. The code lacks input sanitization or command construction methods that prevent command injection in the context of experiment configurations.

* Missing Mitigations:
    * Input sanitization: Implement robust input validation and sanitization for all values read from experiment configurations, especially those used in constructing Docker commands.
    * Secure command construction: Utilize safe methods for constructing Docker commands, such as using parameterization or shell-escaping functions to prevent injection. Avoid directly embedding user-provided strings into shell commands.
    * Least privilege: Ensure the Docker container and Caliban itself run with the minimum privileges necessary to reduce the impact of a successful exploit.

* Preconditions:
    * An attacker needs to be able to provide a malicious experiment configuration to a Caliban user. This could be achieved by:
        * Social engineering: Tricking a user into using a malicious configuration file.
        * Man-in-the-middle attack: Intercepting and modifying an experiment configuration in transit if it's loaded remotely.
        * Supply chain attack: Compromising a source of experiment configurations if users rely on external sources.

* Source Code Analysis:
    1. **`caliban/cli.py`**: This file handles command-line argument parsing. It uses `argparse` to process user inputs. The `script_args` argument with `nargs=REMAINDER` is designed to capture arguments passed to the user's script, but the parsing logic itself doesn't inherently sanitize inputs for shell command safety in the context of Docker execution.
    2. **`caliban/config/experiment.py`**: This file handles experiment configuration loading and expansion. The `expand_experiment_config` function processes dictionaries and lists from JSON or stdin. While `validate_experiment_config` performs type validation, it doesn't include sanitization to prevent command injection. The expanded configurations are then passed as arguments to the user's script, and potentially used by Caliban to construct Docker commands.
    3. **`caliban/platform/run.py`**: This file is responsible for executing local jobs using Docker. The `_run_cmd` function constructs the base `docker run` command. The `run_experiments` function orchestrates the execution of multiple experiments based on the expanded configurations. The crucial part is how these expanded configurations are translated into arguments for the Docker container, and whether any unsanitized values from the experiment configuration are incorporated into commands.
    4. **`caliban/main.py`**: This is the main entry point that calls `run_app`. The `run_app` function dispatches commands and calls the relevant functions in `caliban/platform/run.py` for `caliban run` and `caliban/platform/cloud/core.py` for `caliban cloud`. It passes the parsed arguments, including potentially unsanitized experiment configurations, to these execution functions.

    **Vulnerability Point**: The code lacks explicit sanitization of experiment configuration values before they are used to construct Docker commands, especially within `caliban/platform/run.py` and `caliban/platform/cloud/core.py`.  The assumption is that the values are treated as data, but if they are directly embedded in shell commands without proper escaping, command injection is possible.

* Security Test Case:
    1. Create a malicious experiment configuration file named `malicious_config.json` with the following content:
    ```json
    {
      "learning_rate": [0.01, "0.001; touch /tmp/pwned; #"]
    }
    ```
    This configuration attempts to inject the command `touch /tmp/pwned` into the `caliban run` command. The `#` character is used to comment out any subsequent arguments, which might cause parsing errors.
    2. Execute the following `caliban run` command in a directory where Caliban is installed and configured:
    ```bash
    echo '{"learning_rate": [0.01, "0.001; touch /tmp/pwned; #"]}' | caliban run --experiment_config stdin --nogpu tutorials/basic/mnist.py
    ```
    Alternatively, use the file:
    ```bash
    caliban run --experiment_config malicious_config.json --nogpu tutorials/basic/mnist.py
    ```
    3. After the `caliban run` command completes, check if the file `/tmp/pwned` exists inside the Docker container. You can verify this by running:
    ```bash
    docker run --rm -it $(docker images -q caliban-dev) sh -c "ls /tmp/pwned"
    ```
    (Replace `caliban-dev` with the actual image name if different).
    4. If the file `/tmp/pwned` exists, it confirms that the command injection was successful, and arbitrary code execution within the Docker container is possible.
## Combined Vulnerability List

### Vulnerability Name
Command Injection via Custom MPI Options

### Description
An attacker can inject arbitrary commands by crafting a malicious hyperparameter value for `sagemaker_mpi_custom_mpi_options` or `sagemaker_distributed_dataparallel_custom_mpi_options`. These hyperparameters are designed to allow users to provide custom options to the `mpirun` command used for distributed training with MPI and SMDataParallel. The values of these hyperparameters are directly appended to the `mpirun` command without sufficient sanitization. When the training toolkit constructs the `mpirun` command in `MasterRunner._create_command` (for MPI) or `SMDataParallelRunner._get_mpirun_command` (for SMDataParallel), it includes the user-provided custom MPI options. If a user provides a hyperparameter value containing shell commands (e.g., using backticks, semicolons, or pipes), these commands will be executed by the shell when `mpirun` is invoked. This allows an attacker to achieve arbitrary command execution within the training container by manipulating the training job's hyperparameters.

### Impact
- **High/Critical**: Successful command injection allows an attacker to execute arbitrary commands within the training container.
    - Data exfiltration: Stealing training data, model artifacts, or other sensitive information from the container.
    - Container takeover: Gaining complete control over the training container, potentially allowing further attacks on the SageMaker environment or AWS infrastructure.
    - Denial of service: Disrupting training jobs or consuming resources.
    - Privilege escalation: If the training container has elevated privileges, the attacker might be able to escalate privileges within the container or the host system.

### Vulnerability Rank
Critical

### Currently Implemented Mitigations
- **None**: The project does not implement any sanitization or validation of the `sagemaker_mpi_custom_mpi_options` or `sagemaker_distributed_dataparallel_custom_mpi_options` hyperparameters. The values are directly passed to the `mpirun` command.

### Missing Mitigations
- **Input Sanitization**: The toolkit should sanitize or validate the `sagemaker_mpi_custom_mpi_options` and `sagemaker_distributed_dataparallel_custom_mpi_options` hyperparameters to prevent command injection.
    - Option 1: Whitelist approach: Define a set of allowed MPI options and only permit those options to be passed to `mpirun`.
    - Option 2: Blacklist approach: Sanitize the input to remove or escape potentially dangerous characters or command sequences. However, blacklisting is generally less secure than whitelisting.
    - Option 3: Parameterization: Reconstruct the `mpirun` command using a secure command construction method that separates commands and arguments, avoiding shell interpretation of hyperparameters.

### Preconditions
- **User-provided Training Script**: The user must be using a training script that receives and utilizes hyperparameters passed by the SageMaker Training Toolkit.
- **MPI or SMDataParallel Distributed Training**: The training job must be configured to use MPI or SMDataParallel distributed training, as these are the runners that utilize the vulnerable hyperparameters.
- **Ability to Set Hyperparameters**: The attacker must be able to set hyperparameters for the SageMaker training job, which is a standard functionality in SageMaker.

### Source Code Analysis
- **Vulnerable Code Location 1**: `src/sagemaker_training/mpi.py:MasterRunner._create_command`
    ```python
    def _create_command(self):
        ...
        overridden_known_options, additional_options = _parse_custom_mpi_options(
            self._custom_mpi_options
        )
        ...
        command = [
            "mpirun",
            ...
        ]
        command.extend(additional_options) # Vulnerability: Appending unsanitized custom options
        ...
        command.extend(super(MasterRunner, self)._create_command())
        return command
    ```
    - The `_create_command` function in `MasterRunner` retrieves `self._custom_mpi_options`, which is derived from the `sagemaker_mpi_custom_mpi_options` hyperparameter.
    - It calls `_parse_custom_mpi_options` to parse these options, but this parsing does not sanitize or validate the options for security.
    - `additional_options`, the result of parsing, is directly extended to the `mpirun_command` list. This allows any options provided in the hyperparameter to be passed directly to `mpirun`.

- **Vulnerable Code Location 2**: `src/sagemaker_training/smdataparallel.py:SMDataParallelRunner._get_mpirun_command`
    ```python
    def _get_mpirun_command(
        self,
        num_hosts,
        host_list,
        smdataparallel_flag,
        num_processes,
        smdataparallel_server_addr=None,
        smdataparallel_server_port=None,
    ):
        """Fetch mpi command for SMDataParallel"""
        overridden_known_options, additional_options = _parse_custom_mpi_options(
            self._custom_mpi_options
        ) # Vulnerability: Parsing custom options without sanitization
        ...
        mpirun_command = [
            "mpirun",
            ...
        ]
        mpirun_command.extend(additional_options) # Vulnerability: Appending unsanitized custom options
        ...
        return mpirun_command
    ```
    - Similar to `MasterRunner`, `SMDataParallelRunner._get_mpirun_command` also uses `_parse_custom_mpi_options` to process `self._custom_mpi_options` (derived from `sagemaker_distributed_dataparallel_custom_mpi_options` hyperparameter).
    - The `additional_options` are then directly appended to the `mpirun_command`, creating the same command injection vulnerability.

- **Helper Function**: `src/sagemaker_training/mpi.py:_parse_custom_mpi_options` and `src/sagemaker_training/smdataparallel.py:_parse_custom_mpi_options`
    ```python
    def _parse_custom_mpi_options(custom_mpi_options):
        """Parse custom MPI options provided by user. Known options default value will be overridden
        and unknown options will be identified separately."""

        parser = argparse.ArgumentParser()
        parser.add_argument("--NCCL_DEBUG", default="INFO", type=str) # Example of parsed option

        return parser.parse_known_args(custom_mpi_options.split()) # Vulnerability: Parsing without sanitization
    ```
    - This function uses `argparse.ArgumentParser` to parse the custom MPI options. While `argparse` provides some parsing capabilities, it doesn't inherently sanitize for command injection. The `parse_known_args` method, in particular, is designed to ignore options it doesn't recognize, which could allow malicious options to pass through if they are crafted to be ignored by the parser but interpreted by the shell.

- **Visualization of Vulnerable Code Flow:**

    ```mermaid
    graph LR
        A[Training Job Configuration <br/> (Hyperparameters)] --> B(SageMaker Training Toolkit <br/> (Reads Hyperparameters));
        B --> C{Is MPI or SMDataParallel <br/> Distributed Training?};
        C -- Yes --> D(MasterRunner._create_command <br/> or <br/> SMDataParallelRunner._get_mpirun_command);
        D --> E(Parse Custom MPI Options <br/> (_parse_custom_mpi_options));
        E --> F[Unsanitized Custom MPI Options];
        F --> G(Construct mpirun Command <br/> (Appending Unsanitized Options));
        G --> H(Execute mpirun Command <br/> (Command Injection Vulnerability));
        C -- No --> I[Other Training Flow <br/> (No Command Injection via MPI Options)];
    ```

### Security Test Case
1. **Setup**:
    - Create a SageMaker training job using a custom training container based on a pre-built SageMaker Docker image (e.g., for PyTorch or TensorFlow).
    - Configure the training job to use MPI or SMDataParallel for distributed training (instance count > 1).
    - Set the entry point to a simple training script that will demonstrate command execution.
    - Define a hyperparameter named `sagemaker_mpi_custom_mpi_options` or `sagemaker_distributed_dataparallel_custom_mpi_options` (depending on the chosen distributed training type) with a malicious value.

2. **Malicious Hyperparameter Value**:
    - Set the hyperparameter value to: `"--allow-run-as-root --tag-output --mca btl_tcp_if_include eth0; touch /tmp/pwned ; --verbose"`
    - This value attempts to inject the command `touch /tmp/pwned` within the `mpirun` command. The `--allow-run-as-root`, `--tag-output`, `--mca btl_tcp_if_include eth0`, and `--verbose` options are included to maintain a somewhat valid MPI option structure to bypass basic parsing, while the semicolon `;` is used to separate and inject the malicious `touch` command.

3. **Training Script (e.g., `train.py`):**
    ```python
    import os
    import time
    import argparse

    if __name__ == "__main__":
        parser = argparse.ArgumentParser()
        parser.add_argument("--epochs", type=int, default=1)
        args = parser.parse_args()

        print("Training started.")
        print(f"Epochs: {args.epochs}")

        # Check if the injected file was created
        if os.path.exists("/tmp/pwned"):
            print("VULNERABILITY TEST SUCCESS: /tmp/pwned file created (Command Injection)")
        else:
            print("VULNERABILITY TEST FAILED: /tmp/pwned file NOT created (No Command Injection)")

        print("Training finished.")
    ```
    - This script simply checks for the existence of the `/tmp/pwned` file, which would be created if the command injection is successful.

4. **Execute Training Job**: Launch the SageMaker training job with the configured container, script, and malicious hyperparameter.

5. **Observe Output and Check for Exploitation**:
    - Examine the CloudWatch logs for the training job's output.
    - If the vulnerability is successfully exploited, the logs should contain the "VULNERABILITY TEST SUCCESS: /tmp/pwned file created (Command Injection)" message, indicating that the `touch /tmp/pwned` command was executed within the container.
    - Verify that the `/tmp/pwned` file is indeed created within the container (if possible, e.g., via container access or by modifying the training script to list files).

This test case demonstrates how a malicious hyperparameter can be used to inject and execute arbitrary commands within the SageMaker training container via the custom MPI options, confirming the command injection vulnerability.
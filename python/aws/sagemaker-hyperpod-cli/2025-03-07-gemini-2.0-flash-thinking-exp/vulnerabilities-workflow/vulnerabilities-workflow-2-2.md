- Vulnerability name: Command Injection in `hyperpod exec` command
- Description:
  - An attacker can use the `hyperpod exec` command to execute commands inside a container of a pod associated with a training job.
  - The attacker can inject malicious commands by crafting a payload within the `-- <command>` argument of the `hyperpod exec` command.
  - When the `hyperpod exec` command is processed, the injected commands are executed directly by the system shell within the container's context.
- Impact:
  - Successful command injection allows for unauthorized code execution within the training job's container.
  - This can lead to various malicious activities, including:
    - Data exfiltration from the training environment.
    - Modification or corruption of training data and models.
    - Lateral movement to other containers or resources within the cluster if the compromised container has sufficient permissions.
    - In a severe scenario, if the container runs with elevated privileges (e.g., root user, or with specific capabilities), it could potentially lead to node compromise or broader cluster-level impact.
- Vulnerability rank: High
- Currently implemented mitigations: None (Based on the provided project files, there is no source code available to confirm implemented mitigations. The documentation also lacks any mention of input sanitization or command injection prevention for the `hyperpod exec` command.)
- Missing mitigations:
  - Input sanitization: The `-- <command>` argument should be strictly sanitized to remove or escape any characters that could be interpreted as shell metacharacters.
  - Parameterized execution: Instead of directly executing shell commands constructed from user input, the code should utilize parameterized execution methods to separate commands from arguments.
  - Shell escaping: If shell execution is unavoidable, proper shell escaping must be implemented to ensure that user-provided arguments are treated as data and not as executable commands.
  - Principle of least privilege: Containers should be configured with the minimal necessary privileges to limit the potential damage from command injection vulnerabilities. Security policies and context should be reviewed to restrict container capabilities and user IDs.
- Preconditions:
  - The attacker must have access to the `hyperpod` CLI tool. This assumes the attacker is a user who has installed the CLI, as described in the `README.md` installation instructions.
  - The attacker needs to be authenticated and authorized to interact with the HyperPod cluster, implying they have configured `kubectl` to connect to the cluster.
  - To exploit this vulnerability, the attacker must know the name of a running training job within the HyperPod cluster to target with the `hyperpod exec` command.
  - The `hyperpod exec` command in the CLI tool must be implemented in a way that is vulnerable to command injection, specifically by unsafely processing the `-- <command>` argument. This is assumed based on the initial vulnerability description.
- Source code analysis:
  - As the source code for the `hyperpod` CLI is available in `/code/src` directory, a detailed source code analysis of the actual implementation can be performed.
  - Vulnerable code flow (Python):
    ```python
    # File: /code/src/hyperpod_cli/service/exec_command.py
    from hyperpod_cli.clients.kubernetes_client import KubernetesClient
    from hyperpod_cli.service.list_pods import ListPods

    class ExecCommand:
        # ...
        def exec_command(
            self,
            job_name: str,
            pod_name: Optional[str],
            namespace: Optional[str],
            all_pods: Optional[bool],
            bash_command: tuple, # User provided command
        ):
            # ...
            after_seperator = bash_command[bash_command.index("-") + 1 :]
            bash_command_str: str = " ".join(after_seperator) # VULNERABILITY: Unsafe command construction

            k8s_client = KubernetesClient()
            # ...
            if all_pods:
                # ...
                output += (
                    k8s_client.exec_command_on_pod(
                        pod,
                        namespace,
                        bash_command_str, # VULNERABILITY: Command injection point
                    )
                    + "\n"
                )
                # ...
            else:
                # ...
                return k8s_client.exec_command_on_pod(
                    pod_name,
                    namespace,
                    bash_command_str, # VULNERABILITY: Command injection point
                )

    # File: /code/src/hyperpod_cli/clients/kubernetes_client.py
    from kubernetes import stream
    class KubernetesClient:
        # ...
        def exec_command_on_pod(
            self,
            pod: str,
            namespace: str,
            bash_command: str,
        ):
            return stream.stream( # VULNERABILITY: stream.stream executes command via shell
                client.CoreV1Api().connect_get_namespaced_pod_exec,
                stderr=True,
                stdout=True,
                name=pod,
                namespace=namespace,
                command=bash_command,
            )
    ```
    - In `/code/src/hyperpod_cli/service/exec_command.py`, the `exec_command` function takes user-provided `bash_command` tuple, joins the arguments after separator `-` into `bash_command_str` without any sanitization.
    - This `bash_command_str` is then passed to `k8s_client.exec_command_on_pod` in `/code/src/hyperpod_cli/clients/kubernetes_client.py`.
    - The `exec_command_on_pod` function in `KubernetesClient` directly uses `kubernetes.stream.stream` to execute the command. `stream.stream` in Kubernetes Python client, when used with `client.CoreV1Api().connect_get_namespaced_pod_exec` and `command` parameter, executes the given command using `/bin/sh -c` within the container. This makes the application vulnerable to command injection because the `bash_command_str` is not sanitized and can contain malicious shell commands.
- Security test case:
  1. Set up the environment:
     - Assume you have successfully installed the `hyperpod` CLI tool as described in the `README.md`.
     - Assume you have configured `kubectl` to connect to your HyperPod cluster and have the necessary permissions to execute commands within training job containers.
     - Ensure you have a running training job in your HyperPod cluster. For this test, let's assume a job named `vuln-test-job` is running in the `kubeflow` namespace.
  2. Execute the `hyperpod exec` command with a command injection payload:
     ```bash
     hyperpod exec --job-name vuln-test-job --namespace kubeflow -- -- bash -c 'mkdir /tmp/hyperpod-vuln-test'
     ```
     - This command attempts to inject a command that creates a directory named `hyperpod-vuln-test` in the `/tmp` directory of the container.
  3. Verify successful command injection:
     - To verify if the command injection was successful, you need to access the container of one of the pods associated with the `vuln-test-job`. You can use `kubectl exec` to get a shell inside the container.
     - First, list the pods associated with the job to get a pod name:
       ```bash
       kubectl get pods -n kubeflow -l pytorch-job-name=vuln-test-job
       ```
       - Let's say you get a pod name like `vuln-test-job-worker-0`. Now, execute a command inside the container to check if the directory `/tmp/hyperpod-vuln-test` was created:
       ```bash
       kubectl exec -it -n kubeflow vuln-test-job-worker-0 -- bash
       ```
       - Once inside the container shell, check for the directory:
       ```bash
       ls /tmp/
       ```
       - If you see `hyperpod-vuln-test` in the list, it confirms that the command injection was successful and the `mkdir /tmp/hyperpod-vuln-test` command was executed within the container.
  4. Expected result:
     - If the vulnerability exists, the `hyperpod exec` command should execute the injected command, and the `/tmp/hyperpod-vuln-test` directory should be created in the container. This confirms the command injection vulnerability in the `hyperpod exec` command.
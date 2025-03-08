### Vulnerability List

- Vulnerability Name: **Python Code Injection in Objective Function**
- Description:
  1. An attacker crafts a malicious Python objective function.
  2. The attacker submits this malicious objective function to the Vizier service as part of a study configuration (e.g., in the `evaluate` function within the Python code provided to the Vizier client).
  3. The Vizier service, upon receiving a trial that requires evaluation, executes the user-provided objective function without proper sandboxing or security checks.
  4. The malicious code within the objective function is executed by the Vizier service.
- Impact:
  - **Critical**
  - Remote Code Execution (RCE) on the Vizier server or in the evaluation environment.
  - Full compromise of the Vizier service and potentially the underlying infrastructure.
  - Data exfiltration or manipulation.
  - Unauthorized access to internal resources.
- Vulnerability Rank: **Critical**
- Currently Implemented Mitigations:
  - **None**. The provided code does not include any input validation or sandboxing for user-provided Python code.
- Missing Mitigations:
  - **Input Sanitization and Validation**: While difficult for arbitrary Python code, basic checks could be implemented to detect obvious malicious patterns. However, this is not a sufficient mitigation.
  - **Sandboxing/Isolation**: The most effective mitigation is to execute user-provided objective functions in a sandboxed environment with restricted permissions, preventing access to sensitive resources and system commands. This could involve using containers, VMs, or secure execution environments.
- Preconditions:
  - An attacker needs to be able to submit a study configuration to a publicly accessible Vizier service instance. This is generally the intended use case of the Open Source Vizier, so it's a common precondition.
- Source Code Analysis:
  - The `README.md` file provides an example where the `evaluate` function is defined by the user and directly used in the client code.
  - The client code in `README.md` and `demos/run_vizier_client.py` shows how a user-defined Python function (`evaluate_trial` or `evaluate`) is passed to the Vizier client and intended to be executed.
  - Files like `vizier/service/clients/__init__.py` and `vizier/service/__init__.py` suggest the presence of client-server architecture, implying that the `evaluate` function, if a remote address is provided, will be executed by the Vizier service.
  - The provided code lacks any explicit mechanism to sanitize or restrict the execution of the user-provided objective function within the Vizier service.
- Security Test Case:
  1. Setup a Vizier service instance using `demos/run_vizier_server.py`.
  2. Create a malicious Python objective function (e.g., to execute system command `whoami` and write the output to a file):
     ```python
     import os
     def evaluate(w: float, x: int, y: float, z: str) -> float:
       os.system('whoami > /tmp/vizier_exploit.txt')
       return w**2 - y**2 + x * ord(z)
     ```
  3. Modify the `Getting Started` example in `README.md` or `demos/run_vizier_client.py` to use the malicious `evaluate` function.
  4. Run the modified client code, connecting to the Vizier service instance.
  5. Check the Vizier server's filesystem (e.g., `/tmp` directory) for the existence of the `vizier_exploit.txt` file containing the output of the `whoami` command. If the file exists and contains the expected output, the vulnerability is confirmed.
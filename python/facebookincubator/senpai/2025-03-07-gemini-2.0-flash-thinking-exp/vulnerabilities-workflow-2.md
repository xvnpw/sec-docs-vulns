## Vulnerability: Cgroup Path Traversal due to Insufficient Input Validation

- Description:
  - The Senpai application takes the cgroup path (`cgpath`) as a command-line argument to specify the target cgroup for monitoring and management.
  - This `cgpath` is directly used to construct file paths for accessing cgroup files (e.g., `memory.pressure`, `memory.high`) without sufficient validation or sanitization.
  - An attacker can provide a maliciously crafted `cgpath` containing path traversal sequences (e.g., `../`) or an absolute path to escape the intended cgroup directory and target other cgroups.
  - By manipulating the `cgpath`, an attacker can trick Senpai into interacting with cgroup files of unintended containers or even the host system, depending on the cgroup filesystem configuration and permissions.
  - This allows for unauthorized modification of memory limits and monitoring of unintended cgroups, potentially leading to resource misallocation, instability, or even denial of service for targeted containers.

- Impact:
  - **Unauthorized Modification of Memory Limits:** An attacker can modify the memory limits of arbitrary cgroups on the system. This could lead to:
    - **Resource Starvation:** Reducing memory limits of other containers or system services, causing performance degradation or crashes.
    - **Resource Misallocation:** Senpai might aggressively reduce the memory limit of a critical container, causing performance degradation or instability.
    - **Instability of unintended containers:** Incorrect memory limit adjustments by Senpai can lead to thrashing or out-of-memory errors in unintended containers.
    - **Potential denial of service for unintended containers:** By setting extremely low memory limits, an attacker can effectively cause a denial of service for targeted containers.
  - **Potential Instability of the Host System:** If critical system cgroups are targeted (depending on system configuration and permissions), it might lead to host system instability.
  - **Limited Information Disclosure:** In some scenarios, reading other cgroup files might lead to limited information disclosure about resource usage of other containers.
  - **Privilege Escalation (in certain scenarios):** While not direct privilege escalation to root, manipulating cgroup limits can indirectly impact the resource allocation and behavior of other processes, potentially leading to unexpected or exploitable conditions.
  - **Container Escape (in extreme cases, less likely but theoretically possible depending on cgroupfs misconfiguration):** In highly misconfigured environments where cgroupfs is not properly isolated, it might be theoretically possible to influence host-level cgroups, although this is less common in standard container setups.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
  - None. The application directly uses the user-provided `cgpath` argument without any validation or sanitization.

- Missing Mitigations:
  - **Input Validation and Sanitization:** The application should validate the `cgpath` argument to ensure it is a valid cgroup path and does not contain path traversal sequences.
  - **Path Canonicalization:** Before using the `cgpath`, the application should canonicalize it to resolve symbolic links and remove redundant path components (e.g., `.` and `..`). This can help prevent traversal attempts.
  - **Restrict Path Scope:** The application could be designed to only operate within a predefined base cgroup path and reject any `cgpath` that attempts to go outside of this base path.
  - **Path Validation:** Implement checks to ensure the provided cgroup path is valid and conforms to expected patterns. This could involve verifying that the path starts with `/sys/fs/cgroup/` and does not contain unexpected components.
  - **Principle of Least Privilege:** While not a direct mitigation for path injection, running Senpai with minimal privileges can reduce the potential impact if the vulnerability is exploited.

- Preconditions:
  - The attacker must be able to provide the `cgpath` argument to the Senpai application. This could be achieved if:
    - Senpai is exposed as a service and allows users to specify the cgroup path.
    - Senpai is used by another application that is vulnerable to argument injection and allows controlling the `cgpath` passed to Senpai.
    - The attacker has direct access to the Senpai execution environment and can modify the command-line arguments.
  - The attacker must have the ability to execute the `senpai.py` script. This could be through direct access to the system, or indirectly if the script is exposed through a web interface or other service.
  - The attacker needs to have sufficient permissions to run Senpai and for Senpai to interact with cgroup files.

- Source Code Analysis:
  - **File: `/code/senpai.py`**
  - **Argument Parsing:**
    ```python
    parser = argparse.ArgumentParser(...)
    parser.add_argument('cgpath', type=str)
    conf = parser.parse_args()
    ```
    - The `cgpath` argument is parsed as a string using `argparse` without any validation.
  - **Class `Cgroup` `__init__` method:**
    ```python
    class Cgroup(object):
        def __init__(self, path, limit_min, limit_max):
            self.path = path
            # ... rest of the code
    ```
    - The `__init__` method of the `Cgroup` class takes the `path` argument directly from the `Senpai` class initialization, which in turn gets it from `conf.cgpath` without any checks.
  - **`Cgroup` `read`, `readlines`, `write` methods:**
    ```python
    def read(self, filename):
        with open(os.path.join(self.path, filename)) as f:
            return f.read()

    def readlines(self, filename):
        with open(os.path.join(self.path, filename)) as f:
            return f.readlines()

    def write(self, filename, string):
        with open(os.path.join(self.path, filename), 'w') as f:
        f.write(string)
    ```
    - These methods use `os.path.join(self.path, filename)` to construct the full path to cgroup files.
    - Because `self.path` is directly derived from the user-provided `cgpath` argument, any path traversal sequences in `cgpath` will be preserved and used in `os.path.join`.
  - **Visualization:**
    ```
    User Input (cgpath) --> argparse --> conf.cgpath --> Senpai.__init__ --> Cgroup.__init__(path) --> Cgroup.path
                                                                    |
                                                                    |-- os.path.join(Cgroup.path, filename) --> File Access
    ```
  - **Step-by-step vulnerability trigger:**
    1. The user executes `senpai.py` and provides a malicious `cgpath` argument, for example: `../other_cgroup` or `/sys/fs/cgroup/../../unintended_cgroup`.
    2. The `argparse` module parses the `cgpath` argument and passes it to the `Senpai` class constructor.
    3. The `Senpai` class constructor creates a `Cgroup` object, passing the malicious `cgpath` to the `Cgroup` constructor.
    4. The `Cgroup` constructor initializes `self.path` with the malicious path.
    5. When `Senpai` or `Cgroup` methods call `Cgroup.read`, `Cgroup.readlines`, or `Cgroup.write`, the `os.path.join` function constructs file paths using the malicious `self.path`.
    6. This allows accessing files relative to the attacker-controlled path, potentially outside the intended cgroup.

- Security Test Case:
  - **Pre-requisites:**
    - A Linux system with cgroup v2 mounted (typically at `/sys/fs/cgroup`).
    - Python 3 installed.
    - The `senpai.py` script available.
    - Root or sudo privileges to create cgroups and run Senpai.
    - Create two test cgroups: `test_cgroup_intended` and `test_cgroup_unintended` within the cgroup filesystem using commands like `sudo mkdir /sys/fs/cgroup/test_cgroup_intended` and `sudo mkdir /sys/fs/cgroup/test_cgroup_unintended`.
  - **Steps:**
    1. Open three terminal windows.
    2. **Terminal 1 (Monitor Intended Cgroup):** Monitor the `memory.high` file of the intended cgroup:
       ```bash
       while true; do sudo cat /sys/fs/cgroup/test_cgroup_intended/memory.high; sleep 1; done
       ```
    3. **Terminal 2 (Monitor Unintended Cgroup):** Monitor the `memory.high` file of the unintended cgroup:
       ```bash
       while true; do sudo cat /sys/fs/cgroup/test_cgroup_unintended/memory.high; sleep 1; done
       ```
    4. **Terminal 3 (Run Senpai with Intended Path):** Run `senpai.py` with the intended cgroup path and note the memory adjustments in Terminal 1:
       ```bash
       sudo ./senpai.py /sys/fs/cgroup/test_cgroup_intended
       ```
       Observe in Terminal 1 that the `memory.high` value is being modified by Senpai. Observe in Terminal 2 that `memory.high` value is not being modified.
    5. Stop the Senpai process in Terminal 3 (e.g., Ctrl+C).
    6. **Terminal 3 (Run Senpai with Malicious Path):** Run `senpai.py` with a malicious cgroup path targeting the unintended cgroup:
       ```bash
       sudo ./senpai.py /sys/fs/cgroup/../test_cgroup_unintended
       ```
    7. Observe in Terminal 2 that the `memory.high` value is now being modified by Senpai. Observe in Terminal 1 that `memory.high` value is no longer being modified.
  - **Expected Result:**
    - When Senpai is run with the intended path `/sys/fs/cgroup/test_cgroup_intended`, only the `memory.high` file of `test_cgroup_intended` is modified.
    - When Senpai is run with the malicious path `/sys/fs/cgroup/../test_cgroup_unintended`, the `memory.high` file of `test_cgroup_unintended` is modified instead of the intended cgroup, demonstrating successful cgroup path injection and traversal.

This vulnerability allows an attacker to break out of the intended cgroup context and manipulate memory limits of other cgroups by supplying a malicious `cgpath`.
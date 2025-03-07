#### 1. Vulnerability Name: Supply Chain Compromise via Malicious Code Injection in Wheels

- **Description:**
    An attacker could potentially compromise the `securedrop-builder` scripts (such as `build-sync-wheels` or `update-requirements`) or the dependencies used during the build process. By doing so, they could inject malicious code into the generated Python wheels for SecureDrop Workstation components. This could occur if a developer is socially engineered into using a compromised version of `securedrop-builder`.

    **Step-by-step trigger:**
    1. An attacker compromises the `securedrop-builder` repository or gains access to a developer's environment where `securedrop-builder` is used.
    2. The attacker modifies one of the critical scripts, for example, `scripts/build-sync-wheels`, to include malicious code injection logic. This logic could be designed to append malicious code to Python files within the generated wheels during the build process.
    3. A developer, unaware of the compromise, uses the infected `securedrop-builder` to build Python wheels for SecureDrop Workstation components, following the standard procedures outlined in the README.
    4. The `build-sync-wheels` script, now containing the attacker's malicious code, executes and generates Python wheels that are backdoored.
    5. These compromised wheels are then potentially used to build and deploy SecureDrop Workstation components, thus infecting the SecureDrop ecosystem.

- **Impact:**
    Successful exploitation of this vulnerability could lead to a critical compromise of SecureDrop Workstation components. Backdoored wheels could allow the attacker to:
    - Gain unauthorized access to sensitive data handled by SecureDrop Workstation.
    - Execute arbitrary code on systems running SecureDrop Workstation.
    - Disrupt the normal operation of SecureDrop Workstation.
    - Potentially compromise the confidentiality, integrity, and availability of the entire SecureDrop system.

- **Vulnerability Rank:** Critical

- **Currently Implemented Mitigations:**
    - **Verification of sha256sums for dependencies:** The `securedrop-builder` uses sha256 sums to verify the integrity of downloaded dependencies, as indicated in the README and tested in `tests/test_update_requirements.py`. This helps ensure that fetched dependencies from PyPI are not tampered with during download.
    - **Signing of `sha256sums.txt`:** The `sha256sums.txt` file, which lists the sha256 sums of the wheels, is signed using GPG. This is mentioned in the README and aims to provide a way to verify the integrity of the checksum list itself.
    - **Reproducible builds:** The project aims to create reproducible builds, which in theory makes it easier to detect unintended changes in the build outputs. The tests in `tests/test_reproducible_wheels.py` check for unexpected changes in the git repository after building wheels, indicating a focus on build reproducibility.
    - **Code review and CI:** The project uses GitHub and CircleCI, implying that code changes are subject to review and are tested in a CI environment. This process can help in catching unintentional or malicious changes to the codebase.

- **Missing Mitigations:**
    - **Integrity checks for `securedrop-builder` scripts:** There are no explicit mechanisms in place to verify the integrity of the `securedrop-builder` scripts themselves before execution. An attacker compromising the scripts directly could bypass the dependency integrity checks.
    - **Stronger verification of the build environment:** The security of the environment where `securedrop-builder` is executed is not explicitly addressed. If the build environment is compromised, the entire build process becomes vulnerable.
    - **Supply chain security best practices:** Implementing more robust supply chain security measures, such as using a trusted build service, dependency scanning, and software bill of materials (SBOM), could further reduce the risk.
    - **Limited scope of reproducibility tests:** While tests check for git diffs after wheel building, they might not detect subtle code injections within the wheels if the changes don't result in file modifications tracked by git or if the changes are cleverly concealed.

- **Preconditions:**
    - The attacker needs to compromise either:
        - The `securedrop-builder` repository (e.g., via compromised developer account, vulnerability in GitHub).
        - A developer's local environment where `securedrop-builder` is used (e.g., via malware, social engineering).
    - A developer must then use the compromised `securedrop-builder` to build wheels for SecureDrop Workstation components.

- **Source Code Analysis:**
    - **`scripts/build-sync-wheels`:** This script is central to the wheel building process. If an attacker modifies this script, they can inject arbitrary code during the wheel creation. For example, they could modify the script to append malicious Python code to the `__init__.py` file of any package being built. The script does not have any built-in integrity checks for itself.
    - **`scripts/update-requirements`:** This script manages the `build-requirements.txt` file. While it verifies sha256 sums of dependencies, it does not verify the integrity of the scripts involved in updating these requirements. A compromised `update-requirements` script could be used to introduce malicious dependencies or manipulate the requirements in a way that facilitates code injection.
    - **`scripts/utils.py`:** This utility script is used by other scripts. If compromised, it could affect the behavior of multiple scripts, potentially creating vulnerabilities across the build process. For instance, if `get_poetry_hashes` or `get_requirements_hashes` is modified to return incorrect hashes, dependency verification could be bypassed.
    - **Test Limitations:** The existing tests in `tests/` primarily focus on functional correctness (e.g., ensuring sha256 sum verification works, builds are reproducible in terms of git diffs). They do not include specific tests to detect or prevent malicious code injection into the build process or the scripts themselves. The reproducibility tests in `test_reproducible_wheels.py` only check for git diffs, which may not catch all forms of malicious injection, especially if the attacker is careful to avoid changing tracked files or introduces subtle modifications within the wheel building process itself.

- **Security Test Case:**
    1. **Set up a test environment:** Clone the `securedrop-builder` repository to a local machine.
    2. **Modify `build-sync-wheels` script for malicious injection:**
        - Open the `scripts/build-sync-wheels` file.
        - Add the following lines at the end of the `build_wheels_for_project` function, just before the `return` statement. This code will inject a simple backdoor into the `__init__.py` file of the first package being built.
        ```python
        import os
        import glob

        wheel_dir = Path(pkg_dir) / "wheels"
        init_files = glob.glob(str(wheel_dir / "**/*/__init__.py"), recursive=True)
        if init_files:
            target_init_file = init_files[0] # Just target the first package for simplicity
            with open(target_init_file, "a") as f:
                f.write("\n# Malicious code injected by compromised build script\n")
                f.write("def backdoor():\n")
                f.write("    import os\n")
                f.write("    os.system('touch /tmp/backdoor_activated')\n") # Simulate malicious activity
                f.write("backdoor()\n")
        ```
    3. **Run `build-sync-wheels`:** Execute the `build-sync-wheels` script for the `workstation-bootstrap` project:
        ```bash
        ./scripts/build-sync-wheels --pkg-dir ./workstation-bootstrap --project workstation-bootstrap --clobber
        ```
    4. **Inspect the generated wheels:**
        - Navigate to the `workstation-bootstrap/wheels` directory.
        - Extract the first generated wheel file (e.g., using `unzip <wheel_file>.whl -d extracted_wheel`).
        - Inspect the `__init__.py` file within the extracted wheel's directory structure (e.g., `extracted_wheel/<package_name>/__init__.py`).
        - Verify that the malicious code (lines starting with `# Malicious code injected...` and `def backdoor()...`) is present at the end of the `__init__.py` file.
    5. **Check for side effect (backdoor activation):**
        - Check if the file `/tmp/backdoor_activated` exists. If it does, the backdoor code was executed when the compromised wheel was installed (simulating a real-world scenario where the wheel is installed as part of SecureDrop Workstation).

    If the malicious code is found in the `__init__.py` file and `/tmp/backdoor_activated` exists, it confirms that an attacker can inject malicious code into the generated wheels by compromising the `build-sync-wheels` script, demonstrating the supply chain vulnerability.
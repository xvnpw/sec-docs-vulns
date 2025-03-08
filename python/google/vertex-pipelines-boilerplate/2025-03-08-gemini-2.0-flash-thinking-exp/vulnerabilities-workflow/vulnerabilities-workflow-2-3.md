- **Vulnerability Name:** Lack of Input Validation for Pipeline Parameters

- **Description:**
    1. The `pipelines-cli run` command accepts pipeline parameters via the `-p` flag.
    2. The `_parse_pipeline_args` function in `src/pipelines/console.py` parses these parameters by splitting each parameter string at the `=` character and storing them in a dictionary.
    3. There is no input validation or sanitization performed on the parameter keys or values in `_parse_pipeline_args` or anywhere else in the boilerplate code before these parameters are passed to the Vertex AI Pipelines service.
    4. While the boilerplate code itself doesn't directly use these parameters in a way that causes immediate harm, it provides a mechanism for users to pass arbitrary string parameters to their Kubeflow pipelines.
    5. If a user develops a Kubeflow pipeline that unsafely uses these parameters (e.g., by directly incorporating them into commands executed within pipeline components, or by constructing file paths without proper validation), it could lead to vulnerabilities within the pipeline execution in Vertex AI Pipelines.
    6. An attacker could leverage this by injecting malicious parameters through the `-p` flag when running the pipeline.

- **Impact:**
    The impact of this vulnerability depends entirely on how the user-developed Kubeflow pipelines handle the parameters passed through the `-p` flags. If the pipeline code is not written securely and doesn't validate or sanitize these inputs, potential impacts could include:
    - **Data manipulation or unauthorized access:** If parameters are used to construct file paths or database queries without validation, attackers could potentially read or write sensitive data or access unauthorized resources within the pipeline's execution environment.
    - **Code execution within pipeline components:** If pipeline parameters are directly used in shell commands or Python `eval()`-like functions within pipeline components without sanitization, attackers could potentially inject and execute arbitrary code within the pipeline's execution context.
    - **Unexpected pipeline behavior:** By injecting unexpected or malicious parameters, attackers could disrupt the intended logic of the pipeline, leading to incorrect results or pipeline failures.

- **Vulnerability Rank:** Medium

- **Currently Implemented Mitigations:**
    - None. The boilerplate code does not implement any input validation or sanitization for pipeline parameters.

- **Missing Mitigations:**
    - **Input Validation in `_parse_pipeline_args`:** The `_parse_pipeline_args` function in `src/pipelines/console.py` should be enhanced to include validation and sanitization of parameter keys and values. This could include:
        - Defining allowed parameter names and types.
        - Implementing checks to ensure parameter values conform to expected formats (e.g., alphanumeric, specific length, regex patterns).
        - Sanitizing parameter values to prevent injection attacks (e.g., escaping special characters).
    - **Guidance in Documentation:** The documentation should explicitly warn users about the security risks of directly using pipeline parameters without proper validation and sanitization within their Kubeflow pipeline code. It should provide best practices and examples of how to securely handle user-provided parameters in pipelines.

- **Preconditions:**
    1. The attacker must have the ability to execute the `pipelines-cli run` command, which typically means they need to have access to the environment where the CLI is installed.
    2. A Kubeflow pipeline must be deployed and configured to accept parameters that are intended to be passed via the `-p` flag.
    3. The Kubeflow pipeline code developed by the user must be vulnerable to parameter injection due to a lack of input validation and sanitization.

- **Source Code Analysis:**
    1. **`src/pipelines/console.py` - `_parse_pipeline_args` function:**
    ```python
    def _parse_pipeline_args(pipeline_args: Dict[str, Any]) -> Dict[str, Any]:
        """Parses pipeline keyword arguments."""
        args = pipeline_args["param"]
        params = dict([p.split("=") for p in args]) # Vulnerable line: No input validation
        return params
    ```
    - This function directly splits the input parameter strings by `=` without any validation. It assumes the input is always in the format `key=value`.
    2. **`src/pipelines/console.py` - `run` command:**
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
        pipeline_params = _parse_pipeline_args(pipeline_args) # Calls vulnerable function
        run_config = pipeline_runner.PipelineRunConfig.from_file(run_config_file)
        pipeline_runner.run(run_config, pipeline_params) # Passes unsanitized parameters
    ```
    - The `run` command utilizes `_parse_pipeline_args` to process the `-p` parameters and then passes these directly to `pipeline_runner.run`.
    3. **`src/pipelines/pipeline_runner.py` - `run` function:**
    ```python
    def run(
        run_config: PipelineRunConfig,
        pipeline_params: Dict[str, Any],
    ) -> str:
        """Runs a Kubeflow pipeline given by specification file.
        ...
        """
        ...
        vertex.PipelineJob(
            ...
            parameter_values=pipeline_params, # Unsanitized parameters passed to Vertex AI
            ...
        ).run(
            ...
        )
        return job_id
    ```
    - The `run` function in `pipeline_runner.py` directly passes the `pipeline_params` dictionary (which contains the unsanitized parameters) as the `parameter_values` argument to the `vertex.PipelineJob` constructor. Vertex AI Pipelines will then use these parameters during pipeline execution.

- **Security Test Case:**
    1. **Prerequisites:**
        - Deploy the sample pipeline or a similar pipeline that accepts parameters and performs an action based on them (e.g., writing to a GCS file path derived from a parameter).
        - Ensure the `pipelines-cli` is installed and configured to run pipelines in a test GCP project.
        - Create a `pipeline-run-config.yaml` file configured for the test environment.
    2. **Scenario:** Attempt to inject a malicious parameter to manipulate the pipeline behavior. In this example, try to inject a parameter that could potentially overwrite a different file in GCS than intended by manipulating the `gcs_filepath` parameter in the `sample_pipeline`.
    3. **Steps:**
        - **Compile the sample pipeline:**
          ```bash
          pipelines-cli compile sample_pipeline pipeline gs://<your-gcs-bucket>/test-pipeline.json
          ```
        - **Run the pipeline with a malicious `-p` parameter:**
          ```bash
          pipelines-cli run pipeline-run-config.yaml \
              -p "message=Malicious Message" \
              -p "gcs_filepath=gs://<your-gcs-bucket>/../../../malicious-output.txt" # Attempting path traversal
          ```
          **Note:** Replace `<your-gcs-bucket>` with your actual GCS bucket. The path traversal attempt `../../../malicious-output.txt` is a simplified example. A more sophisticated attack might involve injecting commands or exploiting vulnerabilities within the pipeline components themselves, depending on the pipeline's logic.
    4. **Expected Outcome (Vulnerable Case):**
        - If the pipeline code directly uses the `gcs_filepath` parameter to construct file paths without validation, the pipeline might attempt to write to the path specified with path traversal (`gs://<your-gcs-bucket>/../../../malicious-output.txt`). While GCS path traversal is inherently limited in the same way local filesystem traversal is, depending on the pipeline's logic and permissions, unintended file operations might occur or errors could be triggered.
        - More importantly, if the pipeline was designed to perform actions based on the *content* of the `message` parameter without sanitization, a malicious message could potentially exploit vulnerabilities within the pipeline's components.
    5. **Expected Outcome (Mitigated Case):**
        - If input validation is implemented in `_parse_pipeline_args` to restrict allowed parameter values or sanitize them, the `pipelines-cli` might reject the malicious parameter input, or the pipeline, if properly coded with input validation, would handle the parameter safely, preventing unintended actions.

This vulnerability highlights the importance of input validation, not just in the boilerplate code, but especially in the user-developed Kubeflow pipelines that utilize parameters passed through the CLI. The boilerplate provides the mechanism for parameter passing, and the responsibility for secure parameter handling falls on the pipeline developer.
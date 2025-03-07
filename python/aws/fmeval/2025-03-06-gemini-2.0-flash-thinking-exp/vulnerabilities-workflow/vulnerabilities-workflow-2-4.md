- Vulnerability Name: Arbitrary Local File Read via Dataset URI
- Description:
    1. An attacker crafts a malicious `DataConfig` object.
    2. In this `DataConfig`, the `dataset_uri` parameter is set to point to a sensitive local file on the server's filesystem, such as `/etc/passwd` or any other file the user running `fmeval` has read access to (e.g., `file:///etc/passwd`).
    3. The attacker then initiates an evaluation using `fmeval` and provides this maliciously crafted `DataConfig` to be used as a custom dataset.
    4. When `fmeval` attempts to load the dataset, it processes the provided `dataset_uri` without sufficient validation.
    5. The `LocalDataFile` class opens and reads the file specified by the attacker's URI, effectively performing an arbitrary local file read.
    6. While the content of the file is intended to be used for evaluation and might not be directly returned to the attacker, it could be logged, saved to disk in evaluation results, or processed in a way that leaks sensitive information or causes unintended behavior due to processing unexpected file content.
- Impact:
    An attacker can read arbitrary local files from the system where `fmeval` is running. This could lead to the disclosure of sensitive information, including configuration files, private keys, or other confidential data, depending on the permissions of the user running `fmeval` and the file system structure.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    No specific mitigations are implemented in the provided code to prevent arbitrary local file reads via `dataset_uri`. The `LocalDataFile` class in `/code/src/fmeval/data_loaders/data_sources.py` directly opens the file path provided in the `dataset_uri` without any checks to restrict access to specific directories or validate the safety of the path.
- Missing Mitigations:
    - Input validation for `dataset_uri` in `DataConfig` to restrict allowed URI schemes and paths. Only `s3://` and safe local paths should be permitted. `file://` scheme should be disallowed or heavily restricted.
    - Input sanitization or path canonicalization to prevent path traversal attacks in local file paths.
    - Principle of least privilege should be applied to the user account running `fmeval` to limit the impact of potential file read vulnerabilities.
- Preconditions:
    - The attacker must be able to provide a custom `DataConfig` object to `fmeval`, which is possible as the library is designed to allow users to evaluate models on custom datasets.
    - The user running `fmeval` must have read access to the local files the attacker is trying to access.
- Source Code Analysis:
    - File: `/code/src/fmeval/data_loaders/data_sources.py`
        ```python
        class LocalDataFile(DataFile):
            """
            Datafile class for local files
            """

            def __init__(self, file_path: str):
                super().__init__(file_path)

            def open(self, mode="r") -> IO:
                try:
                    return open(self.uri, mode) # Vulnerability: Directly opens user-provided file_path
                except Exception as e:
                    raise EvalAlgorithmClientError(
                        f"Unable to open '{self.uri}'. Please make sure the local file path is valid."
                    ) from e
        ```
    - File: `/code/src/fmeval/data_loaders/util.py`
        ```python
        def get_data_source(dataset_uri: str) -> DataSource:
            """
            Validates a dataset URI and returns the corresponding DataSource object
            :param dataset_uri: local dataset path or s3 dataset uri
            :return: DataSource object
            """
            if _is_valid_local_path(dataset_uri): # Checks if path exists, but not if it's safe
                return _get_local_data_source(dataset_uri)
            elif _is_valid_s3_uri(dataset_uri):
                return _get_s3_data_source(dataset_uri)
            else:
                raise EvalAlgorithmClientError(f"Invalid dataset path: {dataset_uri}")


        def _get_local_data_source(dataset_uri) -> LocalDataFile:
            """
            :param dataset_uri: local dataset path
            :return: LocalDataFile object with dataset uri
            """
            absolute_local_path = os.path.abspath(urllib.parse.urlparse(dataset_uri).path) # Converts to absolute path, but no further checks
            if os.path.isfile(absolute_local_path): # Checks if it is a file, but not if it is safe
                return LocalDataFile(absolute_local_path)
            if os.path.isdir(absolute_local_path):
                # TODO: extend support to directories
                raise EvalAlgorithmClientError("Please provide a local file path instead of a directory path.")
            raise EvalAlgorithmClientError(f"Invalid local path: {dataset_uri}")

        def _is_valid_local_path(path: str) -> bool:
            """
            :param path: local file path
            :return: True if path is a valid local path, False otherwise
            """
            parsed_url = urllib.parse.urlparse(path)
            return parsed_url.scheme in ["", "file"] and os.path.exists(parsed_url.path) # Checks if path exists, but not if it is safe
        ```

- Security Test Case:
    1. Create a malicious DataConfig in Python:
        ```python
        from fmeval.data_loaders import DataConfig
        from fmeval.eval_algorithms import Toxicity, ToxicityConfig
        from fmeval.model_runners import DummyModelRunner

        config = DataConfig(
            dataset_name="malicious_dataset",
            dataset_uri="file:///etc/passwd",  # Malicious dataset URI pointing to /etc/passwd
            dataset_mime_type="application/jsonlines", # Mime type doesn't matter for this vulnerability
            model_input_location="prompt", # Dummy location
        )
        toxicity_eval = Toxicity(ToxicityConfig()) # Choose any eval algo
        model_runner = DummyModelRunner() # Use dummy model runner, actual model invocation is not needed for this vulnerability

        # Trigger the vulnerability by running evaluate with the malicious config
        eval_output = toxicity_eval.evaluate(model=model_runner, dataset_config=config)

        # The content of /etc/passwd` might be saved in eval_output.output_path if saving is enabled or logged during processing.
        print(f"Check eval output at: {eval_output[0].output_path}")
        ```
    2. Run the above Python script with `fmeval`.
    3. After the script execution, check the evaluation output directory (printed in the script output). If saving is enabled, the content of `/etc/passwd` or an error message indicating attempt to read it will be in the evaluation output file (`<eval_name>_<dataset_name>.jsonl`) or logs. If saving is not enabled, check the logs for potential file content leakage if the code logs dataset content during processing.

Vulnerability Rank: High
This vulnerability allows arbitrary local file read, which is a serious security concern. An attacker could potentially gain access to sensitive system files.
- Vulnerability Name: Path Traversal via Input File Paths

- Description:
    1. The CHALET application accepts input file paths via command-line arguments `-i` or `--inputs`.
    2. The `main()` function in `src/cli/main.py` retrieves these input paths and assigns them to the `INPUT_PATH` variable.
    3. The `Executor` class is initialized with `INPUT_PATH` and `OUTPUT_PATH`.
    4. The `get_all_inputs()` function in `src/data_io/input_handler.py` is called with the `INPUT_PATH`.
    5. Inside `get_all_inputs()`, the `load_files()` function is called, which iterates through `files_to_load` (defined as `[Node, Arc, OdPair]`).
    6. For each file type, `_get_file()` is called, which constructs the full file path using `os.path.join(path, file.get_file_name() + ".csv")`, where `path` is the user-provided `INPUT_PATH`.
    7. The constructed file path is directly used in `pd.read_csv()` to load the CSV data.
    8. If a malicious user provides a crafted input path like `../../../../malicious_data`, the `os.path.join()` and `pd.read_csv()` will resolve this path, potentially leading to reading files outside the intended input directory.

- Impact:
    - High
    - An attacker can read arbitrary files from the server's file system by crafting malicious input CSV file paths.
    - This can lead to disclosure of sensitive information, including application code, configuration files, or data stored on the server.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    - None. The code directly uses user-provided input paths without any sanitization or validation.

- Missing Mitigations:
    - Input path sanitization: Implement input validation to ensure that the provided input path is a valid directory and does not contain path traversal sequences like `../` or absolute paths.
    - Path validation: Validate that the resolved file paths after joining with input path still reside within the intended input directory.
    - Use secure file path handling functions: Employ functions that prevent path traversal, or restrict file access to a specific directory.

- Preconditions:
    - The application must be running and accessible to an attacker.
    - The attacker needs to be able to provide input to the application, specifically through the `-i` or `--inputs` command-line arguments when executing `chalet`.

- Source Code Analysis:
    - `src/cli/main.py`:
        ```python
        parser = argparse.ArgumentParser(description="Charging Location Tool execution engine")
        parser.add_argument("-i", "--inputs", help="inputs folder")
        parser.add_argument("-o", "--outputs", help="outputs folder")
        args, unknown = parser.parse_known_args()

        INPUT_PATH = args.inputs or "data/"
        OUTPUT_PATH = args.outputs or "output/"
        ```
        - This code snippet shows that `INPUT_PATH` is directly assigned from user input `args.inputs` without any sanitization.

    - `src/data_io/input_handler.py`:
        ```python
        def _get_file(path: str, file: BaseCsvFile) -> pd.DataFrame:
            """Load a csv file from given path and perform schema validations."""
            csv_filepath = os.path.join(path, file.get_file_name() + ".csv")

            # Read in chunks to support large csv files, e.g., arcs.csv can have thousands of rows
            chunks = pd.read_csv(csv_filepath, chunksize=chunk_size)
            data = pd.concat(chunks)
            validated_data = file.get_schema().validate(data)
            return validated_data
        ```
        - `os.path.join(path, file.get_file_name() + ".csv")` constructs the file path by directly joining the user-provided `path` with the filename, making it vulnerable to path traversal if `path` is malicious.
        - `pd.read_csv(csv_filepath, chunksize=chunk_size)` then uses this potentially malicious path to read the CSV file.

- Security Test Case:
    1. Prepare a malicious input path: `../../../../tmp`
    2. Create a dummy `parameters.json`, `od_pairs.csv`, `nodes.csv` in a temporary `input_data` directory.
    3. Create a symbolic link named `arcs.csv` inside the `input_data` directory, pointing to a sensitive file on the system, e.g., `/etc/passwd` on Linux or `C:\Windows\win.ini` on Windows.
        ```bash
        mkdir input_data
        echo '{"dev_factor": 2}' > input_data/parameters.json
        echo "ORIGIN_ID,DESTINATION_ID" > input_data/od_pairs.csv
        echo "ID,TYPE,COST" > input_data/nodes.csv
        ln -s /etc/passwd input_data/arcs.csv # Linux
        # mklink arcs.csv C:\Windows\win.ini # Windows (in input_data directory)
        ```
    4. Run the `chalet` application, providing the malicious input path:
        ```bash
        chalet -i input_data
        ```
    5. Check the output logs or output files in the `output/` directory. If the vulnerability is present, the application might attempt to parse the content of `/etc/passwd` or `C:\Windows\win.ini` as a CSV file, potentially causing errors or revealing parts of the sensitive file in the logs or output.
    6. For stronger evidence, modify the `_get_file` function temporarily to just read and print the file content instead of parsing it as CSV if a path traversal is suspected. This would directly display the content of the targeted sensitive file, clearly demonstrating the vulnerability.
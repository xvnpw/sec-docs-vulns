## Combined Vulnerability List

### Vulnerability Name: Path Traversal via Input File Paths

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

### Vulnerability Name: CSV Injection in Arc File Processing

- Description:
    1. The application reads arc data from `arcs.csv` using pandas `read_csv` function in `chalet/data_io/input_handler.py`.
    2. The `arcs.csv` file defines network arcs with attributes like `HEAD_ID`, `TAIL_ID`, `TIME`, and `DISTANCE`.
    3. If an attacker can control the content of `arcs.csv`, they can inject malicious formulas into fields read by pandas, such as the `TIME` or `DISTANCE` columns.
    4. When pandas processes this CSV, it may execute these injected formulas if formula evaluation is enabled, leading to arbitrary code execution.
- Impact: Arbitrary code execution. An attacker can execute arbitrary commands on the system running the CHALET application.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations:
    - None. The code does not sanitize or validate CSV inputs for formula injection.
- Missing Mitigations:
    - Disable formula evaluation in pandas `read_csv` by setting `engine='python'` and `sep=','`, or using `pandas.read_csv(..., engine='python', quoting=csv.QUOTE_NONE, escapechar='\\')`.
    - Implement robust input validation and sanitization for all CSV and JSON input fields to ensure they conform to expected formats and do not contain executable code or malicious content.
- Preconditions:
    - The attacker must be able to modify or provide a malicious `arcs.csv` file to the CHALET application. This could be achieved through various means depending on how the application is deployed and used (e.g., if the application processes user-provided input files).
- Source Code Analysis:
    - File: `/code/src/chalet/data_io/input_handler.py`
    ```python
    def _get_file(path: str, file: BaseCsvFile) -> pd.DataFrame:
        """Load a csv file from given path and perform schema validations."""
        csv_filepath = os.path.join(path, file.get_file_name() + ".csv")

        # Read in chunks to support large csv files, e.g., arcs.csv can have thousands of rows
        chunks = pd.read_csv(csv_filepath, chunksize=chunk_size) # Vulnerable line
        data = pd.concat(chunks)
        validated_data = file.get_schema().validate(data)
        return validated_data
    ```
    - The `pd.read_csv` function is used to parse the CSV file without specifying any parameters to disable formula execution. This default behavior of pandas makes the application vulnerable to CSV injection.
- Security Test Case:
    1. Prepare a malicious `arcs.csv` file with the following content, injecting a formula into the `TIME` column:
    ```csv
    HEAD_ID,TAIL_ID,TIME,DISTANCE
    1,2,=SYSTEM("calc")*10,10
    2,3,20,20
    ```
    2. Save this file as `arcs.csv` in the `data/` input directory expected by the application, or provide the path to this malicious file using the `-i` command line argument.
    3. Run the CHALET application using the command `chalet`.
    4. Observe if the calculator application (`calc.exe` on Windows, `calc` on Linux/macOS) is launched. If it is, this confirms arbitrary code execution via CSV injection.
    5. Examine the application logs in the `output/` directory for any error messages or unusual activity that might indicate the formula injection was processed.

### Vulnerability Name: CSV Injection in Nodes File Processing

- Description:
    1. Similar to the Arc file, the application also reads node data from `nodes.csv` using pandas `read_csv` in `chalet/data_io/input_handler.py`.
    2. The `nodes.csv` file defines network nodes with attributes like `ID`, `TYPE`, `COST`, `LATITUDE`, `LONGITUDE`, and `NAME`.
    3. An attacker can inject malicious formulas into columns like `COST`, `LATITUDE`, `LONGITUDE`, or `NAME` in `nodes.csv`.
    4. When pandas parses `nodes.csv`, it may execute these injected formulas, leading to arbitrary code execution.
- Impact: Arbitrary code execution, similar to CSV Injection in Arc File Processing.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations:
    - None. The code does not sanitize or validate CSV inputs for formula injection.
- Missing Mitigations:
    - Same as CSV Injection in Arc File Processing: Disable formula evaluation in pandas and implement robust input validation and sanitization.
- Preconditions:
    - The attacker must be able to modify or provide a malicious `nodes.csv` file to the CHALET application.
- Source Code Analysis:
    - Same vulnerable code is used as in CSV Injection in Arc File Processing in `/code/src/chalet/data_io/input_handler.py`.
- Security Test Case:
    1. Prepare a malicious `nodes.csv` file with the following content, injecting a formula into the `COST` column:
    ```csv
    ID,TYPE,COST,LATITUDE,LONGITUDE,NAME
    1,SITE,=SYSTEM("calc")*10,10.0,20.0,Node1
    2,STATION,1.0,30.0,40.0,Node2
    ```
    2. Save this file as `nodes.csv` in the `data/` input directory or provide the path using `-i`.
    3. Run the CHALET application using the command `chalet`.
    4. Observe if the calculator application is launched, indicating arbitrary code execution.
    5. Check the application logs for any error messages related to formula injection.

### Vulnerability Name: CSV Injection in OD Pairs File Processing

- Description:
    1. The application reads origin-destination pair data from `od_pairs.csv` using pandas `read_csv` in `chalet/data_io/input_handler.py`.
    2. The `od_pairs.csv` file defines OD pairs with attributes like `ORIGIN_ID`, `DESTINATION_ID`, and `DEMAND`.
    3. An attacker can inject malicious formulas into columns like `DEMAND` in `od_pairs.csv`.
    4. When pandas processes `od_pairs.csv`, it may execute these injected formulas, leading to arbitrary code execution.
- Impact: Arbitrary code execution, similar to CSV Injection in Arc and Node File Processing.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations:
    - None. The code does not sanitize or validate CSV inputs for formula injection.
- Missing Mitigations:
    - Same as CSV Injection in Arc File Processing: Disable formula evaluation in pandas and implement robust input validation and sanitization.
- Preconditions:
    - The attacker must be able to modify or provide a malicious `od_pairs.csv` file to the CHALET application.
- Source Code Analysis:
    - Same vulnerable code is used as in CSV Injection in Arc File Processing in `/code/src/chalet/data_io/input_handler.py`.
- Security Test Case:
    1. Prepare a malicious `od_pairs.csv` file with the following content, injecting a formula into the `DEMAND` column:
    ```csv
    ORIGIN_ID,DESTINATION_ID,DEMAND
    1,2,=SYSTEM("calc")*10
    2,3,20.0
    ```
    2. Save this file as `od_pairs.csv` in the `data/` input directory or provide the path using `-i`.
    3. Run the CHALET application using the command `chalet`.
    4. Observe if the calculator application is launched, indicating arbitrary code execution.
    5. Check the application logs for any error messages related to formula injection.
## Combined Vulnerability List

### Code Injection via `eval()` in Benchmark File Parsing

- Description:
    1. The `reconstruct.py` script reads files from the `remapped_benchmarks` directory, which are expected to contain Python lists representing index-offset pairs for benchmark reconstruction.
    2. For each benchmark file, the script uses the `eval()` function to parse the file's content into a Python list named `index_offset_arr`.
    3. The `eval()` function in Python executes arbitrary code passed to it as a string.
    4. If an attacker can control the content of a file within the `remapped_benchmarks` directory, they can inject malicious Python code into this file.
    5. When `reconstruct.py` processes this malicious benchmark file, the `eval()` function will execute the injected code, leading to arbitrary code execution on the system running the script.

- Impact:
    - Arbitrary code execution on the machine running `reconstruct.py`.
    - An attacker could potentially gain full control of the system, steal sensitive data, or use the system for malicious purposes.

- Vulnerability Rank: Critical

- Currently Implemented Mitigations:
    - None. The code directly uses `eval()` without any input sanitization or validation on the benchmark files from `remapped_benchmarks`.

- Missing Mitigations:
    - **Replace `eval()` with `ast.literal_eval()`:**  The most critical mitigation is to replace the unsafe `eval()` function with `ast.literal_eval()`. `ast.literal_eval()` safely evaluates a string containing only Python literals (strings, numbers, tuples, lists, dicts, booleans, and None). This will prevent the execution of arbitrary code.
    - **Input Validation:** Implement validation to ensure that the content read from benchmark files in `remapped_benchmarks` conforms to the expected format (a list of tuples, where each tuple contains two integers representing index and offset). This validation should be performed *after* using `ast.literal_eval()` to ensure the parsed data is of the correct type and structure.
    - **File Integrity Checks:**  Consider implementing mechanisms to verify the integrity and authenticity of the files in the `remapped_benchmarks` directory to prevent unauthorized modification.
    - **Principle of Least Privilege:** Running the `reconstruct.py` script with minimal necessary privileges would limit the impact of a successful exploit.

- Preconditions:
    - An attacker must be able to place a malicious file or modify an existing file within the `remapped_benchmarks` directory before `reconstruct.py` is executed.  This could be through a separate vulnerability in a preceding process that generates these files, or through compromised access to the file system.

- Source Code Analysis:
    - In `reconstruct.py`, the vulnerability exists in the following code block within the main loop:
      ```python
      with open(os.path.join(base_path, benchmark), 'r') as bench_data:
        print(benchmark)
        index_offset_arr = eval(bench_data.read()) # Vulnerable line
        for index, offset in index_offset_arr:
          output_data += indexable_file_contents[index][offset:offset+1024]
      ```
      - The script opens each file located in the `remapped_benchmarks/<suite>/` directory.
      - `bench_data.read()` reads the entire content of the benchmark file as a string.
      - `eval(bench_data.read())` then takes this string content and executes it as Python code.
      - **Example of malicious file content:** If a file in `remapped_benchmarks/Snappy-COMPRESS/` contains the following text:
        ```
        __import__('os').system('echo Vulnerability_Exploited > /tmp/proof_of_exploit.txt')
        ```
        When `reconstruct.py` processes this file, `eval()` will execute the `__import__('os').system(...)` command, which will create a file `/tmp/proof_of_exploit.txt` as a proof of concept. Any arbitrary Python code can be placed in these benchmark files and will be executed.

- Security Test Case:
    1. **Setup `remapped_benchmarks` directory:** If it doesn't exist, create the `remapped_benchmarks` directory and subdirectories for each benchmark suite (e.g., `Snappy-COMPRESS`, `Snappy-DECOMPRESS`, `ZSTD-COMPRESS`, `ZSTD-DECOMPRESS`).
    2. **Create Malicious Benchmark File:** Inside the `remapped_benchmarks/Snappy-COMPRESS/` directory, create a new file named `malicious_benchmark`.
    3. **Inject Malicious Code:** Write the following Python code into `malicious_benchmark` file:
       ```
       __import__('os').system('touch /tmp/vulnerable')
       ```
       This code, when executed by `eval()`, will use the `os` module to execute the system command `touch /tmp/vulnerable`, which creates an empty file named `vulnerable` in the `/tmp/` directory.
    4. **Run `reconstruct.py`:** Execute the `reconstruct.py` script from the command line: `python3 reconstruct.py`.
    5. **Verify Exploitation:** After the script finishes execution, check if the file `/tmp/vulnerable` exists. If the file `/tmp/vulnerable` is present, it confirms that the malicious code injected into `malicious_benchmark` was executed by `eval()`, demonstrating the code injection vulnerability.
    6. **Cleanup (Optional):** Delete the `/tmp/vulnerable` file after verification.

### Path Traversal in Benchmark Filename Processing

- Description:
    1. The `reconstruct.py` script processes benchmark files located in the `remapped_benchmarks/` directory.
    2. It reads the list of benchmark filenames from the directory using `os.listdir(base_path)`.
    3. For each filename obtained from `os.listdir()`, it constructs an output file path by joining the `output_path` (which is `extracted_benchmarks/[suite]/`) with the filename directly using `os.path.join(output_path, benchmark)`.
    4. If an attacker can place a malicious file with a crafted filename containing path traversal sequences (like `../`) within the `remapped_benchmarks/` directory, the `os.path.join` operation will resolve to a path outside of the intended `extracted_benchmarks/` directory.
    5. Consequently, when the script attempts to create and write to the output file using this path, it can write files to arbitrary locations on the file system, depending on the path traversal sequence in the malicious filename.

- Impact:
    An attacker can achieve arbitrary file write on the system where `reconstruct.py` is executed. This can lead to various malicious outcomes, including:
    *   **Overwriting critical system files:** An attacker could overwrite configuration files, scripts, or even binaries, potentially leading to system compromise or denial of service.
    *   **Planting malicious files:** An attacker could write executable files (e.g., scripts, binaries) in locations where they might be automatically executed or easily triggered by users or other system processes, leading to code execution and further compromise.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    *   None. The code directly uses filenames from `os.listdir()` without any validation or sanitization before using them in `os.path.join` to create output file paths.

- Missing Mitigations:
    - **Filename Sanitization:** The application is missing input sanitization for benchmark filenames obtained from `os.listdir()`. Filenames should be validated to ensure they do not contain path traversal characters (e.g., `../`, `..\\`) or other potentially dangerous sequences. A whitelist approach for allowed characters in filenames could also be implemented.
    - **Secure Path Handling:** Instead of directly joining filenames, the application should use secure path handling techniques. For example, it could verify that the resolved output path is still within the intended `extracted_benchmarks/` directory.
    - **Path Normalization:** Normalize the output path to ensure it stays within the intended output directory. For example, use `os.path.abspath()` to resolve the path and check if it's still within the expected base directory.
    - **Input Validation:** Validate that the benchmark files in `remapped_benchmarks/` are created by a trusted process and are not tampered with.

- Preconditions:
    *   The attacker needs to be able to place a malicious file with a crafted filename into one of the directories under `remapped_benchmarks/`, specifically within the benchmark suite directories (e.g., `remapped_benchmarks/Snappy-COMPRESS/`).

- Source Code Analysis:
    1. **`reconstruct.py`:** The script starts by importing necessary modules and variables from `index_builder.py`.
    ```python
    import os
    from index_builder import *
    ```
    2. **Benchmark Suite Iteration:** The script iterates through predefined `benchmark_suites`.
    ```python
    for suite in benchmark_suites:
        base_path = os.path.join(remap_dir, suite, '')
        output_path = os.path.join(output_dir, suite, '')
        # ...
    ```
    `base_path` is constructed using `remap_dir` ("remapped_benchmarks/") and the current `suite` (e.g., "Snappy-COMPRESS"). `output_path` is constructed using `output_dir` ("extracted_benchmarks/") and the current `suite`.
    3. **Listing Benchmark Files:** The script lists all files within the `base_path` using `os.listdir(base_path)`. This is the crucial point where filenames are read from the file system, and no validation is performed on these filenames.
    ```python
    all_benchmarks = os.listdir(base_path)
    for benchmark in all_benchmarks:
        # ...
    ```
    For example, if `base_path` is `remapped_benchmarks/Snappy-COMPRESS/` and this directory contains a malicious file named `../../../evil.txt`, then `all_benchmarks` will include `../../../evil.txt`.
    4. **Output Path Construction:** Inside the loop, the script constructs the output file path by directly joining `output_path` and `benchmark` using `os.path.join`.
    ```python
    with open(os.path.join(output_path, benchmark), 'wb') as bench_extracted:
        bench_extracted.write(output_data)
    ```
    If `output_path` is `extracted_benchmarks/Snappy-COMPRESS/` and `benchmark` is `../../../evil.txt`, then `os.path.join(output_path, benchmark)` will result in the path `extracted_benchmarks/Snappy-COMPRESS/../../../evil.txt`, which simplifies to `extracted_benchmarks/../../evil.txt`. This allows writing the file `evil.txt` in the directory above `extracted_benchmarks/`.

- Security Test Case:
    1. **Setup Environment:** Ensure you have set up the project as described in `README.md`, including creating the `source_data` directory and downloading the benchmark datasets.
    2. **Prepare Malicious Benchmark File:**
        *   Create the directory `remapped_benchmarks/Snappy-COMPRESS/` if it doesn't exist.
        *   Inside `remapped_benchmarks/Snappy-COMPRESS/`, create a new file named `../../../evil.txt`.
        *   Add valid benchmark data to this file. For example, insert the text `[(0, 0)]` into `../../../evil.txt`. This is valid input for `eval()` in the script.
    3. **Run `reconstruct.py`:** Execute the `reconstruct.py` script from the command line: `python3 reconstruct.py`
    4. **Verify File Creation:** After the script execution completes, check for the creation of the file `evil.txt` in the directory *above* the `extracted_benchmarks` directory. If `extracted_benchmarks` is in the project's root directory, `evil.txt` should be created in the project's root directory.
    5. **Check File Content:** Verify that the content of `evil.txt` is as expected based on the benchmark data you put in `../../../evil.txt` (in this case, it should contain the first 1024 bytes of the first file in `indexable_file_contents`, which is likely from `Calgary/bib`).

    If the file `evil.txt` is created outside the `extracted_benchmarks/Snappy-COMPRESS/` directory with the expected content, this confirms the path traversal vulnerability.
### Vulnerability List

- Vulnerability Name: Code Injection via `eval()` in Benchmark File Parsing
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
    - **File Integrity Checks:**  Consider implementing mechanisms to verify the integrity and authenticity of the files in the `remapped_benchmarks` directory to prevent unauthorized modification. This could involve using cryptographic hashes or digital signatures, although this might be an overkill for this project and depends on the threat model.
- Preconditions:
    - An attacker must be able to place a malicious file or modify an existing file within the `remapped_benchmarks` directory before `reconstruct.py` is executed.  While the provided files do not detail how `remapped_benchmarks` is populated, we assume for the purpose of demonstrating this vulnerability, that an attacker has a way to influence the content of files in this directory. This could be through a separate vulnerability in a preceding process that generates these files, or through compromised access to the file system.
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
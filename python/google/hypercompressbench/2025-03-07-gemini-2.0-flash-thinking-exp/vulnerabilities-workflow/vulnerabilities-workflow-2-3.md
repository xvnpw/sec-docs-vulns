- Vulnerability Name: Arbitrary Code Execution via Unsafe Deserialization (Eval Injection)
- Description:
    1. The `reconstruct.py` script reads files from the `remapped_benchmarks/` directory.
    2. For each benchmark file, it reads the entire content into a string.
    3. The script then uses the `eval()` function to parse this string as Python code.
    4. If an attacker can replace the files in `remapped_benchmarks/` with malicious content, they can inject arbitrary Python code.
    5. When `reconstruct.py` is executed, the `eval()` function will execute the attacker's malicious code.
- Impact: Critical. Successful exploitation allows an attacker to execute arbitrary code on the system running `reconstruct.py`. This can lead to full system compromise, data exfiltration, malware installation, or denial of service. The attacker gains the privileges of the user running the script.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations: None. The code directly uses `eval()` on the content of the benchmark files without any sanitization or validation.
- Missing Mitigations:
    - **Replace `eval()` with safe parsing:** The most critical missing mitigation is to replace the unsafe `eval()` function with a secure method for parsing the benchmark data. If the data is expected to be in a specific format (e.g., a list of tuples), using `ast.literal_eval()` would be a safer alternative as it only evaluates literal Python expressions and prevents the execution of arbitrary code. If a more complex format is needed, a dedicated parser should be implemented.
    - **Input Validation:** While replacing `eval()` is the primary solution, as a defense-in-depth measure, input validation could be added even if `eval()` were to be used (though this is strongly discouraged). However, validating input to fully prevent code injection in `eval()` is extremely complex and generally not recommended.
    - **Principle of Least Privilege:** Running the `reconstruct.py` script with minimal necessary privileges would limit the impact of a successful exploit.
- Preconditions:
    - The attacker must be able to replace or modify the files within the `remapped_benchmarks/` directory before `reconstruct.py` is executed. This could occur if the attacker has write access to the filesystem, or if there is another vulnerability that allows file manipulation.
- Source Code Analysis:
    - In `reconstruct.py`, the following code block is responsible for processing each benchmark file:
      ```python
      with open(os.path.join(base_path, benchmark), 'r') as bench_data:
        print(benchmark)
        index_offset_arr = eval(bench_data.read()) # Vulnerable line
        for index, offset in index_offset_arr:
          output_data += indexable_file_contents[index][offset:offset+1024]
      ```
    - `os.path.join(base_path, benchmark)` constructs the path to the benchmark file within the `remapped_benchmarks/` directory. `base_path` is derived from `remap_dir` and `suite`, and `benchmark` is the name of the file being processed.
    - `open(..., 'r') as bench_data:` opens the benchmark file in read mode.
    - `bench_data.read()` reads the entire content of the benchmark file as a string.
    - `eval(bench_data.read())` is the vulnerable line. The `eval()` function takes the string read from the benchmark file and executes it as Python code.
    - If a malicious user replaces a benchmark file with content like `[(0, 0), "__import__('os').system('malicious_command')"]`, when `reconstruct.py` processes this file, `eval()` will execute `__import__('os').system('malicious_command')`, leading to arbitrary command execution.
- Security Test Case:
    1. **Prepare Malicious Benchmark File:**
        - Navigate to the `remapped_benchmarks/Snappy-COMPRESS/` directory (or any other suite directory).
        - Create a new file named `malicious_benchmark`.
        - Insert the following content into `malicious_benchmark`:
          ```python
          [(0, 0), "__import__('os').system('touch /tmp/pwned_eval_vuln')"]
          ```
          This malicious payload will attempt to create a file named `pwned_eval_vuln` in the `/tmp/` directory when executed.
    2. **Run `reconstruct.py`:**
        - Execute the `reconstruct.py` script from your terminal: `python3 reconstruct.py`
        - Observe the output in the terminal. It should process the `malicious_benchmark` file.
    3. **Verify Code Execution:**
        - Check if the file `/tmp/pwned_eval_vuln` has been created. You can use the command `ls /tmp/pwned_eval_vuln`.
        - If the file `/tmp/pwned_eval_vuln` exists, it confirms that the `eval()` function executed the injected code, demonstrating the arbitrary code execution vulnerability.
### Vulnerability List

- Vulnerability Name: Path Traversal in Benchmark File Processing
- Description:
    1. An attacker can create a malicious benchmark file with a crafted filename (e.g., containing "../") within the `remapped_benchmarks/{suite}/` directory.
    2. The `reconstruct.py` script iterates through files in `remapped_benchmarks/{suite}/` using `os.listdir()`.
    3. For each filename obtained from `os.listdir()`, the script constructs the output file path using `os.path.join(output_path, benchmark)`.
    4. If the filename contains path traversal sequences like "../", the resulting output path can escape the intended `extracted_benchmarks/{suite}/` directory.
    5. When the script writes the extracted benchmark data to this crafted path, it can write files to arbitrary locations on the file system, potentially overwriting existing files or creating new files in unexpected directories.
- Impact:
    Arbitrary File Write. An attacker can write arbitrary data to arbitrary locations on the file system where the script has write permissions. This could lead to:
    - Overwriting system files, leading to system instability or denial of service.
    - Overwriting configuration files, potentially changing application behavior.
    - Creating malicious files in sensitive directories, potentially leading to further attacks.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    None. The code directly uses filenames from `os.listdir()` without any sanitization or validation before using them in `os.path.join()`.
- Missing Mitigations:
    - Filename Sanitization: Sanitize or validate filenames obtained from `os.listdir()` to remove or reject path traversal sequences like "../".
    - Path Normalization: Normalize the output path to ensure it stays within the intended output directory. For example, use `os.path.abspath()` to resolve the path and check if it's still within the expected base directory.
    - Input Validation: Validate that the benchmark files in `remapped_benchmarks/` are created by a trusted process and are not tampered with.
- Preconditions:
    1. The attacker needs to be able to place malicious files into the `remapped_benchmarks/{suite}/` directory. This might be possible if the benchmark creation process is vulnerable or if the attacker has write access to the file system where `remapped_benchmarks/` is located.
    2. The `reconstruct.py` script needs to be executed after the malicious file is placed in the directory.
- Source Code Analysis:
    1. In `reconstruct.py`, the script gets a list of benchmark files using `all_benchmarks = os.listdir(base_path)`.
    2. It then iterates through `all_benchmarks` using `for benchmark in all_benchmarks:`.
    3. Inside the loop, it constructs the output file path using `os.path.join(output_path, benchmark)`.
    ```python
    output_path = os.path.join(output_dir, suite, '')
    ...
    for benchmark in all_benchmarks:
        ...
        with open(os.path.join(output_path, benchmark), 'wb') as bench_extracted:
            bench_extracted.write(output_data)
    ```
    4. If `benchmark` is a malicious filename like `../../../malicious_file`, the `os.path.join()` will create a path that goes outside the intended directory.
    5. The `open()` function will then create or open a file at the traversed path, and `bench_extracted.write(output_data)` will write data to that location.
- Security Test Case:
    1. Create a directory `remapped_benchmarks/Snappy-COMPRESS/`.
    2. Create a malicious file named `../../../malicious_file` inside `remapped_benchmarks/Snappy-COMPRESS/`. The content of this file should be a valid benchmark file format for the script not to fail early. Create a file with content `'[(0, 0)]'`.
        ```bash
        mkdir -p remapped_benchmarks/Snappy-COMPRESS/
        echo "'[(0, 0)]'" > remapped_benchmarks/Snappy-COMPRESS/../../../malicious_file
        ```
    3. Run the `reconstruct.py` script: `python3 reconstruct.py`.
    4. Check if a file named `malicious_file` is created in the directory above `extracted_benchmarks/`. For example, if you run `reconstruct.py` from the project root, check if `malicious_file` is created in the project root directory.
        ```bash
        ls ../malicious_file
        ```
    5. If the file `malicious_file` exists in the parent directory of `extracted_benchmarks`, the path traversal vulnerability is confirmed.
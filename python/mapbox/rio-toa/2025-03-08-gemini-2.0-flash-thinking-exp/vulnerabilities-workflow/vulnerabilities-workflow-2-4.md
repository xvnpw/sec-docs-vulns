### Vulnerability List

* Vulnerability Name: Path Traversal in CLI tools

* Description:
    1. The `rio-toa` CLI tools (`radiance`, `reflectance`, `brighttemp`) accept file paths as command-line arguments for processing Landsat 8 imagery. Specifically, the arguments `SRC_PATH`, `SRC_PATHS`, and `SRC_MTL` in the CLI commands are interpreted as file paths.
    2. When a user executes a CLI command, the application directly uses these provided file paths to open and process files using functions from the `rasterio` library and Python's built-in `open` function within the `rio_toa.toa_utils._load_mtl` function.
    3. If a malicious user provides a crafted `SRC_PATH`, `SRC_PATHS`, or `SRC_MTL` that includes path traversal characters (e.g., `../`, `../../`), the application, without sufficient input validation, will attempt to open a file at the manipulated path.
    4. This can allow an attacker to access files and directories outside of the intended working directory of the application, potentially leading to unauthorized file access. For example, by providing a path like `../../../etc/passwd` as `SRC_MTL`, an attacker could attempt to read the contents of the `/etc/passwd` file on the system where the CLI tool is executed.

* Impact:
    - **Information Disclosure:** An attacker could read sensitive files on the server's file system that the user running the `rio-toa` tool has access to. This could include configuration files, application code, or other data not intended for public access.
    - **Potential for further exploitation:** While direct arbitrary code execution is not evident in the provided code, information gained through path traversal could be used to identify further vulnerabilities or to prepare for social engineering attacks. The ability to read system files can significantly aid in system reconnaissance and elevation of privileges in a more complex attack scenario.

* Vulnerability Rank: High

* Currently Implemented Mitigations:
    - None. The code directly uses user-provided paths without any visible sanitization or validation to prevent path traversal.

* Missing Mitigations:
    - **Input Path Sanitization:** Implement sanitization of all file path inputs (`SRC_PATH`, `SRC_PATHS`, `SRC_MTL`) in the CLI tools. This should involve validating that the provided paths are within the expected directories or conform to expected patterns. Techniques include:
        - **Using `os.path.abspath` and `os.path.commonprefix`:** Resolve the absolute path of the user-provided input and check if it is within the expected base directory.
        - **Path validation with regular expressions:**  Validate the input path against a whitelist of allowed characters and patterns.
        - **Using secure path manipulation libraries:** Explore libraries designed to handle file paths securely and prevent traversal vulnerabilities.
    - **Principle of Least Privilege:** Ensure that the user running the `rio-toa` tool operates with the minimum necessary privileges to reduce the potential impact of a successful path traversal attack. However, this is a general security best practice and not a direct mitigation within the code itself.

* Preconditions:
    - The attacker needs to be able to execute the `rio-toa` CLI tools (`radiance`, `reflectance`, `brighttemp`) and provide command-line arguments.
    - The user running the CLI tools must have read permissions to the files the attacker attempts to access via path traversal, for the attack to be successful in information disclosure.

* Source Code Analysis:
    - **CLI Argument Handling:** In `rio_toa/scripts/cli.py`, the `@click.argument` decorator for `src_path`, `src_paths`, and `src_mtl` in `radiance`, `reflectance`, and `brighttemp` commands simply defines them as arguments without any input validation or sanitization.
    - **File Opening in CLI commands:**  For example, in the `radiance` command in `rio_toa/scripts/cli.py`:
        ```python
        @click.command('radiance')
        @click.argument('src_path', type=click.Path(exists=True))
        @click.argument('src_mtl', type=click.Path(exists=True))
        @click.argument('dst_path', type=click.Path(exists=False))
        ...
        def radiance(ctx, src_path, src_mtl, dst_path, ...):
            ...
            calculate_landsat_radiance(src_path, src_mtl, dst_path, ...)
        ```
        The `src_path` and `src_mtl` are directly passed to `calculate_landsat_radiance`.
    - **File Opening in `calculate_landsat_radiance` (and similar functions):** In `rio_toa/radiance.py`, the `calculate_landsat_radiance` function receives `src_path` and `src_mtl`. It opens these files directly using `rasterio.open(src_path)` and `toa_utils._load_mtl(src_mtl)`:
        ```python
        def calculate_landsat_radiance(src_path, src_mtl, dst_path, ...):
            mtl = toa_utils._load_mtl(src_mtl) # Potential path traversal here
            with rasterio.open(src_path) as src: # Potential path traversal here
                ...
        ```
    - **File Opening in `_load_mtl`:** In `rio_toa/toa_utils.py`, the `_load_mtl` function opens the MTL file using Python's built-in `open` function:
        ```python
        def _load_mtl(src_mtl):
            with open(src_mtl) as src: # Potential path traversal here
                if src_mtl.split('.')[-1] == 'json':
                    return json.loads(src.read())
                else:
                    return _parse_mtl_txt(src.read())
        ```
    - **Visualization:**
        ```
        CLI Command (e.g., radiance) --> cli.py (argument parsing) --> calculate_landsat_radiance (radiance.py) --> toa_utils._load_mtl (toa_utils.py) --> open(src_mtl) / rasterio.open(src_path)
        User Input (malicious path) --> SRC_MTL / SRC_PATH command-line arguments --> Passed directly to file opening functions
        ```
        This flow shows that user-controlled input (file paths) directly reaches file system operations without sanitization, creating a path traversal vulnerability.

* Security Test Case:
    1. **Setup:** Ensure you have `rio-toa` installed and accessible via the command line. You also need a dummy Landsat 8 band TIF file (e.g., `tests/data/tiny_LC80100202015018LGN00_B1.TIF`) and a dummy MTL JSON file (e.g., `tests/data/LC80100202015018LGN00_MTL.json`) within your testing environment, or accessible paths to these files. For the exploit, assume there is a sensitive file at `/tmp/sensitive_file.txt` with content "This is sensitive data."
    2. **Create a sensitive file (for testing purposes):** On your test system, create a file at `/tmp/sensitive_file.txt` with some content:
        ```bash
        echo "This is sensitive data." > /tmp/sensitive_file.txt
        ```
    3. **Execute `rio toa radiance` command with path traversal in `src_mtl`:** Run the `rio toa radiance` CLI command, providing a path traversal payload as the `src_mtl` argument. For `src_path` and `dst_path`, use valid paths, for example paths to the provided test data or create dummy files if needed. Redirect the output to a file to examine it later.
        ```bash
        rio toa radiance tests/data/tiny_LC80100202015018LGN00_B1.TIF "../../../tmp/sensitive_file.txt" /tmp/output_radiance.tif
        ```
        **Note:** Adjust the path traversal string (`"../../../tmp/sensitive_file.txt"`) based on the location of your sensitive file relative to the expected working directory of the `rio-toa` command. The provided example assumes that running the command from the project root would allow traversal to `/tmp`.
    4. **Examine the output and error messages:** Check the output of the command and any error messages. If the path traversal is successful, the command might fail because the MTL file format is not expected for `/tmp/sensitive_file.txt`, but it will attempt to open and parse `/tmp/sensitive_file.txt`.  The goal is to confirm that the application attempts to access the file at the traversed path. In a real-world scenario, if an attacker could place a file with valid MTL structure at a known location they can traverse to, they might be able to make the command execute successfully, potentially revealing more information through error messages or side-channel effects, even if direct file content is not echoed to standard output.
    5. **Verify file access (optional, requires code modification for direct content read):** To directly demonstrate reading the content, you would need to modify the `rio_toa.toa_utils._load_mtl` function temporarily to print the content of the opened file or save it to a predictable location, instead of just parsing it as MTL. Then, re-run the test case and check if the content of `/tmp/sensitive_file.txt` is revealed. However, for the purpose of proving the vulnerability, observing the attempt to open the file via error messages or debugging is often sufficient.

This test case demonstrates that the `rio-toa` CLI tools are vulnerable to path traversal because they directly use user-provided file paths without sufficient sanitization, allowing an attacker to attempt to access arbitrary files on the file system.
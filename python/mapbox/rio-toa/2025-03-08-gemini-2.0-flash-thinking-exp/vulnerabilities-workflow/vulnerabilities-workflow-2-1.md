- Vulnerability Name: Path Traversal in CLI Arguments

- Description:
An attacker can exploit a path traversal vulnerability by manipulating the `SRC_PATH` or `SRC_MTL` arguments in the command-line interface (CLI) tools such as `radiance`, `reflectance`, `brighttemp`, and `parsemtl`. By providing a crafted path containing directory traversal sequences (e.g., `../`), an attacker can potentially read arbitrary files from the file system where the `rio-toa` tool is executed.

**Step-by-step trigger:**
1. The attacker identifies that the `rio-toa` library is used, specifically the CLI tools like `radiance`, `reflectance`, `brighttemp`, or `parsemtl`.
2. The attacker crafts a malicious input for either `SRC_PATH` or `SRC_MTL` arguments in one of the CLI tools. For example, when using the `radiance` tool, the attacker can replace the expected path to a Landsat image or MTL file with a path like `/etc/passwd` or `../../../../sensitive_file.txt`.
3. The attacker executes the CLI tool with the manipulated argument. For example:
   ```bash
   rio toa radiance ../../../../etc/passwd tests/data/LC81060712016134LGN00_MTL.json output.tif
   ```
   or
   ```bash
   rio toa radiance tests/data/LC81060712016134LGN00_B3.TIF ../../../../etc/passwd output.tif
   ```
4. The application, without proper path validation, attempts to open and process the file specified by the attacker-controlled path.
5. If successful, the tool will attempt to read and potentially process the content of the file located at the attacker-specified path (e.g., `/etc/passwd`). In the case of `parsemtl`, the content of the arbitrary file will be parsed and outputted as JSON. For `radiance`, `reflectance`, and `brighttemp`, the tool might fail to process a non-image file as input, but the file will still be opened and read by `rasterio` library which is the core of the vulnerability.

- Impact:
    - **Information Disclosure:** An attacker can read sensitive files on the server or system where the `rio-toa` tool is running. This could include configuration files, application code, or user data, depending on the file system permissions and the context in which the tool is executed.
    - **Potential for further exploitation:** In more critical scenarios, reading sensitive files could provide attackers with credentials or other information needed to escalate their attack and gain deeper access to the system.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    - None. The provided code does not implement any explicit path validation or sanitization for the `SRC_PATH` or `SRC_MTL` arguments in the CLI tools. The file paths are directly passed to `rasterio.open()` and `open()` functions without checks.

- Missing Mitigations:
    - **Input Path Validation:** Implement validation for `SRC_PATH` and `SRC_MTL` arguments to ensure that the paths are within the expected directories or conform to expected patterns.
    - **Path Sanitization:** Sanitize the input paths to remove directory traversal sequences (e.g., `../`, `./`) before using them in file system operations.
    - **Principle of Least Privilege:** Ensure that the user running the `rio-toa` tool has the minimum necessary permissions to access only the intended files and directories. This is a general security best practice but can limit the impact of a path traversal vulnerability.

- Preconditions:
    - The attacker must have access to execute the `rio-toa` CLI tools (`radiance`, `reflectance`, `brighttemp`, `parsemtl`).
    - The tool must be running in an environment where the attacker-specified paths exist and are readable by the user executing the tool.

- Source Code Analysis:
    1. **CLI Argument Handling (`rio_toa/scripts/cli.py`):**
       - In `rio_toa/scripts/cli.py`, the CLI commands `radiance`, `reflectance`, `brighttemp`, and `parsemtl` are defined using `click`.
       - For example, in the `radiance` command:
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
       - The `click.Path(exists=True)` type for `src_path` and `src_mtl` only checks if the path *exists*, but it does not prevent directory traversal. It does not validate if the path is within an allowed directory or sanitize path traversal sequences.

    2. **File Opening in Core Logic (`rio_toa/radiance.py`, `rio_toa/reflectance.py`, `rio_toa/brightness_temp.py`, `rio_toa/toa_utils.py`):**
       - In the core logic functions like `calculate_landsat_radiance`, `calculate_landsat_reflectance`, and `calculate_landsat_brightness_temperature`, the `src_path` and `src_mtl` arguments are directly used to open files:
         - `rasterio.open(src_path)` is used to open the source raster file.
         - `toa_utils._load_mtl(src_mtl)` is used to load the MTL file, which internally uses `open(src_mtl)`.
       - Neither `rasterio.open()` nor the standard Python `open()` function inherently prevent path traversal vulnerabilities if the provided paths are not validated or sanitized.

    **Visualization:**

    ```
    [Attacker] --> CLI Command (rio toa radiance) --SRC_PATH="../../../etc/passwd"--> [rio_toa CLI] --> src_path argument = "../../../etc/passwd" --> calculate_landsat_radiance(src_path) --> rasterio.open("../../../etc/passwd") --> [File System] --> /etc/passwd (if permissions allow) --> [Data Read] --> [rio_toa processing (likely to fail but file is read)]
    ```

- Security Test Case:

    **Test Case Name:** Path Traversal Read Arbitrary File via `radiance` CLI

    **Description:**
    This test verifies that an attacker can read arbitrary files from the system using the `rio toa radiance` command by manipulating the `SRC_PATH` argument with path traversal sequences.

    **Preconditions:**
    - `rio-toa` library is installed and the `rio toa` CLI command is accessible.
    - A test file exists on the system at a known location that the attacker should not normally be able to access (e.g., a temporary file with sensitive content, or for demonstration purposes, `/etc/passwd` on Linux-like systems - be cautious and only test on systems you own or have explicit permission to test on). For this example, let's assume we want to read `/etc/passwd`.
    - A dummy MTL file is needed, for example, any MTL file from the `tests/data` directory in the project.

    **Steps:**
    1. Open a terminal and navigate to a directory where you can execute the `rio toa` command.
    2. Execute the `rio toa radiance` command, replacing the `SRC_PATH` argument with a path traversal string to target the `/etc/passwd` file and using a valid MTL file from the test data. For example:
       ```bash
       rio toa radiance ../../../../etc/passwd tests/data/LC81060712016134LGN00_MTL.json output_passwd.tif
       ```
    3. After execution, check if the command runs without errors related to file access (it might throw errors later due to file format, but the initial open should succeed).
    4. (Verification - manual): Examine the output or any logs produced by the tool. If the tool attempts to process `/etc/passwd` as a raster image, it indicates that the path traversal was successful in opening the file. While `rio toa radiance` might fail to process `/etc/passwd` as a valid image, the vulnerability is confirmed by the fact that it attempted to open and read the file from the attacker-specified path.
    5. (Enhanced Verification - for `parsemtl` command): For the `parsemtl` command, the output should be the JSON parsed content of the `/etc/passwd` file, which would directly confirm the successful path traversal and file reading. For example:
       ```bash
       rio toa parsemtl ../../../../etc/passwd
       ```
       Examine the standard output. It should contain the content of `/etc/passwd` parsed as JSON (which will likely not be valid JSON and cause errors, but the content attempt is the indicator).

    **Expected Result:**
    - For `radiance`, `reflectance`, `brighttemp`: The command will likely execute but may throw errors during processing due to `/etc/passwd` not being a valid raster image. However, the successful execution up to the point of file opening confirms the path traversal vulnerability.
    - For `parsemtl`: The command will attempt to parse the content of `/etc/passwd` as a MTL file and output JSON. While it will likely not be valid MTL and might result in errors, the output will reflect attempts to process `/etc/passwd`, confirming the vulnerability.

    **Note:** When testing path traversal vulnerabilities, always be ethical and responsible. Only perform tests on systems you own or have explicit permission to test. Avoid accessing or attempting to access sensitive files that you are not authorized to view. For demonstration purposes in a safe test environment, creating a dummy sensitive file is recommended instead of targeting system files like `/etc/passwd`.
### Combined Vulnerability List

This document outlines the identified vulnerabilities after combining and deduplicating the provided lists. Each vulnerability is detailed with its description, potential impact, severity ranking, current mitigations, missing mitigations, preconditions for exploitation, source code analysis, and a security test case.

#### 1. Path Traversal in CLI Arguments (`SRC_PATH`, `SRC_PATHS`, `SRC_MTL`)

- **Description:**
    An attacker can exploit a path traversal vulnerability by manipulating the `SRC_PATH`, `SRC_PATHS`, or `SRC_MTL` arguments in the command-line interface (CLI) tools such as `radiance`, `reflectance`, `brighttemp`, and `parsemtl`. By providing a crafted path containing directory traversal sequences (e.g., `../`), an attacker can potentially read arbitrary files from the file system where the `rio-toa` tool is executed.

    **Step-by-step trigger:**
    1. The attacker identifies that the `rio-toa` library is used, specifically the CLI tools like `radiance`, `reflectance`, `brighttemp`, or `parsemtl`.
    2. The attacker crafts a malicious input for either `SRC_PATH`, `SRC_PATHS`, or `SRC_MTL` arguments in one of the CLI tools. For example, when using the `radiance` tool, the attacker can replace the expected path to a Landsat image or MTL file with a path like `/etc/passwd` or `../../../../sensitive_file.txt`.
    3. The attacker executes the CLI tool with the manipulated argument. For example:
       ```bash
       rio toa radiance ../../../../etc/passwd tests/data/LC81060712016134LGN00_MTL.json output.tif
       ```
       or
       ```bash
       rio toa radiance tests/data/LC81060712016134LGN00_B3.TIF ../../../../etc/passwd output.tif
       ```
       or for `parsemtl`:
       ```bash
       rio toa parsemtl ../../../../etc/passwd
       ```
    4. The application, without proper path validation, attempts to open and process the file specified by the attacker-controlled path.
    5. If successful, the tool will attempt to read and potentially process the content of the file located at the attacker-specified path (e.g., `/etc/passwd`). In the case of `parsemtl`, the content of the arbitrary file will be parsed and outputted as JSON. For `radiance`, `reflectance`, and `brighttemp`, the tool might fail to process a non-image file as input, but the file will still be opened and read by `rasterio` library which is the core of the vulnerability.

- **Impact:**
    - **Information Disclosure:** An attacker can read sensitive files on the server or system where the `rio-toa` tool is running. This could include configuration files, application code, or user data, depending on the file system permissions and the context in which the tool is executed.
    - **Potential for further exploitation:** In more critical scenarios, reading sensitive files could provide attackers with credentials or other information needed to escalate their attack and gain deeper access to the system.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
    - None. The provided code does not implement any explicit path validation or sanitization for the `SRC_PATH`, `SRC_PATHS`, or `SRC_MTL` arguments in the CLI tools. The file paths are directly passed to `rasterio.open()` and `open()` functions without checks.

- **Missing Mitigations:**
    - **Input Path Validation:** Implement validation for `SRC_PATH`, `SRC_PATHS`, and `SRC_MTL` arguments to ensure that the paths are within the expected directories or conform to expected patterns.
    - **Path Sanitization:** Sanitize the input paths to remove directory traversal sequences (e.g., `../`, `./`) before using them in file system operations.
    - **Principle of Least Privilege:** Ensure that the user running the `rio-toa` tool has the minimum necessary permissions to access only the intended files and directories. This is a general security best practice but can limit the impact of a path traversal vulnerability.

- **Preconditions:**
    - The attacker must have access to execute the `rio-toa` CLI tools (`radiance`, `reflectance`, `brighttemp`, `parsemtl`).
    - The tool must be running in an environment where the attacker-specified paths exist and are readable by the user executing the tool.

- **Source Code Analysis:**
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
    3. **File Opening in `_load_mtl` (`rio_toa/toa_utils.py`):**
        ```python
        def _load_mtl(src_mtl):
            with open(src_mtl) as src: # Potential path traversal here
                if src_mtl.split('.')[-1] == 'json':
                    return json.loads(src.read())
                else:
                    return _parse_mtl_txt(src.read())
        ```

    **Visualization:**

    ```
    [Attacker] --> CLI Command (rio toa radiance) --SRC_PATH="../../../etc/passwd"--> [rio_toa CLI] --> src_path argument = "../../../etc/passwd" --> calculate_landsat_radiance(src_path) --> rasterio.open("../../../etc/passwd") --> [File System] --> /etc/passwd (if permissions allow) --> [Data Read] --> [rio_toa processing (likely to fail but file is read)]
    ```

- **Security Test Case:**

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

#### 2. Insecure Type Conversion in MTL Parsing

- **Description:**
    An attacker can craft a malicious Landsat 8 MTL text file containing a specifically formatted string value within a metadata field that is expected to be a numerical type (integer or float). When processed by the `_cast_to_best_type` function, this string is incorrectly converted to a float, bypassing expected data type constraints in downstream calculations within `rio-toa`. This leads to flawed or unexpected results in the generated TOA products. The vulnerability is triggered when using the `parsemtl` command-line tool to parse the malicious MTL file, and subsequently when other `rio-toa` commands utilize the parsed metadata.

    **Step-by-step trigger:**
    1. An attacker crafts a malicious Landsat 8 MTL text file.
    2. This file contains a specifically formatted string value within a metadata field that is expected to be a numerical type (integer or float).
    3. The attacker uses a carefully designed string that, when processed by the `_cast_to_best_type` function, is incorrectly converted to a float.
    4. This incorrect type conversion bypasses expected data type constraints in downstream calculations within `rio-toa`.
    5. The `parsemtl` command-line tool is used to parse this malicious MTL file.
    6. Subsequently, when other `rio-toa` commands (like `radiance`, `reflectance`, or `brighttemp`) utilize the parsed metadata, they may perform calculations based on the attacker-controlled, incorrectly typed value, leading to flawed or unexpected results in the generated TOA products.

- **Impact:**
    - Incorrect Top Of Atmosphere (TOA) calculations.
    - Generation of inaccurate or misleading Landsat 8 TOA products.
    - Potential for misuse of generated data in downstream applications relying on accurate TOA values.

- **Vulnerability Rank:** Medium

- **Currently Implemented Mitigations:**
    - None. The code attempts to cast strings to `int` and `float` but lacks validation or sanitization to prevent incorrect or malicious conversions.

- **Missing Mitigations:**
    - Input validation for MTL file content, specifically checking data types and formats against expected schemas.
    - Sanitization of input strings before type conversion to prevent unexpected behavior during casting.
    - Explicit type checking and validation in functions that consume parsed MTL data to ensure expected data types are used in calculations.

- **Preconditions:**
    - The attacker needs to be able to provide a malicious Landsat 8 MTL text file to the `parsemtl` command-line tool. This could be achieved if the tool is used in an environment where users can supply their own MTL files, for example, in a web service or a workflow processing user-uploaded data.

- **Source Code Analysis:**
    - File: `/code/rio_toa/toa_utils.py`
    - Function: `_cast_to_best_type(kd)`
    ```python
    def _cast_to_best_type(kd):
        key, data = kd[0]
        try:
            return key, int(data)
        except ValueError:
            try:
                return key, float(data) # Potential vulnerability: Incorrect float conversion
            except ValueError:
                return key, u'{}'.format(data.strip('"'))
    ```
    - The `_cast_to_best_type` function attempts to convert string values from the MTL file to `int` first, then to `float` if `int` conversion fails, and finally leaves it as a string if both fail.
    - **Vulnerability Point**: The float conversion is performed without any validation or sanitization of the input `data` string. An attacker can craft a string that is successfully converted to a float but represents an unexpected or malicious value.
    - Function: `_parse_mtl_txt(mtltxt)` and Command: `parsemtl(mtl)` in `/code/rio_toa/scripts/cli.py` are also relevant as described in the original vulnerability report.

- **Security Test Case:**
    1. Create a malicious MTL text file (e.g., `malicious_mtl.txt`) with a modified `K1_CONSTANT_BAND_10` value designed to cause an issue in `brightness_temp` calculation, for example by setting it to a very large or small float value represented as a string that `_cast_to_best_type` will convert to float.
    ```
    GROUP = L1_METADATA_FILE
      GROUP = METADATA_FILE_INFO
        ORIGIN = "Image courtesy of the U.S. Geological Survey"
      END_GROUP = METADATA_FILE_INFO
      GROUP = PRODUCT_METADATA
        SCENE_CENTER_TIME = "15:10:22.4142571Z"
        DATE_ACQUIRED = 2015-01-18
      END_GROUP = PRODUCT_METADATA
      GROUP = TIRS_THERMAL_CONSTANTS
        K1_CONSTANT_BAND_10 = "1.0e30"  // Maliciously crafted string for K1_CONSTANT_BAND_10
        K2_CONSTANT_BAND_10 = 1321.08
      END_GROUP = TIRS_THERMAL_CONSTANTS
    END_GROUP = L1_METADATA_FILE
    ```
    2. Run the `parsemtl` command on the malicious MTL file and save the JSON output to a file (e.g., `malicious_mtl.json`).
    ```bash
    rio toa parsemtl malicious_mtl.txt > malicious_mtl.json
    ```
    3. Execute the `rio toa brighttemp` command using a sample TIF file and the maliciously crafted MTL JSON file.
    ```bash
    rio toa brighttemp tests/data/tiny_LC81390452014295LGN00_B10.TIF malicious_mtl.json /tmp/bt_malicious.tif
    ```
    4. Compare the output `/tmp/bt_malicious.tif` with a baseline output generated using a clean MTL file. Observe if the brightness temperature calculation is significantly different or produces errors due to the manipulated `K1_CONSTANT_BAND_10` value.

#### 3. Path Traversal in `DST_PATH` parameter

- **Description:**
    The `rio-toa` command-line interface (CLI) allows users to specify an output file path (`DST_PATH`) for processed Landsat 8 imagery using `radiance`, `reflectance`, and `brighttemp` commands. The application directly uses the provided `DST_PATH` to create and write output files without proper validation or sanitization. An attacker can craft a malicious `DST_PATH` containing path traversal sequences like `../` to write files to arbitrary locations outside the intended output directory.

    **Step-by-step trigger:**
    1. The attacker identifies that the `rio-toa` library is used, specifically the CLI tools like `radiance`, `reflectance`, or `brighttemp`.
    2. The attacker crafts a malicious `DST_PATH` argument in one of the CLI tools (`radiance`, `reflectance`, or `brighttemp`). For example, the attacker can provide a path like `../../../evil.tif`.
    3. The attacker executes the CLI tool with the manipulated `DST_PATH` argument. For example:
    ```bash
    rio toa radiance tests/data/tiny_LC80100202015018LGN00_B1.TIF tests/data/LC80100202015018LGN00_MTL.json ../../../evil.tif
    ```
    4. The application, without proper path validation, attempts to create and write the output file to the attacker-specified path.
    5. If successful, the tool will write the output file (e.g., `evil.tif`) to the attacker-specified location, potentially outside the intended output directory.

- **Impact:**
    - **Arbitrary File Write:** An attacker can write files to locations outside the intended output directory.
    - **Potential for Information Disclosure, Code Execution, and Data Tampering:** By writing to arbitrary locations, an attacker could potentially overwrite critical system files, configuration files, or executable files. This could lead to various malicious outcomes, including gaining unauthorized access, executing arbitrary code, or corrupting system data.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
    - None. The application does not perform any validation or sanitization of the `DST_PATH` parameter.

- **Missing Mitigations:**
    - **Input validation and sanitization for `DST_PATH`:** The application should validate and sanitize the `DST_PATH` to prevent path traversal attacks. This can be achieved by:
        - Converting the user-provided `DST_PATH` to an absolute path using `os.path.abspath`.
        - Normalizing the path using `os.path.normpath` to remove redundant separators and path traversal components.
        - Validating that the normalized absolute path is within the intended output directory or a set of allowed directories.

- **Preconditions:**
    - The attacker needs to be able to execute the `rio-toa` CLI commands (`radiance`, `reflectance`, or `brighttemp`) and control the `DST_PATH` parameter.

- **Source Code Analysis:**
    - File: `rio_toa/scripts/cli.py` and `rio_toa/radiance.py` (and similarly for `reflectance.py` and `brightness_temp.py`)
    - The `DST_PATH` argument is passed from the CLI command directly to the core processing functions (e.g., `calculate_landsat_radiance`).
    - In core processing functions, `DST_PATH` is used directly in `riomucho.RioMucho` which utilizes `rasterio.open` to create the output file at the specified path.
    - No path validation or sanitization is performed on `DST_PATH` in `rio-toa` code before it is used by `rasterio.open`.

- **Security Test Case:**
    1. Create a temporary directory named `test_rio_toa_traversal`.
    2. Navigate into this directory: `cd test_rio_toa_traversal`.
    3. Create a subdirectory named `output_dir`: `mkdir output_dir`.
    4. Navigate into `output_dir`: `cd output_dir`.
    5. Execute the `rio toa radiance` command with a path traversal payload for `DST_PATH`.
    ```bash
    rio toa radiance ../../../code/tests/data/tiny_LC80100202015018LGN00_B1.TIF ../../../code/tests/data/LC80100202015018LGN00_MTL.json ../evil_traversal.tif
    ```
    6. Navigate back to the temporary directory `test_rio_toa_traversal`: `cd ..`.
    7. Verify if the file `evil_traversal.tif` has been created in `test_rio_toa_traversal` directory.
    8. Clean up the temporary directory `test_rio_toa_traversal` and the created `evil_traversal.tif` file.
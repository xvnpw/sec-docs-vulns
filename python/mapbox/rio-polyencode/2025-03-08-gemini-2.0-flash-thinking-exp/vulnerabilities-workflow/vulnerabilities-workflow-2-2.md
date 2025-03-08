#### 1. Command Injection via Filename Arguments

- **Description:**
  An attacker can achieve command injection by crafting malicious filenames or paths provided as `INPUTS` or `OUTPUT` arguments to the `polyencode` or `polydecode` commands. These arguments, intended to specify raster file paths, are passed to the `rasterio.open()` function without proper sanitization. If the underlying GDAL library, used by `rasterio`, is susceptible to command injection through filenames (which can occur depending on GDAL drivers and configurations), this vulnerability allows for arbitrary command execution on the system.

  **Steps to trigger the vulnerability:**
  1. The attacker crafts a malicious filename or path. This malicious input is designed to be interpreted as a command when processed by the system, especially by GDAL through `rasterio.open()`.
  2. The attacker uses the `rio polyencode` or `rio polydecode` command-line tool, providing the malicious filename as either an `INPUTS` argument for `polyencode`, or `INPUT` argument for `polydecode`, or as the `OUTPUT` argument for either command.
  3. When the Python script executes `rio.open()` with the attacker-controlled filename, and if GDAL is vulnerable to command injection through filenames in the given environment, GDAL attempts to process the filename.
  4. Due to insufficient sanitization, GDAL interprets the malicious filename as a command and executes it on the server.

- **Impact:**
  Successful command injection allows the attacker to execute arbitrary commands on the server where the `rio-polyencode` tool is running. This can lead to severe consequences, including:
    - **Complete System Compromise:** Attackers can gain full control of the server.
    - **Data Theft:** Sensitive data stored on the server can be accessed and exfiltrated.
    - **Data Manipulation:** Attackers can modify or delete critical data.
    - **Denial of Service:** The system can be made unavailable through malicious commands.
    - **Lateral Movement:** The compromised system can be used as a stepping stone to attack other systems within the network.

- **Vulnerability Rank:** Critical

- **Currently Implemented Mitigations:**
  None. The project uses `click.Path(resolve_path=True)` for path arguments, which only resolves the path to be absolute. This does not provide any security against command injection vulnerabilities. There is no input sanitization or validation implemented in the code to prevent malicious filenames from being processed by `rasterio.open()`.

- **Missing Mitigations:**
  - **Input Sanitization:** Implement robust sanitization of all filename and path arguments (`INPUTS`, `INPUT`, `OUTPUT`) before they are passed to `rasterio.open()`. This could include:
    - **Whitelisting allowed characters:** Restrict filenames to a safe set of characters (alphanumeric, underscores, hyphens, periods).
    - **Path validation:** Ensure that the provided paths conform to expected patterns and do not contain unexpected elements that could be interpreted as commands.
  - **Secure Path Handling:** Explore and utilize secure path handling functions provided by `rasterio` or GDAL, if available, that can prevent command injection.
  - **Principle of Least Privilege:** Run the `rio-polyencode` tool with the minimum necessary privileges to limit the impact of a successful command injection.

- **Preconditions:**
  1. **Attacker Access:** The attacker needs to be able to execute the `rio-polyencode` command-line tool and control the `INPUTS`, `INPUT`, or `OUTPUT` arguments. This could be through direct command-line access, or indirectly through a web application or service that utilizes this tool and allows user-controlled filenames.
  2. **GDAL Vulnerability (Context Dependent):** The underlying GDAL library must be vulnerable to command injection through filenames in the specific environment and configuration where `rio-polyencode` is running. While not guaranteed in every GDAL version or configuration, historical vulnerabilities and the complexity of GDAL drivers make this a realistic concern. The vulnerability is more likely to be exploitable if GDAL is configured to use drivers that are known to be susceptible to command injection through filenames.

- **Source Code Analysis:**

  1. **`rio_polyencode/scripts/cli.py`:**
     - **`polyencode` function:**
       ```python
       @click.command(short_help="")
       @click.argument(
           "inputfiles",
           type=click.Path(resolve_path=True),
           required=True,
           nargs=-1,
           metavar="INPUTS",
       )
       @click.argument("output", type=click.Path(resolve_path=True))
       ...
       def polyencode(ctx, inputfiles, output, poly_order, reflect):
           ...
           with rio.open(inputfiles[0]) as src: # Vulnerable line 1
               ...
           for i, p in enumerate(inputfiles):
               with rio.open(p) as src:        # Vulnerable line 2
                   ...
           with rio.open(output, "w", **metaprof) as dst: # Vulnerable line 3
               ...
       ```
       - The `polyencode` function takes `inputfiles` and `output` arguments, both defined using `click.Path(resolve_path=True)`. This `click.Path` type only resolves the path to be absolute but does not sanitize it for security vulnerabilities.
       - **Vulnerable Lines:** The `inputfiles[0]`, `p` (from `inputfiles`), and `output` variables, which are directly derived from user input, are passed to `rio.open()` without any sanitization. This is where the command injection vulnerability lies. If an attacker provides a malicious filename as part of `inputfiles` or `output`, it will be directly passed to GDAL through `rio.open()`.

     - **`polydecode` function:**
       ```python
       @click.command(short_help="")
       @click.argument(
           "inputfile",
           type=click.Path(resolve_path=True),
           required=True,
           metavar="INPUT",
       )
       @click.argument("output", type=click.Path(resolve_path=True))
       @click.argument("x", type=float)
       ...
       def polydecode(ctx, inputfile, output, x):
           ...
           with rio.open(inputfile) as src: # Vulnerable line 1
               ...
           with rio.open(output, "w", **metaprof) as dst: # Vulnerable line 2
               ...
       ```
       - Similarly, the `polydecode` function takes `inputfile` and `output` arguments using `click.Path(resolve_path=True)`.
       - **Vulnerable Lines:** The `inputfile` and `output` variables are directly passed to `rio.open()` without sanitization, making the `polydecode` function also vulnerable to command injection through malicious filenames.

  **Visualization:**
  ```
  User Input (Malicious Filename) --> click.Path(resolve_path=True) --> rio.open() --> GDAL --> System Command Execution (if vulnerable)
  ```

- **Security Test Case:**

  1. **Setup:**
     - Ensure `rio-polyencode` is installed in a test environment.
     - Create a dummy GeoTIFF input file named `input.tif` (the content doesn't matter for this test).

  2. **Test for `polyencode` command injection:**
     - Execute the following command in a terminal, attempting to inject a command using a malicious input filename. This example uses `touch /tmp/pwned_encode` to create a file in the `/tmp` directory as a proof of concept for command execution:
       ```bash
       rio polyencode "input.tif; touch /tmp/pwned_encode" output_encode.tif
       ```
     - **Verification:** Check if the file `/tmp/pwned_encode` has been created. If it exists, the command injection was successful through the `polyencode` command.

  3. **Test for `polydecode` command injection:**
     - Execute the following command in a terminal, attempting to inject a command using a malicious input filename for `polydecode`. This example uses `touch /tmp/pwned_decode` to create a file in the `/tmp` directory as a proof of concept for command execution:
       ```bash
       rio polydecode "input.tif; touch /tmp/pwned_decode" output_decode.tif 10
       ```
     - **Verification:** Check if the file `/tmp/pwned_decode` has been created. If it exists, the command injection was successful through the `polydecode` command.

  **Expected Result:**
  If either `/tmp/pwned_encode` or `/tmp/pwned_decode` files are created after running the respective commands, it confirms the command injection vulnerability is present in `rio-polyencode`. This indicates that malicious commands embedded in filenames passed as arguments to `rio-polyencode` can be executed on the system.
### Vulnerability List:

- Vulnerability Name: Potential Command Injection via Filenames in `rio polyencode` and `rio polydecode`
- Description:
    - An attacker can provide a maliciously crafted filename as input to the `rio polyencode` or `rio polydecode` tools.
    - When `rasterio.open()` is called with this filename, it is possible that the underlying GDAL library or system file handling mechanisms might interpret certain characters within the filename as shell commands, leading to unintended command execution.
    - This could occur if filenames are not properly sanitized before being processed by GDAL or the operating system, and if GDAL or system calls triggered by `rasterio.open()` inadvertently pass parts of the filename to a shell for interpretation.
    - Specifically, in `rio polyencode`, the `inputfiles` and `output` arguments are potential injection points, and in `rio polydecode`, the `inputfile` and `output` arguments are potential injection points.
- Impact: Arbitrary command execution on the system running the `rio polyencode` or `rio polydecode` tools. This could allow an attacker to gain complete control over the system, steal sensitive data, or cause a denial of service.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations:
    - None. The code uses `click.Path(resolve_path=True)` which resolves the path to be absolute but does not perform any sanitization to prevent command injection.
- Missing Mitigations:
    - Filenames provided as input should be strictly validated and sanitized to prevent interpretation of malicious characters as shell commands. This could involve:
        - Restricting allowed characters in filenames to alphanumeric characters, underscores, hyphens, and dots.
        - Using escaping or quoting mechanisms when passing filenames to underlying system calls or libraries that might interpret them in a shell context.
        - Employing secure file handling practices to avoid reliance on shell interpretation of filenames.
- Preconditions:
    - The attacker must be able to provide filenames as command-line arguments to the `rio polyencode` or `rio polydecode` tools. This is inherently possible as the tools are designed to take file paths as input.
- Source Code Analysis:
    - In the file `/code/rio_polyencode/scripts/cli.py`:
        - **`polyencode` function**:
            - `@click.argument("inputfiles", type=click.Path(resolve_path=True), ...)`: Defines `inputfiles` argument, which is a tuple of file paths.
            - `@click.argument("output", type=click.Path(resolve_path=True))`: Defines `output` argument, a file path.
            - `with rio.open(inputfiles[0]) as src:`: Opens the first input file using `rasterio.open()`.
            - `with rio.open(p) as src:`: Opens each input file in the `inputfiles` list using `rasterio.open()`.
            - `with rio.open(output, "w", **metaprof) as dst:`: Opens the output file for writing using `rasterio.open()`.
        - **`polydecode` function**:
            - `@click.argument("inputfile", type=click.Path(resolve_path=True), ...)`: Defines `inputfile` argument, a file path.
            - `@click.argument("output", type=click.Path(resolve_path=True))`: Defines `output` argument, a file path.
            - `with rio.open(inputfile) as src:`: Opens the input file using `rasterio.open()`.
            - `with rio.open(output, "w", **metaprof) as dst:`: Opens the output file for writing using `rasterio.open()`.
        - In both functions, the filenames from command-line arguments are directly passed to `rasterio.open()`.
        - There is no explicit sanitization or validation of these filenames before being used in `rio.open()`.
        - If `rasterio.open()` or the underlying GDAL library processes these filenames in a way that is vulnerable to shell injection (e.g., by passing them to system commands without proper escaping), then a malicious filename could lead to command execution.
- Security Test Case:
    - Pre-requisite: Have `rio-polyencode` installed and functional, and have a basic GeoTIFF file (e.g., `input.tif`) for testing.
    - Step 1: Create a malicious filename designed to execute a command. For example, create a filename string that includes a shell command injection attempt: `\"pwnedfile.tif; touch /tmp/pwned\"`. Note the quotes are important to pass the `;` as part of a single filename argument in many shells.
    - Step 2: Execute the `rio polydecode` command, providing the malicious filename as the input file argument and a valid output filename, along with a dummy X value. For example:
        ```bash
        rio polydecode "\"pwnedfile.tif; touch /tmp/pwned\"" output.tif 10
        ```
        Alternatively, try with `rio polyencode`:
        ```bash
        rio polyencode "\"pwnedfile.tif; touch /tmp/pwned\"" input2.tif output.tif
        ```
        (Assuming `input2.tif` is a valid dummy tif file if required by polyencode).
    - Step 3: After running the command, check if the file `/tmp/pwned` has been created.
    - Step 4: If the file `/tmp/pwned` exists, this confirms that the command injection was successful. This indicates a vulnerability where filenames are not properly sanitized, allowing for potential execution of arbitrary commands via maliciously crafted filenames.
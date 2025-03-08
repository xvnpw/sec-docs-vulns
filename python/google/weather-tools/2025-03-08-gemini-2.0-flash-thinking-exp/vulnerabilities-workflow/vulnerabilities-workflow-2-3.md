- vulnerability name: Local File System Path Traversal in `weather-dl` and `weather-mv` via Configuration File Injection
- description:
    1. An attacker crafts a malicious configuration file (e.g., `evil.cfg`).
    2. The attacker tricks a user into using `weather-dl` or `weather-mv` with the malicious configuration file as input, for example, by sending the `evil.cfg` to the user and instructing them to run `weather-dl evil.cfg` or `weather-mv --config evil.cfg`.
    3. The malicious configuration file contains a manipulated `target_path` or `--uris` parameter with path traversal sequences (e.g., `../`, `../../`) or absolute paths.
    4. When `weather-dl` or `weather-mv` processes this configuration, it uses the attacker-controlled path to download data to or move data from an arbitrary location on the user's local file system, outside of the intended project directory.
- impact:
    - **High**: Arbitrary File Write/Read. An attacker can potentially overwrite sensitive system files, write malicious executables to startup directories, or read sensitive local files by controlling the download or move destination. This can lead to arbitrary code execution on the user's machine or exposure of sensitive information.
- vulnerability rank: High
- currently implemented mitigations:
    - No specific input validation or sanitization is implemented for `target_path` in `weather-dl` or `--uris` in `weather-mv` based on the provided files. The tools rely on the user to provide safe configuration files.
- missing mitigations:
    - **Input Validation and Sanitization**: Implement robust validation and sanitization for file paths provided in the configuration files. This should include:
        - Restricting paths to a specific directory or a set of allowed directories.
        - Sanitizing paths to remove path traversal sequences (e.g., using `os.path.abspath` and checking if the resolved path is within allowed directories).
        - Avoiding direct use of user-provided paths in file system operations without validation.
    - **Principle of Least Privilege**: Document and encourage users to run the tools with minimal permissions to limit the impact of potential file system manipulation vulnerabilities.
- preconditions:
    - The user must download and execute `weather-dl` or `weather-mv` on their local machine.
    - The user must be tricked into using a maliciously crafted configuration file provided by the attacker.
- source code analysis:
    - **`weather_dl/weather-dl` and `weather_dl/download_pipeline/pipeline.py`**:
        - The `weather-dl` script takes a configuration file path as a command-line argument.
        - The `Configuration.md` and `README.md` documents mention that the `target_path` in the configuration file determines the download destination.
        - Source code for `weather-dl` and `download_pipeline` was not provided, but based on the documentation and common patterns for configuration-driven tools, it's highly likely that the `target_path` from the configuration file is directly used to construct file paths for downloads without sufficient validation.
    - **`weather_mv/weather-mv` and `weather_mv/README.md`**:
        - The `weather-mv` script takes `--uris` argument which specifies input file paths and `--output_table` which specifies BigQuery output table.
        - `weather-mv` also uses configuration files, although not explicitly shown in usage examples in `README.md`, the general architecture suggests configuration files could be used to control behavior, similar to `weather-dl`.
        - The `--uris` argument in `weather-mv` specifies the input file location, and if a configuration file were to control this, a malicious actor could manipulate this path.
        - Source code for `weather-mv` was not provided, but similar to `weather-dl`, it's likely that user-provided `--uris` or configuration-driven paths are used directly in file system operations, potentially leading to path traversal if not validated.
- security test case:
    1. **Setup:**
        - On an attacker machine, create a malicious configuration file `evil.cfg` for `weather-dl` with the following content:

        ```cfg
        [parameters]
        client=cds
        dataset=reanalysis-era5-pressure-levels
        target_path=../../../../tmp/evil_download.nc  # Path traversal to write to /tmp
        partition_keys=pressure_level
        [selection]
        product_type=reanalysis
        format=netcdf
        variable=temperature
        pressure_level=850
        year=2024
        month=05
        day=20
        time=12:00
        ```

        - On a victim machine, install `weather-tools` according to the `README.md`.
    2. **Execution:**
        - The attacker sends `evil.cfg` to the victim and instructs them to execute the following command in their `weather-tools` environment:
        ```bash
        weather-dl evil.cfg --local-run
        ```
    3. **Verification:**
        - After the command execution, check on the victim's machine if the file `evil_download.nc` was created in the `/tmp` directory (`/tmp/evil_download.nc`).
        - If the file exists in `/tmp`, the path traversal vulnerability is confirmed.
        - For `weather-mv`, a similar test case can be constructed by creating a malicious configuration or manipulating command-line arguments to control `--uris` and observe if `weather-mv` can be made to access files outside the intended input directory.
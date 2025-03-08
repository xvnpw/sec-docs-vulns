### Vulnerability List

- Vulnerability Name: Unvalidated GeoJSON Upload via `--no-validation` Flag

    - Description:
        1. A user is tricked into using the `tilesets-cli` tool with the `upload-source` or `add-source` command.
        2. The attacker persuades the user to include the `--no-validation` flag in the command.
        3. The user executes the command, intending to upload a GeoJSON file, but unknowingly bypassing client-side validation.
        4. The `tilesets-cli` skips the GeoJSON validation process due to the `--no-validation` flag.
        5. The crafted, potentially malicious GeoJSON file is uploaded to the Mapbox Tiling Service without being checked for validity or malicious content by the CLI.
        6. If the Mapbox Tiling Service is vulnerable to the specific type of malicious GeoJSON uploaded, it could lead to unexpected behavior or unintended actions on the Mapbox platform.

    - Impact:
        The impact of this vulnerability is medium. While the `tilesets-cli` itself might not be directly compromised, uploading unvalidated and potentially malicious GeoJSON data to the Mapbox Tiling Service could have several negative consequences:
        - Data corruption within the tileset source.
        - Unexpected behavior or errors in tileset processing and rendering.
        - Potential for exploiting vulnerabilities in the Mapbox Tiling Service's GeoJSON processing pipeline, if such vulnerabilities exist.
        - Depending on the nature of the malicious GeoJSON and backend vulnerabilities, it could potentially lead to more severe issues within the Mapbox ecosystem.
        The severity is limited by the dependency on vulnerabilities within the backend Mapbox Tiling Service and the need for user interaction to enable the `--no-validation` flag.

    - Vulnerability Rank: Medium

    - Currently Implemented Mitigations:
        - By default, the `upload-source` and `add-source` commands include client-side GeoJSON validation using schema validation and the `geojson` library. This validation is performed in the `utils.validate_geojson` function, which is called before uploading data, mitigating the risk of uploading invalid GeoJSON under normal circumstances.

    - Missing Mitigations:
        - **Stronger Warning for `--no-validation` Flag:** The CLI lacks a clear and prominent warning message when the `--no-validation` flag is used. A warning should be displayed to the user emphasizing the risks of bypassing validation and uploading potentially malicious or invalid data.
        - **Documentation Enhancement:** Improve documentation for the `--no-validation` flag, clearly outlining the security implications and risks associated with its use.

    - Preconditions:
        1. The attacker must convince a user to use the `tilesets-cli` tool.
        2. The user must be instructed or tricked into using the `upload-source` or `add-source` command with the `--no-validation` flag.
        3. The attacker must provide a maliciously crafted GeoJSON file to the user.
        4. Exploitation relies on potential vulnerabilities within the Mapbox Tiling Service's backend processing of GeoJSON data.

    - Source Code Analysis:
        - File: `/code/mapbox_tilesets/scripts/cli.py`
        - Function: `_upload_source`
        ```python
        def _upload_source(
            ctx, username, id, features, no_validation, quiet, replace, token=None, indent=None
        ):
            # ...
            with tempfile.TemporaryFile() as file:
                for index, feature in enumerate(features):
                    if not no_validation:
                        utils.validate_geojson(index, feature) # Vulnerability: Validation is skipped if no_validation is True
                    # ...
        ```
        - The code snippet clearly shows that the call to `utils.validate_geojson`, which performs GeoJSON validation, is conditionally executed based on the `no_validation` flag. When `--no-validation` is used, this validation step is skipped entirely.

    - Security Test Case:
        1. **Prepare a Malicious GeoJSON File:** Create a file named `malicious.geojson` with the following invalid GeoJSON content (missing "type" property in Feature):
            ```json
            {"geometry": {"type": "Point", "coordinates": [125.6, 10.1]}, "properties": {"name": "Dinagat Islands"}}
            ```
        2. **Attempt Upload with Validation (Expected Fail):** Run the `upload-source` command without the `--no-validation` flag. Replace `<your_mapbox_token>` with a valid Mapbox access token.
            ```bash
            tilesets upload-source testuser valid-source malicious.geojson --token <your_mapbox_token>
            ```
            Observe that the command fails and outputs a validation error message, indicating that the default validation is working as expected. The error message will indicate that the 'type' property is required.
        3. **Bypass Validation with `--no-validation` (Expected Success):** Run the `upload-source` command again, this time including the `--no-validation` flag.
            ```bash
            tilesets upload-source testuser bypass-source malicious.geojson --no-validation --token <your_mapbox_token>
            ```
            Observe that the command executes successfully and uploads the `malicious.geojson` file without any validation errors. The output will indicate a successful upload, even though the GeoJSON file is invalid.

        This test case confirms that the `--no-validation` flag in `upload-source` and `add-source` commands effectively bypasses the client-side GeoJSON validation, allowing for the upload of potentially malicious or invalid GeoJSON data.

- Vulnerability Name: Path Traversal in `validate-source` command

    - Description:
        1. A user executes the `tilesets validate-source` command, providing a file path as an argument.
        2. The `validate-source` command, through the `cligj.features_in_arg` decorator, attempts to open and read the file specified by the user-provided path.
        3. If the user provides a maliciously crafted file path, such as one starting with `../../`, the command will traverse directories outside of the intended working directory.
        4. This allows an attacker to read arbitrary files from the local file system of the user running the `tilesets` command, as the file opening operation is performed without sufficient path sanitization. For example, an attacker could read sensitive files like `/etc/passwd` by providing the path `../../../../etc/passwd` as an argument to `validate-source`.

    - Impact:
        - High: An attacker can read arbitrary files from the local file system where the `tilesets` command is executed. This can lead to the disclosure of sensitive information, including configuration files, private keys, or other user data.

    - Vulnerability Rank: High

    - Currently Implemented Mitigations:
        - None: There is no visible path sanitization or validation in the provided code snippets for the `validate-source` command. The command directly processes the path provided by the user.

    - Missing Mitigations:
        - Input validation and sanitization: The `validate-source` command should sanitize the input file path to prevent path traversal attacks. This can be achieved by:
            - Ensuring that the path is absolute and resolves within the intended working directory or a set of allowed directories.
            - Using functions that resolve paths safely, preventing traversal outside allowed directories (e.g., `os.path.abspath` and checking if it starts with an allowed base path).
            - Rejecting paths containing path traversal sequences like `../` or `..\\`.

    - Preconditions:
        - The attacker needs to trick a user into running the `tilesets validate-source` command with a malicious file path. This could be achieved through social engineering, phishing, or by convincing the user to process data from an untrusted source.
        - The user must have the `tilesets-cli` tool installed and configured.
        - The attacker must know or guess the path to the file they want to read on the user's system.

    - Source Code Analysis:
        - File: `mapbox_tilesets/scripts/cli.py`
        - Command: `validate_source`
        ```python
        @cli.command("validate-source")
        @cligj.features_in_arg
        def validate_source(features):
            """Validate your source file.
            $ tilesets validate-source <path/to/your/src/file>
            """
            click.echo("Validating features", err=True)

            for index, feature in enumerate(features):
                utils.validate_geojson(index, feature)

            click.echo("✔ valid")
        ```
        - The `@cligj.features_in_arg` decorator is used for the `validate_source` command. This decorator is responsible for handling the input argument, which is expected to be a file path.
        - The code directly passes the path argument to `cligj.features_in_arg` without any sanitization.
        - `cligj.features_in_arg` (from external library `cligj`, not in provided files, but assumed based on context) likely opens the file path provided as a command-line argument. If a malicious path like `../../../../etc/passwd` is provided, `cligj.features_in_arg` will attempt to open this path directly, leading to path traversal.
        - The subsequent loop iterates through features and calls `utils.validate_geojson`, but this function is for GeoJSON validation and not related to path traversal.

    - Security Test Case:
        1. **Precondition:** Ensure `mapbox-tilesets` CLI is installed and configured. Have a sensitive file accessible on the local file system, for example, `/etc/passwd` on Linux or `C:\Windows\win.ini` on Windows.
        2. **Craft a malicious path:** Create a path that traverses out of the expected directory to access the sensitive file. For example, if you are in your home directory, use `../../../../etc/passwd` (Linux) or `..\..\..\..\..\Windows\win.ini` (Windows).
        3. **Execute the `validate-source` command:** Run the command `tilesets validate-source ../../../../etc/passwd` (Linux) or `tilesets validate-source ..\..\..\..\..\Windows\win.ini` (Windows).
        4. **Observe the output:** If the vulnerability exists, the content of the sensitive file (e.g., `/etc/passwd` or `C:\Windows\win.ini`) will be printed to the standard output, or an error message indicating the file content could not be parsed as GeoJSON (but still attempting to open and read the file) will be shown. This confirms that the path traversal was successful and the tool attempted to read the targeted file.
        5. **Expected Result:** The content of `/etc/passwd` (or `C:\Windows\win.ini`) or error message implying file read should be displayed, demonstrating the path traversal vulnerability.

- Vulnerability Name: Improper handling of large coordinates in area estimation

    - Description:
        1. An attacker crafts a GeoJSON file containing features with extremely large coordinate values (e.g., longitude and latitude values exceeding reasonable geographic bounds, like 1e18).
        2. The attacker uses the `tilesets estimate-area` command, providing the crafted GeoJSON file as input along with a specified precision level (e.g., 10m).
        3. The `tilesets estimate-area` command processes the GeoJSON file, using the `supermercado` library to calculate the tiled area based on the provided features and precision.
        4. Due to the extremely large coordinate values in the GeoJSON, the area calculation within `supermercado` or the underlying numerical computations might become unstable or produce incorrect results. This could lead to a miscalculation of the estimated area.

    - Impact:
        - Incorrect area estimation for GeoJSON features with large coordinates.
        - This could lead to inaccurate reporting of tiled area, potentially impacting billing or resource allocation based on these estimations.
        - While not a direct code execution or data breach vulnerability, it undermines the reliability of the `estimate-area` command and could have financial implications if area estimations are used for billing purposes.

    - Vulnerability Rank: Medium

    - Currently Implemented Mitigations:
        - GeoJSON validation is performed by default using `jsonschema` and `geojson.is_valid` in the `validate_geojson` and `geojson_validate` functions within `mapbox_tilesets/utils.py`.
        - This validation checks for basic GeoJSON structure and validity, but it does not include specific checks for the range or magnitude of coordinate values.

    - Missing Mitigations:
        - Input sanitization and validation to enforce reasonable ranges for coordinate values in GeoJSON inputs before processing them in the `estimate-area` command.
        - Implement range checks or bounds validation for longitude (e.g., -180 to +180) and latitude (e.g., -90 to +90) values.
        - Enhance error handling within the `calculate_tiles_area` function in `mapbox_tilesets/utils.py` to gracefully handle potential numerical issues arising from extreme coordinate values, possibly by clipping or normalizing coordinates to valid geographic ranges before area calculation, or by implementing checks for NaN or infinite values in intermediate calculations.

    - Preconditions:
        - The attacker must have access to the `tilesets` CLI tool and be able to execute the `estimate-area` command.
        - The optional `estimate-area` dependencies, including `supermercado`, must be installed for the command to function.

    - Source Code Analysis:
        1. `mapbox_tilesets/scripts/cli.py`: The `estimate_area` command utilizes `cligj.features_in_arg` to process GeoJSON features from input files or stdin. It then calls `utils.calculate_tiles_area` to compute the area.
        2. `mapbox_tilesets/utils.py`: The `calculate_tiles_area` function uses the `supermercado.burntiles.burn` function to generate tiles and `_calculate_tile_area` to calculate the area of each tile.
        3. `_calculate_tile_area` performs area calculation using trigonometric functions (`np.sin`, `np.arctan`, `np.exp`) on tile coordinates, which are derived from the input feature coordinates. Extremely large coordinate values passed to these functions might lead to precision issues, overflow, or unexpected numerical results.
        4. The `validate_geojson` and `geojson_validate` functions in `mapbox_tilesets/utils.py` perform schema and GeoJSON validity checks, but these validations do not include checks on the magnitude or range of coordinate values within the GeoJSON geometries.

    - Security Test Case:
        1. Create a GeoJSON file named `large_coords.geojson` with the following content:
        ```json
        {"type": "FeatureCollection",
        "features": [
          {
            "type": "Feature",
            "geometry": {
              "type": "Point",
              "coordinates": [1e18, 1e18]
            },
            "properties": {}
          }
        ]
        }
        ```
        2. Open a terminal and execute the `estimate-area` command with the crafted GeoJSON file and 10m precision:
        ```bash
        tilesets estimate-area large_coords.geojson -p 10m
        ```
        3. Observe the output of the command. Check if the reported `km2` value is a reasonable geographic area or if it is an anomalously large number, zero, negative, or "NaN".
        4. Compare the output with the expected behavior when using a GeoJSON file with valid, geographically reasonable coordinates. If the area estimation is significantly skewed or results in an error, it confirms the vulnerability related to improper handling of large coordinates.
        5. (Optional) Repeat the test with different precision levels (e.g., 1m, 30cm, 1cm) and with the `--no-validation` flag to verify that the validation is not preventing the issue and that the problem lies within the area calculation logic when handling extreme coordinates.
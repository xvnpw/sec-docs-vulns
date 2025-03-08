* Vulnerability Name: Unvalidated GeoJSON Upload via `--no-validation` Flag

* Description:
    1. A user is tricked into using the `tilesets-cli` tool with the `upload-source` or `add-source` command.
    2. The attacker persuades the user to include the `--no-validation` flag in the command.
    3. The user executes the command, intending to upload a GeoJSON file, but unknowingly bypassing client-side validation.
    4. The `tilesets-cli` skips the GeoJSON validation process due to the `--no-validation` flag.
    5. The crafted, potentially malicious GeoJSON file is uploaded to the Mapbox Tiling Service without being checked for validity or malicious content by the CLI.
    6. If the Mapbox Tiling Service is vulnerable to the specific type of malicious GeoJSON uploaded, it could lead to unexpected behavior or unintended actions on the Mapbox platform.

* Impact:
    The impact of this vulnerability is medium. While the `tilesets-cli` itself might not be directly compromised, uploading unvalidated and potentially malicious GeoJSON data to the Mapbox Tiling Service could have several negative consequences:
    - Data corruption within the tileset source.
    - Unexpected behavior or errors in tileset processing and rendering.
    - Potential for exploiting vulnerabilities in the Mapbox Tiling Service's GeoJSON processing pipeline, if such vulnerabilities exist.
    - Depending on the nature of the malicious GeoJSON and backend vulnerabilities, it could potentially lead to more severe issues within the Mapbox ecosystem.
    The severity is limited by the dependency on vulnerabilities within the backend Mapbox Tiling Service and the need for user interaction to enable the `--no-validation` flag.

* Vulnerability Rank: Medium

* Currently Implemented Mitigations:
    - By default, the `upload-source` and `add-source` commands include client-side GeoJSON validation using schema validation and the `geojson` library. This validation is performed in the `utils.validate_geojson` function, which is called before uploading data, mitigating the risk of uploading invalid GeoJSON under normal circumstances.

* Missing Mitigations:
    - **Stronger Warning for `--no-validation` Flag:** The CLI lacks a clear and prominent warning message when the `--no-validation` flag is used. A warning should be displayed to the user emphasizing the risks of bypassing validation and uploading potentially malicious or invalid data.
    - **Documentation Enhancement:** Improve documentation for the `--no-validation` flag, clearly outlining the security implications and risks associated with its use.

* Preconditions:
    1. The attacker must convince a user to use the `tilesets-cli` tool.
    2. The user must be instructed or tricked into using the `upload-source` or `add-source` command with the `--no-validation` flag.
    3. The attacker must provide a maliciously crafted GeoJSON file to the user.
    4. Exploitation relies on potential vulnerabilities within the Mapbox Tiling Service's backend processing of GeoJSON data.

* Source Code Analysis:
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

* Security Test Case:
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
### Vulnerability List

- Vulnerability Name: Insecure Type Conversion in MTL Parsing
- Description:
    1. An attacker crafts a malicious Landsat 8 MTL text file.
    2. This file contains a specifically formatted string value within a metadata field that is expected to be a numerical type (integer or float).
    3. The attacker uses a carefully designed string that, when processed by the `_cast_to_best_type` function, is incorrectly converted to a float.
    4. This incorrect type conversion bypasses expected data type constraints in downstream calculations within `rio-toa`.
    5. The `parsemtl` command-line tool is used to parse this malicious MTL file.
    6. Subsequently, when other `rio-toa` commands (like `radiance`, `reflectance`, or `brighttemp`) utilize the parsed metadata, they may perform calculations based on the attacker-controlled, incorrectly typed value, leading to flawed or unexpected results in the generated TOA products.
- Impact:
    - Incorrect Top Of Atmosphere (TOA) calculations.
    - Generation of inaccurate or misleading Landsat 8 TOA products.
    - Potential for misuse of generated data in downstream applications relying on accurate TOA values.
- Vulnerability Rank: Medium
- Currently Implemented Mitigations:
    - None. The code attempts to cast strings to `int` and `float` but lacks validation or sanitization to prevent incorrect or malicious conversions.
- Missing Mitigations:
    - Input validation for MTL file content, specifically checking data types and formats against expected schemas.
    - Sanitization of input strings before type conversion to prevent unexpected behavior during casting.
    - Explicit type checking and validation in functions that consume parsed MTL data to ensure expected data types are used in calculations.
- Preconditions:
    - The attacker needs to be able to provide a malicious Landsat 8 MTL text file to the `parsemtl` command-line tool. This could be achieved if the tool is used in an environment where users can supply their own MTL files, for example, in a web service or a workflow processing user-uploaded data.
- Source Code Analysis:
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
    - **Vulnerability Point**: The float conversion is performed without any validation or sanitization of the input `data` string. An attacker can craft a string that is successfully converted to a float but represents an unexpected or malicious value. For example, a string like `"1.0e5"` would be parsed as a valid float, but it might be outside the expected range or precision for certain metadata parameters, leading to issues in calculations. Or more maliciously crafted strings might be designed to cause unexpected behavior in floating point operations in downstream code.
    - Function: `_parse_mtl_txt(mtltxt)`
    ```python
    def _parse_mtl_txt(mtltxt):
        # ...
        for g in map(str.lstrip, group):
            # ...
            else:
                k, d = _parse_data(g) # Calls _parse_data, which calls _cast_to_best_type
                if k:
                    k = u'{}'.format(k)
                    output[-1]['data'][k] = d
        return output[0]['data']
    ```
    - The `_parse_mtl_txt` function parses the MTL text content line by line and uses `_parse_data` to extract key-value pairs. `_parse_data` then calls `_cast_to_best_type` to convert the value to its "best" type.
    - File: `/code/rio_toa/scripts/cli.py`
    - Command: `parsemtl(mtl)`
    ```python
    @click.command('parsemtl')
    @click.argument('mtl', default='-', required=False)
    def parsemtl(mtl):
        """Converts a Landsat 8 text MTL
        to JSON
        """
        try:
            mtl = str(click.open_file(mtl).read()) # Reads MTL file content
        except IOError:
            mtl = str('\n'.join([inputtiles]))

        click.echo(json.dumps(_parse_mtl_txt(mtl))) # Parses MTL and outputs JSON
    ```
    - The `parsemtl` command reads the MTL file content and uses `_parse_mtl_txt` to parse it into a JSON format, which is then outputted to stdout. This output is then used by other `rio-toa` commands.

- Security Test Case:
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
    3. Execute the `rio toa brighttemp` command using a sample TIF file and the maliciously crafted MTL JSON file. Redirect output to a file to check results.
    ```bash
    rio toa brighttemp tests/data/tiny_LC81390452014295LGN00_B10.TIF malicious_mtl.json /tmp/bt_malicious.tif
    ```
    4. Compare the output `/tmp/bt_malicious.tif` with a baseline output generated using a clean MTL file. Observe if the brightness temperature calculation is significantly different or produces errors due to the manipulated `K1_CONSTANT_BAND_10` value. For example, check for `NaN` values or extreme temperature values in the output raster, which would indicate a problem caused by the insecure type conversion.
    5. Analyze the output raster for anomalies. If the malicious MTL leads to unexpected or incorrect brightness temperature values, it confirms the vulnerability. For instance, with a very large K1 value, the brightness temperature calculation might result in extremely low or `NaN` values, depending on how the formula handles such inputs.

This test case demonstrates how a maliciously crafted MTL file can influence calculations in `rio-toa` due to insecure type conversion during MTL parsing.
- Vulnerability name: Uncontrolled Numerical Parameters in Color Operations
- Description:
    - An attacker can provide a crafted `rio color` command.
    - The command includes color operations like `gamma` or `sigmoidal` with extremely large numerical parameters (e.g., gamma value of 1000000, or sigmoidal contrast of 10000).
    - The `rio color` command processes these parameters using `rio_color.operations.parse_operations` and applies the corresponding color operation functions (`gamma`, `sigmoidal`).
    - Due to the lack of input validation for the magnitude of these numerical parameters in `rio_color.operations.py`, the underlying numerical computation in `gamma` and `sigmoidal` functions is performed with these extreme values.
    - For extremely large gamma values, the output image may become almost uniformly white (or very close to 1.0 when scaled to 0-1 range), effectively losing image detail.
    - For extremely large contrast values in sigmoidal adjustment, the output image may become binarized or exhibit extreme contrast enhancement, losing image detail and potentially leading to visually distorted or unusable output.
    - This can be triggered by an external attacker by crafting a command line input to `rio color`.
- Impact:
    - Loss of image detail and quality in the output raster.
    - Generation of visually distorted or unusable output images.
    - Potential misrepresentation of geospatial data due to extreme color manipulation.
    - While not a crash or denial of service, it is unexpected and undesirable behavior that can be exploited to manipulate image output in a harmful way.
- Vulnerability rank: Medium
- Currently implemented mitigations:
    - Input validation for gamma value being positive and not NaN in `rio_color/operations.py:gamma`.
    - Input validation for bias being between 0 and 1 in `rio_color/operations.py:sigmoidal`.
    - Input array value range validation (0-1) in `rio_color/operations.py:sigmoidal` and `rio_color/operations.py:gamma`.
    - Parsing and validation of operation strings format in `rio_color/scripts/cli.py:color` and `rio_color/operations.py:parse_operations`.
    - These mitigations prevent some types of invalid inputs, but do not restrict the magnitude of valid numerical parameters like gamma and contrast.
- Missing mitigations:
    - Range validation for numerical parameters like `gamma` and `contrast` to prevent excessively large or small values that lead to undesirable image processing outcomes.
    - Define reasonable and safe ranges for these parameters and enforce them in `rio_color/operations.py:parse_operations` or within the operation functions themselves. For example, limit gamma to a reasonable range like [0.1, 10] and contrast to a range like [-100, 100].
- Preconditions:
    - Attacker has access to the `rio color` command-line tool.
    - Attacker can provide a source raster image and specify operation strings with extreme numerical parameters.
- Source code analysis:
    - `rio_color/operations.py:gamma(arr, g)`: Lacks validation for maximum value of `g`. Large `g` will result in `1.0/g` approaching 0, and `arr ** (1.0 / g)` approaching 1.
    - `rio_color/operations.py:sigmoidal(arr, contrast, bias)`: Lacks validation for the magnitude of `contrast`. Large positive `contrast` values will lead to image binarization effect.
    - `rio_color/operations.py:parse_operations(ops_string)`: Parses operation strings and converts arguments to float. No range validation is performed on these float values.
    - `rio_color/scripts/cli.py:color`: Calls `parse_operations` for validation of the operations string format, but not for the range of numerical arguments. Uses `color_worker` which eventually calls `gamma` and `sigmoidal` with user-provided parameters.
- Security test case:
    - Test for large Gamma:
        ```bash
        rio color tests/rgb8.tif output_gamma_large.tif gamma rgb 1000000
        ```
        - Expected result: Output image `output_gamma_large.tif` will be almost uniformly white, losing image detail.
        - Verify visually or by checking pixel value distribution (histogram).
    - Test for large Sigmoidal Contrast:
        ```bash
        rio color tests/rgb8.tif output_sigmoidal_large_contrast.tif sigmoidal rgb 10000 0.5
        ```
        - Expected result: Output image `output_sigmoidal_large_contrast.tif` will be binarized or have extreme contrast enhancement, losing image detail and appearing visually distorted.
        - Verify visually or by checking pixel value distribution.
    - Missing Security Test Case: Add test cases in `tests/test_cli.py` that specifically test extreme values for gamma and sigmoidal contrast using `rio color` command-line tool. These tests should verify that the output image is as expected (degraded, binarized) and not causing crashes or other unexpected errors, but ideally, the tool should prevent such extreme parameters.
- Vulnerability name: Path Traversal in DST_PATH parameter
- Description:
    1. The `rio-toa` command-line interface (CLI) allows users to specify an output file path (`DST_PATH`) for processed Landsat 8 imagery using `radiance`, `reflectance`, and `brighttemp` commands.
    2. The application directly uses the provided `DST_PATH` to create and write output files without proper validation or sanitization.
    3. An attacker can craft a malicious `DST_PATH` containing path traversal sequences like `../` to write files to arbitrary locations outside the intended output directory.
    4. For example, by using a `DST_PATH` like `../../../evil.tif`, an attacker can instruct the application to write the output file `evil.tif` several directories above the current working directory.
- Impact:
    - Arbitrary File Write: An attacker can write files to locations outside the intended output directory.
    - Potential for Information Disclosure, Code Execution, and Data Tampering: By writing to arbitrary locations, an attacker could potentially overwrite critical system files, configuration files, or executable files. This could lead to various malicious outcomes, including gaining unauthorized access, executing arbitrary code, or corrupting system data.
- Vulnerability rank: High
- Currently implemented mitigations:
    - None. The application does not perform any validation or sanitization of the `DST_PATH` parameter.
- Missing mitigations:
    - Input validation and sanitization for `DST_PATH`: The application should validate and sanitize the `DST_PATH` to prevent path traversal attacks. This can be achieved by:
        - Converting the user-provided `DST_PATH` to an absolute path using `os.path.abspath`.
        - Normalizing the path using `os.path.normpath` to remove redundant separators and path traversal components.
        - Validating that the normalized absolute path is within the intended output directory or a set of allowed directories.
- Preconditions:
    - The attacker needs to be able to execute the `rio-toa` CLI commands (`radiance`, `reflectance`, or `brighttemp`) and control the `DST_PATH` parameter. This is typically the case for users who have access to the command-line interface of the system where `rio-toa` is installed.
- Source code analysis:
    1. File: `rio_toa/scripts/cli.py`
    2. Commands `radiance`, `reflectance`, and `brighttemp` are defined using `click` and accept `dst_path` as an argument.
    3. Example from `radiance` command:
    ```python
    @click.command('radiance')
    @click.argument('src_path', type=click.Path(exists=True))
    @click.argument('src_mtl', type=click.Path(exists=True))
    @click.argument('dst_path', type=click.Path(exists=False)) # dst_path argument
    ...
    def radiance(ctx, src_path, src_mtl, dst_path, ...):
        ...
        calculate_landsat_radiance(src_path, src_mtl, dst_path, ...) # dst_path passed to calculate_landsat_radiance
    ```
    4. Similar pattern exists for `reflectance` and `brighttemp` commands, passing `dst_path` to `calculate_landsat_reflectance` and `calculate_landsat_brightness_temperature` respectively.
    5. File: `rio_toa/radiance.py` (and similarly for `rio_toa/reflectance.py` and `rio_toa/brightness_temp.py`)
    6. In `calculate_landsat_radiance` function, the `dst_path` is directly used in `riomucho.RioMucho`:
    ```python
    def calculate_landsat_radiance(src_path, src_mtl, dst_path, ...):
        ...
        with riomucho.RioMucho([src_path],
                               dst_path, # dst_path is used directly
                               _radiance_worker,
                               options=dst_profile,
                               global_args=global_args) as rm:
            rm.run(processes)
    ```
    7. `riomucho.RioMucho` internally uses `rasterio.open` to create the output file at the specified `dst_path`.
    8. `rasterio.open` and the underlying GDAL library do not inherently prevent path traversal if a malicious path is provided.
    9. No path validation or sanitization is performed on `dst_path` in `rio-toa` code before it is used by `rasterio.open`.
- Security test case:
    1. Create a temporary directory named `test_rio_toa_traversal`.
    2. Navigate into this directory: `cd test_rio_toa_traversal`.
    3. Create a subdirectory named `output_dir`: `mkdir output_dir`.
    4. Navigate into `output_dir`: `cd output_dir`.
    5. Execute the `rio toa radiance` command with a path traversal payload for `DST_PATH`. Assuming `rio-toa` is installed and available in your PATH, and using test data from the repository:
    ```bash
    rio toa radiance ../../../code/tests/data/tiny_LC80100202015018LGN00_B1.TIF ../../../code/tests/data/LC80100202015018LGN00_MTL.json ../evil_traversal.tif
    ```
    6. Navigate back to the temporary directory `test_rio_toa_traversal`: `cd ..`.
    7. Verify if the file `evil_traversal.tif` has been created in `test_rio_toa_traversal` directory. You should find the file in `test_rio_toa_traversal` directory, indicating successful path traversal because the intended output directory was `test_rio_toa_traversal/output_dir`, but the file was written one level up.
    8. Clean up the temporary directory `test_rio_toa_traversal` and the created `evil_traversal.tif` file.
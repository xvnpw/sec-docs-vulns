- Vulnerability name: Input Data Injection leading to Forecast Manipulation
- Description:
    - An attacker can craft malicious input data within NetCDF files provided to the `inference.py` script.
    - This manipulation can involve altering weather observation data, satellite imagery, or HRRR forecast data within these files.
    - By injecting this malicious data, the attacker can influence the ADAF model to generate incorrect or misleading weather forecasts.
    - The `inference.py` script reads these NetCDF files using the `read_sample_file_and_norm_input` function, which in turn uses `xr.open_dataset` to parse the file.
    - The system then proceeds with data normalization and model inference without any explicit validation or sanitization of the input data.
    - This lack of validation allows malicious data to directly impact the model's computations and the resulting forecasts.
- Impact:
    - Generation of incorrect or misleading weather forecasts.
    - Misleading public weather alerts, potentially causing inappropriate responses to weather events.
    - Incorrect operational decisions in weather-sensitive sectors such as aviation, agriculture, and emergency services, leading to financial losses, safety risks, or inefficient resource allocation.
    - Damage to the reputation and trust in the forecasting system and the organizations relying on it.
- Vulnerability rank: High
- Currently implemented mitigations:
    - Data Normalization: Input data is normalized using pre-computed statistics as seen in `utils/data_loader_multifiles.py`. This is intended for data processing, not as a security mitigation, and does not prevent malicious data injection.
    - File Format: The use of NetCDF, a binary data format, provides a limited level of implicit protection against simple text-based injection attempts, but it is not designed as a security feature.
- Missing mitigations:
    - Input Validation: The system lacks input validation to check the integrity, format, and expected ranges of data read from NetCDF files. This includes verifying data types, value ranges, and consistency with expected schemas.
    - Anomaly Detection: There are no anomaly detection mechanisms to identify unusual or suspicious patterns in the input data that could signal malicious manipulation. This could include statistical checks for outliers or unexpected data distributions.
    - Data Integrity Checks: The project does not implement data integrity checks such as checksums or digital signatures to ensure the authenticity and integrity of the input data files, and to verify that they have not been tampered with.
- Preconditions:
    - The attacker needs the ability to create or modify NetCDF input files that are subsequently processed by the `inference.py` script.
    - In a real-world scenario, this could involve compromising data feeds, intercepting data transmissions, or gaining access to systems where input data is stored or generated.
    - For a test scenario, the attacker can create a modified NetCDF file locally and provide its path to the inference script.
- Source code analysis:
    - File: `/code/inference.py`
        - Function: `read_sample_file_and_norm_input(params, file_path, hold_out_obs_ratio=0.2)`
            ```python
            ds = xr.open_dataset(file_path, engine="netcdf4")
            ```
            - The code directly opens and reads data from the provided NetCDF file path without any prior validation of the file's contents or structure.
            - It extracts data variables based on configuration parameters like `params.inp_hrrr_vars`, `params.inp_obs_vars`, `params.inp_satelite_vars`, and `params.field_tar_vars`.
            - The extracted data is then normalized using functions like `min_max_norm_ignore_extreme_fill_nan`.
            - **Vulnerability:** The lack of input validation at this stage means that if a malicious NetCDF file is provided, the system will process it as if it were legitimate data. An attacker can inject arbitrary numerical values or manipulate existing data within the NetCDF structure, which the system will then normalize and feed into the model.

    - File: `/code/utils/data_loader_multifiles.py`
        - Function: `_min_max_norm_ignore_extreme_fill_nan(self, data, vmin, vmax)`
        - Function: `_min_max_norm(data, vmin, vmax)` (if used based on config - not in current config)
            - These normalization functions, while correctly implementing normalization, operate on the data provided to them without questioning its validity or source.
            - If malicious data is provided, these functions will normalize the malicious data just as they would with legitimate data, thus propagating the malicious input further into the system.

    - File: `/code/inference.py`
        - Function: `inference(...)`
            ```python
            inp = torch.tensor(inp[np.newaxis, :, :, :]).to(device, dtype=torch.float)
            inp_sate_norm = torch.tensor(inp_sate_norm[np.newaxis, :, :, :, :]).to(device, dtype=torch.float)
            # ...
            gen = model(inp) # or gen = model(inp, inp_sate)
            ```
            - The normalized input data (`inp`, `inp_sate_norm`) is converted to PyTorch tensors and directly fed into the ADAF model for inference.
            - The model itself, defined in `/code/models/encdec.py`, is designed for weather forecasting and does not include any input sanitization or validation logic. It processes the numerical input it receives as intended data.

        - Visualization:
        ```
        [Malicious NetCDF File] --> (/code/inference.py) read_sample_file_and_norm_input --> [Unvalidated & Normalized Malicious Data] --> [ADAF Model] --> [Manipulated Weather Forecast Output]
        ```
- Security test case:
    1. Prepare Malicious NetCDF File:
        - Locate a valid test NetCDF input file in the `./data/test/` directory. For example, use `2022-10-01_00.nc`.
        - Use a tool like `ncdump` to inspect the structure and data of the NetCDF file:
          ```bash
          ncdump -h /code/data/test/2022-10-01_00.nc > original_header.cdl
          ncdump -v sta_t /code/data/test/2022-10-01_00.nc > original_data.txt # Example for sta_t variable
          ```
        - Modify the `sta_t` variable within the NetCDF file to inject malicious data. For example, set all `sta_t` values to an unrealistically high temperature like 373.15 (100 degrees Celsius) across all locations and time windows. You can use `ncgen` and `nco` tools or Python libraries like `netCDF4` to modify the NetCDF file.
        - Example using `netCDF4` in Python:
          ```python
          import netCDF4
          import numpy as np
          file_path = '/code/data/test/2022-10-01_00.nc'
          dataset = netCDF4.Dataset(file_path, 'r+')
          sta_t_var = dataset.variables['sta_t']
          sta_t_var[:] = 373.15 # Set all sta_t values to 373.15 K (100 C)
          dataset.close()
          print(f"Modified {file_path} by setting sta_t to 373.15K")
          ```
        - Save the modified NetCDF file, overwriting the original or saving it as a new file (e.g., `malicious_2022-10-01_00.nc`).

    2. Run Inference with Malicious Input:
        - Execute the `inference.py` script, pointing `--test_data_path` to the directory containing the modified NetCDF file. If you created a new file, ensure only the malicious file is in the test data path, or adjust the script to target the specific malicious file.
          ```bash
          export CUDA_VISIBLE_DEVICES='0' # or appropriate GPU device
          nohup python -u inference.py \
              --seed=0 \
              --exp_dir='./exp/' \
              --test_data_path='./data/test' \ # or path to directory with malicious file
              --net_config='EncDec' \
              --hold_out_obs_ratio=0.3 \
              > malicious_inference.log 2>&1 &
          ```
          Note: If you replaced the original file, ensure you have a backup. If you created a new malicious file, you might need to adjust the `inference.py` script or the test data path to ensure it processes this specific file. For simplicity in this test case, we assume you've replaced the original test file.

    3. Analyze the Output Forecasts:
        - After inference completes, examine the output NetCDF file generated in the experiment directory (e.g., `./exp/inference_ensemble_*_hold_*/2022-10-01_00.nc`).
        - Open the output NetCDF file and visualize or analyze the predicted variables, particularly `ai_gen_t` (generated temperature).
        - Compare the predicted temperature (`ai_gen_t`) with the background HRRR temperature (`bg_hrrr_t`) and the RTMA target temperature (`rtma_t`) within the output file.
        - Check if the injected high temperature values in `sta_t` have influenced the generated forecast, causing `ai_gen_t` to show unrealistically high temperatures, especially in regions where station observations are influential.
        - Compare these forecasts to those generated using the original, unmodified input file to clearly demonstrate the impact of the malicious data injection.

    4. Verify Vulnerability:
        - If the generated forecast (`ai_gen_t`) shows a significant and unrealistic increase in temperature due to the injected malicious `sta_t` data, and this deviation is clearly attributable to the manipulated input, then the Input Data Injection vulnerability is confirmed.
        - For example, if `ai_gen_t` displays temperatures close to or above 100 degrees Celsius in areas where such temperatures are not meteorologically plausible given the background HRRR and target RTMA data, and this is a direct result of the injected 100-degree station data, the vulnerability is validated.
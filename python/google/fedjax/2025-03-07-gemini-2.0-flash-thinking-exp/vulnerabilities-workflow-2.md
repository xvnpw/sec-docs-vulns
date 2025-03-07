## Vulnerability Report

The following vulnerabilities were identified in the dataset build scripts.

### Vulnerability 1: Data Poisoning via Compromised Datasets

- **Vulnerability Name:** Data Poisoning via Compromised Datasets
- **Description:** The `build_dataset.sh` scripts download datasets from external URLs using `wget` and process them. If these URLs are compromised or subject to man-in-the-middle attacks, malicious datasets can be downloaded and processed. This can poison the training data used in FedJAX simulations.
    - **Step-by-step trigger:**
        1. An attacker compromises the external server hosting the dataset files or performs a man-in-the-middle attack during the download process.
        2. The user executes the `build_dataset.sh` script which uses `wget` to download the dataset from the compromised URL.
        3. The script proceeds to process the downloaded malicious dataset and uses it for FedJAX simulations.
- **Impact:** An attacker can inject malicious data into the datasets used for federated learning simulations. This can lead to data poisoning attacks, compromising the integrity of the trained models. The trained models may exhibit biased or incorrect behavior, leading to unreliable research outcomes.
- **Vulnerability Rank:** High
- **Currently Implemented Mitigations:** None in the `build_dataset.sh` scripts to verify the integrity of downloaded files beyond basic TLS provided by `wget`. For `sent140` dataset, `--no-check-certificate` flag is used which weakens even TLS protection.
- **Missing Mitigations:**
    - Implement integrity checks for downloaded files using checksums (e.g., SHA256) against known good values. These checksums should be stored securely and verified before dataset processing.
    - Enforce HTTPS for all downloads to prevent man-in-the-middle attacks and ensure encrypted communication channels.
    - Implement robust input validation in the Python scripts (`data_to_sqlite.py`) to detect and reject potentially malicious data entries before they are incorporated into the datasets. This validation should go beyond basic normalization and include checks for anomalies or patterns indicative of poisoning attempts.
- **Preconditions:**
    - The user must execute the `build_dataset.sh` script to download and process a dataset.
    - The attacker must be able to compromise the external URLs where datasets are downloaded from or perform a man-in-the-middle attack.
    - The Python processing scripts must lack sufficient input validation to detect and reject malicious data.
- **Source Code Analysis:**
    - **`fedjax/datasets/scripts/cornell_movie_dialogs/build_dataset.sh`:**
        ```bash
        wget "http://www.cs.cornell.edu/~cristian/data/cornell_movie_dialogs_corpus.zip" \
            -O "${data_dir}/cornell.zip"
        python3 data_to_sqlite.py --corpus_zip_path="${data_dir}/cornell.zip" \
            --db_path="${output_dir}/dataset.sqlite"
        ```
        The script downloads `cornell_movie_dialogs_corpus.zip` from `http://www.cs.cornell.edu/~cristian/data/cornell_movie_dialogs_corpus.zip` using `wget`. There is no verification of the downloaded file's integrity.
    - **`fedjax/datasets/scripts/sent140/build_dataset.sh`:**
        ```bash
        wget --no-check-certificate \
            http://cs.stanford.edu/people/alecmgo/trainingandtestdata.zip \
            -O "${tmp_dir}/trainingandtestdata.zip"
        python3 data_to_sqlite.py --corpus_zip_path="${tmp_dir}/trainingandtestdata.zip" \
            --db_path="${output_dir}/dataset.sqlite"
        ```
        The script downloads `trainingandtestdata.zip` from `http://cs.stanford.edu/people/alecmgo/trainingandtestdata.zip` using `wget --no-check-certificate`, which disables SSL certificate verification, making man-in-the-middle attacks easier.  Again, no integrity checks are performed on the downloaded file.
    - In both cases, the downloaded zip files are directly processed by `data_to_sqlite.py` without any checks for malicious content. The `data_to_sqlite.py` scripts might perform some normalization, but they lack comprehensive input validation to prevent data poisoning.
- **Security Test Case:**
    1. **Setup:**
        - Host a malicious zip file at `http://localhost:8000/malicious_dataset.zip`. This zip file contains a modified dataset (e.g., `dataset.sqlite`) designed to poison a federated learning model. For example, in a sentiment analysis dataset, you could flip the labels for a subset of reviews to skew the model's sentiment classification.
        - Modify `fedjax/datasets/scripts/cornell_movie_dialogs/build_dataset.sh` to download the malicious zip file from `http://localhost:8000/malicious_dataset.zip` instead of the original URL.  Start a simple HTTP server in your local directory using `python -m http.server 8000`.
    2. **Execution:**
        - Run the modified `build_dataset.sh` script: `sh build_dataset.sh -d /tmp/poisoned_cornell -o /tmp/poisoned_cornell`
        - Run a FedJAX federated learning simulation using the generated dataset located in `/tmp/poisoned_cornell/dataset.sqlite`.
    3. **Verification:**
        - Train a FedJAX model on both the poisoned dataset and the original, clean dataset.
        - Evaluate the performance of both models on a clean, held-out test set.
        - Compare the models' behavior, specifically looking for signs of data poisoning. For example, in sentiment analysis, check if the model trained on the poisoned data shows a bias towards incorrect sentiment classification on the poisoned data labels. Measure accuracy and potentially other metrics relevant to the task to quantify the impact of the poisoning. A significant degradation in performance or a noticeable bias in the poisoned model compared to the clean model confirms the vulnerability.


### Vulnerability 2: Command Injection in dataset build scripts

- **Vulnerability Name:** Command Injection in dataset build scripts
- **Description:** The `build_dataset.sh` scripts for `cornell_movie_dialogs` and `sent140` datasets use `wget` to download data and `unzip` to extract archives. These scripts use user-provided directories as input via flags `-d` (data directory), `-o` (output directory), and `-t` (temporary directory). If a malicious user can control the download URL (by compromising the original source or through redirection) or provide maliciously crafted zip files, they could potentially achieve command injection or directory traversal during the `unzip` operation. Specifically, a malicious zip archive could be crafted to exploit path traversal vulnerabilities in `unzip`, allowing files to be written outside the intended directories.
    - **Step-by-step trigger:**
        1. An attacker compromises the external server hosting the dataset zip file or sets up a malicious server.
        2. The user executes the `build_dataset.sh` script, which downloads a malicious zip file from the compromised source.
        3. The `build_dataset.sh` script uses `unzip` to extract the contents of the downloaded zip file directly into a directory specified by user-provided flags.
        4. A maliciously crafted zip archive containing path traversal sequences (e.g., filenames like `../../../tmp/evil.sh`) is extracted by `unzip`.
        5. This can lead to arbitrary file creation or overwriting outside the intended data directory, potentially including execution of malicious code if an executable file is placed in a location like `/tmp/` or a user's home directory and then executed.
- **Impact:** High: Arbitrary command execution on the system running the build script. If an attacker can successfully inject commands, they can gain full control over the researcher's environment, potentially stealing data, installing malware, or disrupting research activities.
- **Vulnerability Rank:** High
- **Currently Implemented Mitigations:** None. The scripts directly use shell commands like `wget` and `unzip` without any input sanitization, URL validation, archive inspection, or sandboxing.
- **Missing Mitigations:**
    - **Input Sanitization:** Carefully validate and sanitize user-provided directory paths (`data_dir`, `output_dir`, `tmp_dir`) to prevent path traversal vulnerabilities during `unzip`. Ensure that paths are canonical and within expected boundaries.
    - **URL Validation:** Implement checks to validate the download URLs against a whitelist of trusted sources or use a more secure download mechanism that includes integrity checks and source verification.
    - **Archive Inspection:** Before extracting archives using `unzip`, inspect their contents to prevent directory traversal or malicious file overwriting. Tools or libraries for inspecting zip archive contents programmatically could be used to identify and reject archives containing suspicious paths.
    - **Sandboxing:** Run dataset build scripts in a sandboxed environment (e.g., using containers or virtual machines) to limit the potential impact of command injection or malicious archive extraction. This would restrict the attacker's ability to harm the host system even if command injection is successful.
    - **Hash Verification:** Verify the integrity of downloaded files using checksums (e.g., SHA256) to ensure they haven't been tampered with during transit. This can detect if a downloaded zip file has been replaced by a malicious one.
- **Preconditions:**
    - The user must execute the `build_dataset.sh` script for either the `cornell_movie_dialogs` or `sent140` dataset.
    - The attacker must be able to compromise the download URL to serve malicious content or craft a malicious zip archive.
- **Source Code Analysis:**
    - **`fedjax/datasets/scripts/cornell_movie_dialogs/build_dataset.sh`:**
        ```bash
        unzip "${data_dir}/cornell.zip" -d "${data_dir}"
        ```
    - **`fedjax/datasets/scripts/sent140/build_dataset.sh`:**
        ```bash
        unzip "${tmp_dir}/trainingandtestdata.zip" -d "{$tmp_dir}"
        ```
    - In both scripts, the `unzip` command is used to extract zip archives directly into user-specified directories (`data_dir` or `tmp_dir`). If a malicious zip file is downloaded (either through URL compromise or redirection), and it contains entries with path traversal sequences, `unzip` will extract files outside the intended directories. For example, a file named `../../../tmp/evil.txt` inside the zip would be extracted to `/tmp/evil.txt` on the system.
- **Security Test Case:**
    1. **Step 1:** Create a malicious zip file named `malicious.zip`. This zip file should contain a file with a path that exploits directory traversal when extracted. For example, use the `zip` command in Linux: `zip malicious.zip ../../../tmp/evil.txt`. Inside `evil.txt` put some harmless content like `Vulnerable`.
    2. **Step 2:** Host `malicious.zip` on a local HTTP server. You can use `python -m http.server 8000` in the directory containing `malicious.zip`. The malicious URL will be `http://localhost:8000/malicious.zip`.
    3. **Step 3:** Modify the `build_dataset.sh` script (e.g., `fedjax/datasets/scripts/cornell_movie_dialogs/build_dataset.sh`) to download from your malicious server. Change the `wget` command to:
        ```bash
        wget "http://localhost:8000/malicious.zip" -O "${data_dir}/cornell.zip"
        ```
    4. **Step 4:** Run the modified `build_dataset.sh` script:
        ```bash
        sh build_dataset.sh -d /tmp/test_cornell -o /tmp/test_cornell
        ```
    5. **Step 5:** After the script execution, check if the file `evil.txt` has been created in the `/tmp/` directory. Run `cat /tmp/evil.txt`. If the content `Vulnerable` is displayed, it confirms successful directory traversal and command injection vulnerability through malicious zip file and `unzip`.
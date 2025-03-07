- vulnerability name: Command Injection in dataset build scripts

- description:
  - The `build_dataset.sh` scripts for `cornell_movie_dialogs` and `sent140` datasets use `wget` to download data from external URLs and `unzip` to extract archives.
  - These scripts take user-provided directories as input via flags `-d` (data directory), `-o` (output directory), and `-t` (temporary directory).
  - If a malicious user can control the download URL or somehow inject commands into the `build_dataset.sh` script's execution environment (though less likely in this context, focusing on URL and directory control), they could potentially execute arbitrary commands on the system running the script. More realistically, if the download URL redirects to a malicious site, the downloaded and executed script could be harmful.
  - In `cornell_movie_dialogs/build_dataset.sh`, the script downloads a zip file and unzips it directly into a user-provided directory using `unzip "${data_dir}/cornell.zip" -d "${data_dir}"`. If the zip file is maliciously crafted, it could potentially lead to directory traversal during extraction, writing files outside of the intended output directory.
  - Similar situation exists in `sent140/build_dataset.sh` with `unzip "${tmp_dir}/trainingandtestdata.zip" -d "{$tmp_dir}"`.

- impact:
  - High: Arbitrary command execution on the system running the build script. In the context of a researcher using FedJAX for simulation, this could lead to complete compromise of their research environment if they run the dataset build scripts on a compromised dataset URL.

- vulnerability rank: high

- currently implemented mitigations:
  - None: The scripts directly use shell commands like `wget` and `unzip` without input sanitization or security checks on the downloaded data or URLs.

- missing mitigations:
  - Input sanitization: Validate and sanitize user-provided directory paths to prevent path traversal during `unzip`.
  - URL validation: Implement checks to validate the download URLs against a whitelist or use a safer download mechanism.
  - Archive inspection: Before extracting archives, inspect their contents to prevent directory traversal or malicious file overwriting.
  - Sandboxing: Run dataset build scripts in a sandboxed environment to limit the impact of potential command injection or malicious archive extraction.
  - Hash verification: Verify the integrity of downloaded files using checksums to ensure they haven't been tampered with.

- preconditions:
  - User must execute the `build_dataset.sh` script for either `cornell_movie_dialogs` or `sent140` dataset.
  - Attacker must be able to compromise the download URL to serve malicious content or craft a malicious zip archive.

- source code analysis:
  - **`fedjax/datasets/scripts/cornell_movie_dialogs/build_dataset.sh`:**
    ```bash
    wget "http://www.cs.cornell.edu/~cristian/data/cornell_movie_dialogs_corpus.zip" \
        -O "${data_dir}/cornell.zip"

    unzip "${data_dir}/cornell.zip" -d "${data_dir}"

    mv "${data_dir}/cornell movie-dialogs corpus" "${data_dir}/cornell_dataset"
    ```
    - The script downloads `cornell_movie_dialogs_corpus.zip` from `http://www.cs.cornell.edu/~cristian/data/cornell_movie_dialogs_corpus.zip` and extracts it using `unzip` to the directory specified by `${data_dir}`. A malicious zip archive could exploit `unzip` vulnerabilities.

  - **`fedjax/datasets/scripts/sent140/build_dataset.sh`:**
    ```bash
    wget --no-check-certificate \
        http://cs.stanford.edu/people/alecmgo/trainingandtestdata.zip \
        -O "${tmp_dir}/trainingandtestdata.zip"
    unzip "${tmp_dir}/trainingandtestdata.zip" -d "{$tmp_dir}"
    mv "${tmp_dir}/training.1600000.processed.noemoticon.csv" \
        "${tmp_dir}/training.csv"
    mv "${tmp_dir}/testdata.manual.2009.06.14.csv" "${tmp_dir}/test.csv"
    rm "${tmp_dir}/trainingandtestdata.zip"
    ```
    - The script downloads `trainingandtestdata.zip` from `http://cs.stanford.edu/people/alecmgo/trainingandtestdata.zip` and extracts it using `unzip` to the directory specified by `${tmp_dir}`. Similar to the Cornell dataset, a malicious zip archive could exploit `unzip` vulnerabilities.

- security test case:
  - **Step 1:** Create a malicious zip file (e.g., `malicious.zip`) containing a file that, when extracted, would overwrite a sensitive file or create a file in an unexpected location. For example, create a zip containing a file named `../../../tmp/evil.txt` with some malicious content.
  - **Step 2:** Host this `malicious.zip` file on a server accessible via HTTP (e.g., using `python -m http.server 8000` in the directory containing `malicious.zip`).
  - **Step 3:** Modify the `build_dataset.sh` script locally to download from your malicious server instead of the original source. For example, in `fedjax/datasets/scripts/cornell_movie_dialogs/build_dataset.sh`, change the `wget` command to:
    ```bash
    wget "http://localhost:8000/malicious.zip" -O "${data_dir}/cornell.zip"
    ```
  - **Step 4:** Run the modified `build_dataset.sh` script:
    ```bash
    sh build_dataset.sh -d /tmp/test_cornell -o /tmp/test_cornell
    ```
  - **Step 5:** Check if the file `evil.txt` has been created in `/tmp/` directory on your system, or if any unexpected file overwriting has occurred, indicating a successful directory traversal exploit.
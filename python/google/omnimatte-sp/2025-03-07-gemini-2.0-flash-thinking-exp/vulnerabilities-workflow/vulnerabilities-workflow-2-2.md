### Vulnerability List:

- Vulnerability Name: Malicious Script Execution via Compromised Download Server
- Description:
  1. A user downloads shell scripts, such as `dldata.sh` or `dlweights.sh`, provided in the repository. These scripts are intended to help users download datasets and pretrained weights necessary to run the project.
  2. The user, following the project's instructions in the README.md, executes one of these downloaded shell scripts on their local machine.
  3. These scripts contain commands using `gsutil cp` or `gsutil -m cp` to download data and model weights from a Google Cloud Storage bucket at `gs://omnimatte/`. For example, `dldata.sh` downloads dataset archives from `gs://omnimatte/data/`, and `dlweights.sh` downloads pretrained weights from `gs://omnimatte/models/`.
  4. Critically, the scripts directly download and, in the case of `dldata.sh` and `dlweights.sh`, automatically extract these archives using `tar -xf` or `unzip`.
  5. If an attacker were to compromise the `gs://omnimatte/` Google Cloud Storage bucket, they could replace the legitimate data and weight files with malicious files of the same names.
  6. Consequently, when a user executes the unmodified scripts, they would unknowingly download these malicious files from the compromised server.
  7. Specifically, if a malicious `.tar.gz` archive is placed at `gs://omnimatte/data/` or a malicious `weights.zip` is placed at `gs://omnimatte/models/`, the scripts would download and then execute code embedded within these malicious archives during the extraction process (`tar -xf` or `unzip`), leading to arbitrary code execution on the user's system.
- Impact:
  Critical. Successful exploitation of this vulnerability allows for arbitrary code execution on the user's machine. If the `gs://omnimatte/` bucket is compromised, an attacker could replace the expected data or weights with malicious payloads. Users who download and run the provided scripts would then unknowingly execute this malicious code. This could lead to a range of severe consequences, including:
    - Full system compromise: Attackers can gain complete control over the user's computer.
    - Data theft: Sensitive data stored on the user's system could be stolen.
    - Malware installation: The attacker could install persistent malware for long-term access or further malicious activities.
    - Denial of service: The attacker could render the user's system unusable.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations:
  None. The provided scripts and project documentation do not include any mechanisms to verify the integrity or authenticity of the downloaded files. There are no checksum verifications, digital signatures, or any other form of validation to ensure that the downloaded files are legitimate and have not been tampered with.
- Missing Mitigations:
  - Implement integrity checks: Introduce checksum verification for all downloaded files. Before extracting or using downloaded data or weights, the scripts should calculate the checksum (e.g., SHA256) of the downloaded file and compare it against a known, trusted checksum. This would ensure that the downloaded file has not been altered.
  - Digital signatures: For a more robust solution, consider digitally signing the data and weight files. The scripts could then verify these signatures before proceeding, ensuring both integrity and authenticity.
  - HTTPS enforcement and warning: While `gsutil` uses HTTPS by default, explicitly mention in the documentation the importance of using HTTPS and warn users about the risks of downloading and executing scripts from the internet without proper verification.
  - User education and warnings: Clearly warn users in the README.md about the security risks associated with directly executing shell scripts downloaded from the internet. Emphasize the importance of reviewing the script's contents before execution.
  - Alternative download methods: If feasible, provide alternative, safer methods for users to obtain the data and weights, such as direct download links to a secure website with checksums provided, or using version control systems to manage and verify the files.
- Preconditions:
  - An attacker successfully compromises the `gs://omnimatte/` Google Cloud Storage bucket, gaining the ability to modify or replace files within it.
  - A user downloads and executes one of the provided shell scripts (e.g., `dldata.sh`, `dlweights.sh`, `train-synth.sh`, `train-real.sh`, `inference.sh`, `eval.sh`) without prior inspection of the script's contents.
- Source Code Analysis:
  - **File: `/code/scripts/dldata.sh`**:
    ```bash
    gsutil -m cp gs://omnimatte/data/kubric-shadows-v1-train.tar.gz data/
    gsutil -m cp gs://omnimatte/data/kubric-shadows-v1-test.tar.gz data/
    ...
    cd data
    for x in *tar.gz; do
      echo "extracting $x..."
      tar -xf $x
    done
    ```
    This script downloads multiple `.tar.gz` archives from `gs://omnimatte/data/` and extracts them using `tar -xf`. If any of these archives are replaced with malicious ones, `tar -xf` will execute malicious commands embedded within them.
  - **File: `/code/scripts/dlweights.sh`**:
    ```bash
    WEIGHTSDIR=pretrained_weights
    mkdir $WEIGHTSDIR
    gsutil cp gs://omnimatte/models/weights.zip $WEIGHTSDIR/
    unzip pretrained_weights/weights.zip -d $WEIGHTSDIR/
    ```
    This script downloads `weights.zip` from `gs://omnimatte/models/` and extracts it using `unzip`. If `weights.zip` is replaced with a malicious zip archive, `unzip` can be exploited to execute arbitrary code.
  - **Files: `/code/scripts/train-real.sh`, `/code/scripts/train-synth.sh`, `/code/scripts/inference.sh`, `/code/scripts/eval.sh`**:
    While these scripts themselves do not download and extract archives, they rely on the data and weights downloaded by `dldata.sh` and `dlweights.sh`. If those are compromised, the execution of these training and evaluation scripts could also be indirectly affected, although the initial entry point for the vulnerability is through `dldata.sh` and `dlweights.sh`.

- Security Test Case:
  1. **Set up a malicious server:** Configure a web server that can mimic the `gs://omnimatte/` Google Cloud Storage structure for testing purposes. You can use a local server or a controlled cloud storage bucket.
  2. **Create a malicious `weights.zip`:** Create a zip archive named `weights.zip`. Inside this archive, include a malicious executable or script (e.g., a simple shell script that creates a file in `/tmp` to indicate successful execution).
  3. **Host the malicious `weights.zip`:** Place the malicious `weights.zip` in your malicious server at the path that corresponds to where `dlweights.sh` expects to download it from (mimicking `gs://omnimatte/models/weights.zip`).
  4. **Modify `dlweights.sh` (for testing only):** Temporarily modify the `dlweights.sh` script to download from your malicious server instead of the legitimate `gs://omnimatte/`. For example, if you are using a local web server at `http://localhost:8000`, change the `gsutil cp` command to `wget http://localhost:8000/models/weights.zip $WEIGHTSDIR/`.
  5. **Run `dlweights.sh`:** Execute the modified `dlweights.sh` script on a test machine.
  6. **Observe the execution:** Check if the malicious code within `weights.zip` was executed. For instance, check if the file in `/tmp` (or any other indicator you used in your malicious script) was created.
  7. **Expected result:** If the vulnerability is present, the malicious code within `weights.zip` will be executed upon extraction, demonstrating arbitrary code execution.
  8. **Revert changes:** After testing, remember to revert the changes made to `dlweights.sh` and remove the malicious server setup to avoid unintended security risks.

This test case demonstrates that if a malicious `weights.zip` is hosted at the expected download location, the `dlweights.sh` script will download and execute code from it, confirming the arbitrary code execution vulnerability. A similar test case can be constructed for `dldata.sh` using a malicious `.tar.gz` archive.
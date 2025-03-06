### Vulnerability List:

#### 1. Insecure Dataset Download (MITM vulnerability during dataset download)

* Description:
    1. The `load_sts` function in `/code/src/data.py` is responsible for downloading the STS dataset if it's not already present.
    2. It uses the `wget` command with the `--no-check-certificate` option.
    3. This option disables SSL certificate verification during the download process.
    4. An attacker positioned in a Man-in-the-Middle (MITM) attack scenario can intercept the download request.
    5. The attacker can then serve a malicious ZIP archive containing a tampered STS dataset instead of the legitimate one from `https://fangyuliu.me/data/STS_data.zip`.
    6. The script will extract this malicious dataset, and it will be used for training or evaluation of the Trans-Encoder model.

* Impact:
    - **Data Poisoning:** A malicious dataset can be crafted to introduce backdoors or biases into the trained Trans-Encoder model.
    - **Model Manipulation:** An attacker can manipulate the model's behavior by controlling the training data, potentially causing the model to produce incorrect sentence similarity scores for specific inputs or classes of inputs.
    - **Downstream Application Vulnerability:** If downstream applications rely on the manipulated model for critical decision-making, they could be misled or exploited due to the model's altered behavior. For example, in a system using sentence similarity for fraud detection, an attacker might manipulate the model to classify fraudulent activities as benign.

* Vulnerability Rank: High

* Currently Implemented Mitigations:
    - None. The `--no-check-certificate` option explicitly disables a security feature.

* Missing Mitigations:
    - **Remove `--no-check-certificate`:** The most critical mitigation is to remove the `--no-check-certificate` option from the `wget` command in `/code/src/data.py`. This will ensure that `wget` verifies the SSL certificate of `fangyuliu.me`, protecting against basic MITM attacks during download.
    - **Verify Downloaded File Integrity:** Implement integrity checks for the downloaded `STS_data.zip` file. This can be done by:
        - **Using HTTPS:** Ensure the download URL `https://fangyuliu.me/data/STS_data.zip` uses HTTPS to encrypt the download channel (already used, but certificate verification is disabled).
        - **Checksum Verification:** Provide a checksum (e.g., SHA256 hash) of the legitimate `STS_data.zip` file in the `README.md` or a separate `CHECKSUM.txt` file. The `data.py` script should then calculate the checksum of the downloaded file and compare it against the provided checksum before extracting the dataset. This will ensure that the downloaded file is not tampered with, even if the HTTPS connection is compromised or initially bypassed.

* Preconditions:
    - The attacker needs to be in a network position to perform a MITM attack between the user running the script and the server `fangyuliu.me`.
    - The user must run one of the training or evaluation scripts (`train_self_distill.sh`, `train_mutual_distill.sh`, or `eval.py`) for the first time on a system where the STS dataset is not already downloaded in the `data/STS_data` directory.

* Source Code Analysis:
    1. Open `/code/src/data.py`.
    2. Locate the `load_sts` function.
    3. Find the following code block responsible for downloading the dataset:
    ```python
    sts_dataset_path = "data/"
    if not os.path.exists(os.path.join(sts_dataset_path, "STS_data")):
        logging.info("Dataset not found. Download")
        zip_save_path = "data/STS_data.zip"
        #os.system("wget https://fangyuliu.me/data/STS_data.zip  -P data/")
        subprocess.run(["wget", "--no-check-certificate", "https://fangyuliu.me/data/STS_data.zip", "-P", "data/"])
        with ZipFile(zip_save_path, "r") as zipIn:
            zipIn.extractall(sts_dataset_path)
    ```
    4. Observe the `subprocess.run` command which includes `wget --no-check-certificate`.
    5. The `--no-check-certificate` argument disables SSL certificate verification, which is a security risk.
    6. When the script is executed and the STS dataset is not found locally, this `wget` command will be executed.
    7. If an attacker is performing a MITM attack at this moment, they can intercept the request to `https://fangyuliu.me/data/STS_data.zip`.
    8. The attacker's malicious server can respond with a crafted `STS_data.zip` file.
    9. Because certificate verification is disabled, `wget` will download the malicious ZIP file without any warning.
    10. The script will then proceed to extract the malicious dataset using `ZipFile.extractall(sts_dataset_path)`.
    11. Subsequent training or evaluation processes will use this compromised dataset.

* Security Test Case:
    1. **Setup MITM Attack Environment:** Use a tool like `mitmproxy` or `Burp Suite` to set up a local MITM proxy. Configure your system to route traffic through this proxy.
    2. **Prepare Malicious Dataset:** Create a malicious version of `STS_data.zip`. This ZIP file should have the same directory structure as the original dataset but contain modified data files (e.g., `en/2012.test.tsv`, `en/2013.test.tsv`, etc.). The modified data can be subtly altered to introduce bias or trigger specific model behavior changes that are detectable in downstream tasks. For simplicity, you could just replace the content of the tsv files with dummy data or slightly modified sentence pairs to observe a change in model performance.
    3. **Configure Proxy to Intercept and Replace:** Configure the MITM proxy to intercept requests to `https://fangyuliu.me/data/STS_data.zip`. When such a request is intercepted, the proxy should respond with the prepared malicious `STS_data.zip` file from step 2 instead of forwarding the request to the actual server `fangyuliu.me`.
    4. **Run Training Script:** Execute one of the training scripts (e.g., `bash train_self_distill.sh 0`) on a system where the `data/STS_data` directory does not exist. This will force the script to download the dataset.
    5. **Observe Download and Extraction:** Monitor the script's output logs. You should see the "Dataset not found. Download" message, indicating that the download process is initiated. The MITM proxy should intercept the download and serve the malicious file. The script should proceed without any certificate warnings due to `--no-check-certificate`.
    6. **Verify Dataset Tampering (Optional but Recommended):** After the script completes (or even interrupt it after dataset download and extraction), manually inspect the files in the `data/STS_data` directory. Compare them to the original dataset files (if you have a copy) or verify if the modifications you introduced in the malicious dataset are present.
    7. **Evaluate Model Behavior Change:** Train or evaluate the Trans-Encoder model using the downloaded (malicious) dataset. Compare the model's performance metrics (e.g., STS scores) with those obtained using a legitimate dataset. Significant deviations in performance or unexpected model behavior can indicate successful data poisoning. For a more targeted attack, design the malicious data to cause misclassification in a specific downstream task that uses sentence similarity scores.
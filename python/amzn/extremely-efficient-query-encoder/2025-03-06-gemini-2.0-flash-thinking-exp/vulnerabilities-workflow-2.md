## Combined Vulnerability List

### Unvalidated Data Sources in Data Preparation Scripts

- **Vulnerability Name:** Unvalidated Data Sources in Data Preparation Scripts
- **Description:**
    - Data preparation scripts within the project (`prepare_wiki_train.py`, `get_data.sh`, `build_train.py`, `build_hn.py`) download training datasets from external, unvalidated sources.
    - An attacker could compromise these external sources or perform a man-in-the-middle attack to replace legitimate data with poisoned data.
    - **Step-by-step to trigger the vulnerability:**
        1. Attacker identifies the external data sources used by the data preparation scripts (e.g., URLs in `prepare_wiki_train.py`, `get_data.sh`).
        2. Attacker compromises one of these external data sources or sets up a malicious server mimicking a legitimate source.
        3. Attacker injects poisoned data into the dataset files hosted on the compromised or malicious server. This poisoned data is crafted to subtly alter the behavior of the trained model, for example, to bias retrieval results for specific queries or topics.
        4. A user, intending to train a query encoder, follows the project's instructions and executes a data preparation script (e.g., by running a command from `examples/coCondenser-nq/README.md` or `examples/coCondenser-marco/README.md`).
        5. The data preparation script, as part of its normal operation, downloads training data from the attacker-controlled source. Due to the lack of integrity checks, the script unknowingly fetches the attacker's poisoned dataset.
        6. The user proceeds to train the query encoder using the downloaded, poisoned data.
        7. The trained query encoder becomes poisoned. It may exhibit subtly altered behavior, such as providing biased or inaccurate retrieval results in downstream applications when used for query encoding.
- **Impact:**
    - Model poisoning: The trained query encoder model is corrupted with malicious data.
    - Biased or inaccurate retrieval results: The poisoned model may produce retrieval results that are intentionally skewed or less accurate, depending on the attacker's goals.
    - Compromised downstream applications: Applications relying on the poisoned query encoder for dense retrieval will be negatively affected, potentially leading to misinformation, unfair outcomes, or security breaches in systems using the retrieval results.
- **Vulnerability Rank:** High
- **Currently Implemented Mitigations:**
    - None. The project does not implement any mechanisms to validate the integrity or authenticity of downloaded training data.
- **Missing Mitigations:**
    - Implement integrity checks: Add checksum verification (e.g., using SHA256 hashes) for all downloaded data files. Compare the calculated checksum of the downloaded file against a known, trusted checksum to ensure data integrity.
    - Enforce HTTPS for data downloads: Ensure that all data downloads are performed over HTTPS to prevent man-in-the-middle attacks during data transfer. Remove `--no-check-certificate` option in `get_data.sh`.
    - Trusted Data Hosting: Host the datasets on trusted and controlled infrastructure (e.g., cloud storage with access controls) to minimize the risk of external compromise.
    - Input Data Validation and Sanitization: Implement validation and sanitization of the input training data within the data loading and preprocessing pipeline. This could include anomaly detection, range checks, or format validation to identify and filter out potentially malicious or corrupted data points before they are used for training.
- **Preconditions:**
    - The user must execute data preparation scripts (`prepare_wiki_train.py`, `get_data.sh`, `build_train.py`, `build_hn.py`) that download training data from external sources.
    - The attacker must be able to compromise or impersonate one of the external data sources used by these scripts or perform a man-in-the-middle attack.
- **Source Code Analysis:**
    - `examples/coCondenser-nq/prepare_wiki_train.py`:
        - Downloads data using `wget` from `https://dl.fbaipublicfiles.com/dpr/data/retriever/biencoder-nq-train.json.gz` and `http://boston.lti.cs.cmu.edu/luyug/co-condenser/nq/hn.json.gz`.
        - The URL `http://boston.lti.cs.cmu.edu/luyug/co-condenser/nq/hn.json.gz` uses HTTP, which is vulnerable to man-in-the-middle attacks.
        - No integrity checks are performed on the downloaded files.
    - `examples/coCondenser-marco/get_data.sh`:
        - Downloads data using `wget` from `https://rocketqa.bj.bcebos.com/corpus/marco.tar.gz`, `https://msmarco.blob.core.windows.net/msmarcoranking/qidpidtriples.train.full.2.tsv.gz`, and `https://msmarco.blob.core.windows.net/msmarcoranking/qrels.train.tsv`.
        - Uses `--no-check-certificate` when downloading from `rocketqa.bj.bcebos.com`, disabling certificate verification and weakening HTTPS security.
        - No integrity checks are performed on the downloaded files.
    - `examples/coCondenser-marco/build_train.py` and `examples/coCondenser-marco/build_hn.py`:
        - These scripts process data from local files (`args.negative_file`, `args.hn_file`, `args.qrels`, `args.queries`, `args.collection`).
        - However, these local files are generated or downloaded by the aforementioned data downloading scripts, inheriting the vulnerability.
- **Security Test Case:**
    1. **Setup Malicious Server:**
        - Create a simple HTTP server using Python (or any other suitable tool).
        - Prepare a modified version of `biencoder-nq-train.json.gz` containing poisoned training data (e.g., subtly alter query-passage pairs to skew retrieval results towards a specific topic or away from a specific entity).
        - Host the modified `biencoder-nq-train.json.gz` file on the malicious server, making it accessible via HTTP at a specific URL (e.g., `http://malicious-server.com/biencoder-nq-train.json.gz`).
    2. **Modify README Instructions:**
        - Edit the `examples/coCondenser-nq/README.md` file, specifically the "Training with BM25 Negatives" section.
        - Locate the `wget` command that downloads `biencoder-nq-train.json.gz` from `https://dl.fbaipublicfiles.com/dpr/data/retriever/biencoder-nq-train.json.gz`.
        - Replace the original URL with the URL of the malicious server hosting the poisoned data (e.g., change `wget https://dl.fbaipublicfiles.com/dpr/data/retriever/biencoder-nq-train.json.gz` to `wget http://malicious-server.com/biencoder-nq-train.json.gz`).
    3. **Execute Data Preparation and Training:**
        - Follow the instructions in the modified `examples/coCondenser-nq/README.md` to download the training data and train the coCondenser model. This will now download the poisoned dataset from the malicious server.
        - Run the training script as instructed.
    4. **Evaluate Model and Observe Poisoning Effects:**
        - After training is complete, evaluate the performance of the trained model.
        - Design evaluation queries to specifically test for the intended poisoning effect. For example, if the poisoned data was designed to bias results towards a specific topic, create queries related to that topic and observe if the retrieval performance is artificially inflated or skewed.
        - Compare the retrieval results of the model trained with poisoned data against a model trained with legitimate data (if available).
        - Observe if the model trained with poisoned data exhibits biased or inaccurate retrieval results as a consequence of the data manipulation. For example, check if the ranking of relevant documents is altered, or if irrelevant documents are promoted for specific queries.

### Data Poisoning in Training Data

- **Vulnerability Name:** Data Poisoning in Training Data
- **Description:**
    1. The project trains query encoders using training data loaded from files or datasets, as specified in configuration files and command-line arguments in scripts like `run_pretraining.pretrain`, `marco_train_pretrained_model.sh`, and `tevatron.driver.train`. Example data paths include `../resources/pretrain_data/train_queries_tokens.jsonl`, `nq-train/bm25.bert.json`, and `marco/bert/train/split*.json`.
    2. An attacker can compromise the integrity of the query encoder by manipulating these training data files before the training process starts. This manipulation involves injecting malicious data into the training set.
    3. The injected malicious data can consist of crafted query-passage pairs designed to mislead the model during training. This could include associating benign queries with irrelevant or biased passages, or associating attacker-controlled queries with highly relevant but potentially harmful passages.
    4. When the training process is executed, the query encoder learns from the poisoned dataset. The learning algorithms in `tevatron.driver.train` and related scripts do not include any mechanisms to detect or filter out data poisoning attacks.
    5. As a result of training on poisoned data, the query encoder's performance can be severely compromised. This can manifest as degraded retrieval accuracy, introduction of biases that skew search results, or optimization of the model to favor queries controlled by the attacker.
- **Impact:**
    - **Degraded Retrieval Performance**: Legitimate users will experience a noticeable decline in the quality of search results. Relevant documents may be missed, and irrelevant or harmful documents might be retrieved instead.
    - **Bias Introduction**: The query encoder can become biased, leading to unfair or discriminatory search outcomes. This is particularly concerning in applications where fairness and neutrality are critical.
    - **Compromised Downstream Applications**: If the poisoned query encoder is used in a downstream application (e.g., a search engine, recommendation system), the application's reliability and trustworthiness will be undermined, potentially causing reputational damage and user dissatisfaction.
- **Vulnerability Rank:** High
- **Currently Implemented Mitigations:** None. The project's current implementation lacks any built-in mechanisms to validate or ensure the integrity of the training data. It implicitly trusts that the input data is clean and free from malicious modifications.
- **Missing Mitigations:**
    - **Input Data Validation and Sanitization**: Implement robust validation checks on all input training data. This should include schema validation to ensure data conforms to expected formats and content validation to detect anomalies or suspicious patterns in query-passage pairs.
    - **Data Provenance and Integrity Checks**: Establish a system for tracking the origin and history of training data. Employ cryptographic techniques such as hashing or digital signatures to verify the integrity of data files and detect unauthorized alterations.
    - **Anomaly Detection in Training Data**: Integrate anomaly detection algorithms to automatically identify and flag unusual or suspicious data points within the training dataset. This can help in preemptively filtering out potentially poisoned samples before they affect model training.
    - **Robust Training Techniques**: Explore and implement training methodologies that are inherently more resilient to data poisoning attacks. This could involve techniques like robust optimization, which aims to minimize the influence of outliers, or outlier-aware loss functions that reduce the impact of noisy or malicious data points.
- **Preconditions:**
    - The attacker needs to gain the ability to modify or replace the training data files that are used by the project's training scripts. This could be achieved through various means, such as:
        - Compromising the storage location of the training data (e.g., a file server, cloud storage bucket).
        - Intercepting or manipulating the data stream if the training data is fetched from an external source over a network.
        - Supply chain attacks, where a dependency or data source used by the project is compromised.
        - Insider threats, where a malicious user with authorized access to the data modifies it.
- **Source Code Analysis:**
    - **Data Loading Process**: The project relies on datasets loaded using file paths that are often hardcoded or specified via configuration files. For example, the `run_pretraining.pretrain.py` script uses `PRETRAIN_DATA_PATH = "../resources/pretrain_data"` and loads data based on filenames within this path. Similarly, example scripts for training models on MS MARCO and NQ datasets reference data files in local directories (e.g., `./marco/bert/train`, `nq-train`).
    - **Absence of Integrity Checks**: A review of the provided Python scripts (`tevatron/driver/train.py`, `run_pretraining/pretrain.py`, dataset loading scripts in `tevatron/datasets/`) reveals a complete lack of input validation or data integrity checks. The code directly reads and processes data from the specified file paths without any verification of its source, format, or content.
    - **External Data Sources**: Scripts like `examples/coCondenser-marco/get_data.sh` demonstrate the project's reliance on external data sources, downloading datasets from URLs (e.g., `https://rocketqa.bj.bcebos.com/corpus/marco.tar.gz`, `https://msmarco.blob.core.windows.net/msmarcoranking/qidpidtriples.train.full.2.tsv.gz`). These download processes are potential points of failure if the download sources are compromised or if man-in-the-middle attacks are possible. The scripts use `wget` without strong integrity checks on downloaded files beyond basic checks like `tar -zxf marco.tar.gz` which does not verify the content's origin or prevent sophisticated poisoning.
- **Security Test Case:**
    1. **Setup**:
        - Set up a development environment with the project code and necessary dependencies.
        - Choose a training example to target, such as pre-training using `run_pretraining.pretrain` and identify the relevant training data input file, for instance, `../resources/pretrain_data/train_queries_tokens.jsonl`.
        - Train a baseline model using the original, clean training data and record its performance metrics (e.g., MRR@10, NDCG@10) on a held-out evaluation dataset. This serves as the benchmark for comparison.
    2. **Data Poisoning**:
        - Introduce poisoned data into the training data file (`../resources/pretrain_data/train_queries_tokens.jsonl`). For example, for every 200 lines, insert one poisoned data entry. A poisoned entry could be crafted to misguide the model. For instance, alter the 'target' vector in a few entries to represent embeddings that are significantly different from what a clean model would produce for those queries, or introduce queries that are semantically unrelated to their target vectors.
    3. **Retraining with Poisoned Data**:
        - Execute the pre-training script (`python -m run_pretraining.pretrain`) using the modified, poisoned training data. This will train a new query encoder model that has been exposed to the injected malicious data.
    4. **Evaluation and Comparison**:
        - Encode a set of clean evaluation queries and passages using both the baseline model (trained on clean data) and the poisoned model.
        - Evaluate the retrieval performance of both models on the same evaluation dataset. Use standard information retrieval metrics like MRR@10 and NDCG@10 to quantify the performance.
        - Compare the evaluation metrics of the poisoned model against the baseline model. A successful data poisoning attack will manifest as a measurable degradation in the poisoned model's retrieval performance compared to the baseline. Additionally, you might observe biased behavior, such as the poisoned model retrieving irrelevant documents for certain queries or showing a preference for documents related to the attacker's chosen bias.
    5. **Verification of Vulnerability**:
        - If the poisoned model demonstrates a statistically significant decrease in retrieval performance metrics or exhibits noticeable bias in retrieval results compared to the baseline model, this confirms the presence of a data poisoning vulnerability. The magnitude of performance degradation and the nature of the bias will indicate the severity and type of poisoning attack that is possible.

### Path Traversal in Data Loading via `encode_in_path`

- **Vulnerability Name:** Path Traversal in Data Loading via `encode_in_path`
- **Description:**
    - An attacker could potentially use path traversal techniques within the `--encode_in_path` argument of the `encode.py` script to access or read files outside of the intended data directories.
    - **Step 1:** The attacker identifies that the `encode.py` script uses the `--encode_in_path` argument to specify the input data file for encoding.
    - **Step 2:** The attacker crafts a malicious `--encode_in_path` value containing path traversal sequences like `../../sensitive_file.json` or similar.
    - **Step 3:** When the `encode.py` script executes, it uses the provided path directly to load the dataset using Hugging Face `datasets.load_dataset`.
    - **Step 4:** If `datasets.load_dataset` or the underlying file system operations do not properly sanitize or restrict the paths, the attacker could potentially read arbitrary files accessible to the user running the script.
- **Impact:**
    - Information Disclosure: An attacker could potentially read sensitive files from the server's file system if the user running the encoding script has the necessary permissions to access those files. This could include configuration files, private data, or other sensitive information.
- **Vulnerability Rank:** High
- **Currently Implemented Mitigations:**
    - None apparent in the provided code. The code directly uses the user-provided `encode_in_path` in `datasets.load_dataset` without explicit validation or sanitization.
- **Missing Mitigations:**
    - Input validation and sanitization for the `encode_in_path` argument.
    - Path validation to ensure that the provided path is within the expected data directory or a restricted set of allowed paths.
    - Consider using secure file handling practices to limit access to only necessary files and directories.
- **Preconditions:**
    - The attacker needs to be able to influence the `--encode_in_path` argument of the `encode.py` script. In a deployed system, this might occur if the encoding process is triggered by user-supplied configuration or through an API that exposes this parameter (though not directly evident from provided files, this is a common deployment pattern).
- **Source Code Analysis:**
    - **File: /code/src/tevatron/driver/encode.py**
    ```python
    if data_args.encode_in_path:
        encode_dataset = HFQueryDataset(tokenizer=tokenizer, data_args=data_args,
                                        cache_dir=data_args.data_cache_dir or model_args.cache_dir)
    else:
        encode_dataset = HFCorpusDataset(tokenizer=tokenizer, data_args=data_args,
                                         cache_dir=data_args.data_cache_dir or model_args.cache_dir)
    encode_dataset = EncodeDataset(encode_dataset.process(data_args.encode_num_shard, data_args.encode_shard_index),
                                   tokenizer, max_len=text_max_length)
    ```
    - The code directly uses `data_args.encode_in_path` (which originates from the command-line argument `--encode_in_path`) when initializing `HFQueryDataset` or `HFCorpusDataset`.
    - **File: /code/src/tevatron/arguments.py**
    ```python
    @dataclass
    class DataArguments:
        # ...
        encode_in_path: List[str] = field(default=None, metadata={"help": "Path to data to encode"})
        # ...
    ```
    - `encode_in_path` is defined as a `List[str]` and is directly populated from command-line arguments via `HfArgumentParser`.
    - **File: /code/src/tevatron/datasets/dataset.py** (Example: `HFQueryDataset`)
    ```python
    class HFQueryDataset:
        def __init__(self, tokenizer: PreTrainedTokenizer, data_args: DataArguments, cache_dir: str):
            data_files = data_args.encode_in_path # <--- vulnerable path usage
            if data_files:
                data_files = {data_args.dataset_split: data_files}
            self.dataset = load_dataset(data_args.dataset_name,
                                        data_args.dataset_language,
                                        data_files=data_files, cache_dir=cache_dir, use_auth_token=True)[data_args.dataset_split]
            # ...
    ```
    - `HFQueryDataset` and `HFCorpusDataset` pass `data_files` (derived from `encode_in_path`) directly to `datasets.load_dataset`.
    - `datasets.load_dataset` can load from local files if a file path is provided. If this function or the underlying file access methods do not sufficiently sanitize the path, a path traversal vulnerability exists.
- **Security Test Case:**
    - Step 1: Create a sensitive file named `sensitive_data.txt` in a directory accessible to the user running the script, but outside the intended data directory (e.g., in the user's home directory). This file should contain some secret information, for example: `This is secret data`.
    - Step 2: Run the `encode.py` script, providing a path traversal payload as the `--encode_in_path` argument. For example, if you are running the script from `/code/src/tevatron/driver/`, and `sensitive_data.txt` is in `/home/user/`, the command could be:
    ```bash
    python -m tevatron.driver.encode --model_name_or_path bert-base-uncased --encode_in_path ../../../../../home/user/sensitive_data.txt --encoded_save_path output.pkl --encode_is_qry --per_device_eval_batch_size 2
    ```
    - Step 3: Examine the output file `output.pkl`. If the vulnerability is exploitable, the contents of `sensitive_data.txt` might be included in the encoded output or error messages, indicating successful file access. While the current code saves embeddings, an attacker might modify the script or observe error messages to confirm file access. A more direct test would involve modifying `encode.py` temporarily to print the content of the loaded dataset. For instance, adding `print(encode_dataset.encode_data[:])` after dataset loading in `encode.py` could reveal the content of `sensitive_data.txt` in the standard output if the exploit is successful.
    - Step 4: Verify if the script was able to read the content of `sensitive_data.txt`. If successful, this confirms the path traversal vulnerability.
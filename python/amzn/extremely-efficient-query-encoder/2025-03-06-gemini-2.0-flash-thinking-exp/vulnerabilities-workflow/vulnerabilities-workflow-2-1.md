### Vulnerability List

- Vulnerability Name: Unvalidated Data Sources in Data Preparation Scripts
- Description:
    - Data preparation scripts within the project (`prepare_wiki_train.py`, `get_data.sh`, `build_train.py`, `build_hn.py`) download training datasets from external, unvalidated sources.
    - An attacker could compromise these external sources or perform a man-in-the-middle attack to replace legitimate data with poisoned data.
    - Step-by-step to trigger the vulnerability:
        1. Attacker identifies the external data sources used by the data preparation scripts (e.g., URLs in `prepare_wiki_train.py`, `get_data.sh`).
        2. Attacker compromises one of these external data sources or sets up a malicious server mimicking a legitimate source.
        3. Attacker injects poisoned data into the dataset files hosted on the compromised or malicious server. This poisoned data is crafted to subtly alter the behavior of the trained model, for example, to bias retrieval results for specific queries or topics.
        4. A user, intending to train a query encoder, follows the project's instructions and executes a data preparation script (e.g., by running a command from `examples/coCondenser-nq/README.md` or `examples/coCondenser-marco/README.md`).
        5. The data preparation script, as part of its normal operation, downloads training data from the attacker-controlled source. Due to the lack of integrity checks, the script unknowingly fetches the attacker's poisoned dataset.
        6. The user proceeds to train the query encoder using the downloaded, poisoned data.
        7. The trained query encoder becomes poisoned. It may exhibit subtly altered behavior, such as providing biased or inaccurate retrieval results in downstream applications when used for query encoding.
- Impact:
    - Model poisoning: The trained query encoder model is corrupted with malicious data.
    - Biased or inaccurate retrieval results: The poisoned model may produce retrieval results that are intentionally skewed or less accurate, depending on the attacker's goals.
    - Compromised downstream applications: Applications relying on the poisoned query encoder for dense retrieval will be negatively affected, potentially leading to misinformation, unfair outcomes, or security breaches in systems using the retrieval results.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - None. The project does not implement any mechanisms to validate the integrity or authenticity of downloaded training data.
- Missing Mitigations:
    - Implement integrity checks: Add checksum verification (e.g., using SHA256 hashes) for all downloaded data files. Compare the calculated checksum of the downloaded file against a known, trusted checksum to ensure data integrity.
    - Enforce HTTPS for data downloads: Ensure that all data downloads are performed over HTTPS to prevent man-in-the-middle attacks during data transfer. Remove `--no-check-certificate` option in `get_data.sh`.
    - Trusted Data Hosting: Host the datasets on trusted and controlled infrastructure (e.g., cloud storage with access controls) to minimize the risk of external compromise.
    - Input Data Validation and Sanitization: Implement validation and sanitization of the input training data within the data loading and preprocessing pipeline. This could include anomaly detection, range checks, or format validation to identify and filter out potentially malicious or corrupted data points before they are used for training.
- Preconditions:
    - The user must execute data preparation scripts (`prepare_wiki_train.py`, `get_data.sh`, `build_train.py`, `build_hn.py`) that download training data from external sources.
    - The attacker must be able to compromise or impersonate one of the external data sources used by these scripts or perform a man-in-the-middle attack.
- Source Code Analysis:
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
- Security Test Case:
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

If the evaluation shows a significant and targeted degradation in retrieval quality, or a noticeable bias in the retrieval results for specific queries related to the injected poison, this confirms the vulnerability and demonstrates successful model poisoning.
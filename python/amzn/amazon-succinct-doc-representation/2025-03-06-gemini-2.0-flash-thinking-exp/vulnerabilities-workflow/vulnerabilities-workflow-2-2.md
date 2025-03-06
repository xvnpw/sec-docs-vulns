* Vulnerability Name: CSV Injection leading to potential data mishandling
* Description:
    1. The application reads various CSV files using pandas `read_csv` function, for example, `top1000.dev`, `qrels.dev.tsv`, `dev_w_qrels.csv`, `trainfile.tsv`, `collection.tsv`.
    2. These CSV files are expected to contain document and query text data.
    3. If a malicious user can replace or influence the content of these CSV files, they can inject arbitrary content into the document and query fields.
    4. When `pandas.read_csv` parses these malicious CSV files, it will load the injected content as strings.
    5. Subsequently, this injected content is used in various parts of the application, including tokenization and model input.
    6. While `pandas.read_csv` itself is generally safe from direct code execution vulnerabilities, injecting extremely long strings or strings with specific characters can lead to unexpected behavior in downstream processing.
    7. For example, very long strings in document fields could cause excessive memory consumption during tokenization or embedding generation, potentially leading to performance degradation or errors.
    8. Maliciously crafted strings might also cause unexpected behavior in the model if it's not robustly designed to handle unusual input.
    9. This vulnerability is triggered when the application processes a maliciously crafted CSV file during training or embedding generation.
* Impact:
    - Potential for unexpected behavior during training or embedding generation due to mishandled data.
    - Performance degradation due to processing of very long strings.
    - Possible errors during tokenization or model inference if the model is not designed to handle malicious inputs.
    - Data corruption if injected content interferes with the intended data processing logic.
* Vulnerability Rank: medium
* Currently Implemented Mitigations:
    - The code relies on pandas `read_csv` for CSV parsing, which is generally considered robust against common CSV injection attacks like formula injection that are relevant to spreadsheet software.
    - The code limits the maximum length of documents and queries during tokenization (`max_length=256` or `DOC_MAX_LENGTH` and `max_length=24`), which can mitigate some impacts of excessively long injected strings in terms of buffer overflows during tokenization, but doesn't prevent memory exhaustion or unexpected behavior in the model.
    - Input file paths are defined using constants in `config.py`, which are not directly user-controlled in the provided code, reducing the risk of arbitrary file read/write vulnerabilities via path injection.
* Missing Mitigations:
    - Input validation and sanitization for document and query text read from CSV files are missing. There is no explicit check for maximum string lengths or unusual characters before processing the data.
    - Error handling for potential exceptions during pandas `read_csv` parsing or subsequent tokenization and embedding generation is not explicitly detailed in the provided code snippets. Robust error handling could prevent unexpected program termination and provide more graceful failure in case of malicious input.
    - Input data integrity checks are missing. The application assumes that the CSV files are trustworthy and have not been tampered with. Mechanisms to verify the integrity of input CSV files (e.g., checksums, digital signatures) are not implemented.
* Preconditions:
    - An attacker must be able to replace or modify the CSV files that the application reads (e.g., `top1000.dev`, `qrels.dev.tsv`, `dev_w_qrels.csv`, `trainfile.tsv`, `collection.tsv`). This could happen if the application is deployed in an environment where file system access controls are weak or if an attacker has compromised the system.
    - The application must be run in a mode where it processes these potentially malicious CSV files, such as during training, embedding generation, or evaluation.
* Source Code Analysis:
    1. **File: `/code/src/evaluation/select_top_k.py`**:
        ```python
        df = pd.read_csv(f"{ARTIFACTS_PATH}/msmarco/top1000.dev", sep="\t", names=["qid", "docid", "query", "doc"])
        dfqrels = pd.read_csv(f"{ARTIFACTS_PATH}/msmarco/qrels.dev.tsv", sep="\t", names=["qid", 0, "docid", "label"])
        dfiter = pd.read_csv(f"{ARTIFACTS_PATH}/msmarco/dev_w_qrels.csv", chunksize=60000)
        ```
        - `pd.read_csv` is used to read `top1000.dev`, `qrels.dev.tsv`, and `dev_w_qrels.csv`. The "query" and "doc" columns from `top1000.dev` and `dev_w_qrels.csv` are directly used for tokenization later in the `predict_scores` function.

    2. **File: `/code/src/late_interaction_baseline/trainer.py`**:
        ```python
        df = pd.read_csv("trainfile.tsv", sep="\t", header=None)
        dfiter = pd.read_csv(f"{TEMP_OUT_PATH}/trainfile_shuffle.tsv", sep="\t", chunksize=10000, names=["pos_score", "neg_score", "query", "pos", "neg"])
        ```
        - `pd.read_csv` reads `trainfile.tsv` and `trainfile_shuffle.tsv`. The "query", "pos", and "neg" columns are used for training in `TsvDatasetSep`.

    3. **File: `/code/src/late_interaction_baseline/predict_kd_baseline.py`**:
        ```python
        dfiter = pd.read_csv(f"{ARTIFACTS_PATH}/msmarco/dev_w_qrels.csv", chunksize=60000)
        df = pd.read_csv(f"{ARTIFACTS_PATH}/msmarco/dev_w_qrels.csv")
        df = pd.read_csv(f"{ARTIFACTS_PATH}/dev_top10_kd.csv")
        ```
        - `pd.read_csv` reads `dev_w_qrels.csv` and `dev_top10_kd.csv`. The "query" and "doc" columns are used for prediction.

    4. **File: `/code/src/late_interaction_baseline/data_loader.py`**:
        ```python
        dfiter = pd.read_csv(f"{ARTIFACTS_PATH}/msmarco/triples.train.sample.tsv", sep="\t", chunksize=10000, names=["query", "pos", "neg"])
        queries = df["query"].tolist()
        passages = df["doc"].tolist() # in TsvDatasetPredictSep
        ```
        - `pd.read_csv` reads `triples.train.sample.tsv`. "query", "pos", "neg" columns are used for training data loading. `TsvDatasetPredictSep` also reads "query" and "doc" columns.

    5. **File: `/code/src/late_interaction_baseline/precompute_embeddings.py`**:
        ```python
        df = pd.read_csv(f"{ARTIFACTS_PATH}/msmarco/collection.tsv", sep="\t", names=["docid", "doc"])
        df = pd.read_csv(data_path)
        passages = df[embd_type].tolist() # embd_type can be 'doc' or 'query'
        ```
        - `pd.read_csv` reads `collection.tsv` and `data_path`. The "doc" column from `collection.tsv` and 'doc' or 'query' column from `data_path` are used for embedding generation.

    6. **File: `/code/src/experiments/run_experiment.py`**:
        ```python
        full_df = read_data_csv(args.ds_csv_path, chunksize=None, usecols=['qid', 'label'])
        df_iter = read_data_csv(args.ds_csv_path, args.ds_chunksize)
        ```
        - `pd.read_csv` (via `read_data_csv`) reads the CSV file specified by `ds_csv_path`.

    7. **File: `/code/src/auto_encoder/ae_modeling_training.py`**:
        ```python
        dfiter = pd.read_csv(f"{ARTIFACTS_PATH}/msmarco/sample_collection.csv", chunksize=32)
        df = pd.read_csv(f"{ARTIFACTS_PATH}/dev_top10_kd.csv") # in evaluate()
        ```
        - `pd.read_csv` reads `sample_collection.csv` and `dev_top10_kd.csv`. The "doc" column from `sample_collection.csv` is used for autoencoder training.

    In all these code snippets, `pd.read_csv` is used to load data from CSV files and the content of columns like "query", "doc", "pos", "neg" is used for further processing by tokenizers and models. There is no input validation on the content read from these CSV files.

* Security Test Case:
    1. **Prepare a malicious CSV file:** Create a CSV file named `collection_malicious.tsv` (or any CSV file that the code reads, e.g., `trainfile.tsv` for training) with the following content. This example targets `precompute_embeddings.py` which by default processes `collection.tsv`.
        ```tsv
        docid	doc
        1	Very long document text ... [repeat 'A' character many times, e.g., 200000 times] ... to cause potential memory issues or slowdown during tokenization.
        2	Normal document.
        ```
    2. **Replace the original CSV file (if necessary for test setup):** If you are testing in an environment where you can replace files, replace the original `collection.tsv` (or the targeted CSV) in the `ARTIFACTS_PATH/msmarco/` directory with `collection_malicious.tsv`. Alternatively, modify the code temporarily to read `collection_malicious.tsv` directly.
    3. **Run the embedding generation script:** Execute the script that processes the CSV file, for example, `src/late_interaction_baseline/precompute_embeddings.py`. You can run the example command from the `precompute_embeddings.py` file, adjusting paths if needed:
        ```bash
        python -m src.late_interaction_baseline.precompute_embeddings
        ```
        Or, if you are testing training, run the training script:
        ```bash
        python -m src.late_interaction_baseline.trainer
        ```
    4. **Observe the application behavior:** Monitor the application's memory usage and processing time. Observe if the application slows down significantly or if it throws any errors related to memory exhaustion or string processing when handling the malicious CSV file with the very long document text.
    5. **Expected outcome:** The application might exhibit performance degradation due to the extremely long string being processed. Depending on the system resources and specific tokenizer/model implementation, it might lead to increased memory usage, slower processing, or potentially errors if resources are exhausted. While not a crash or remote code execution, this demonstrates that malicious CSV input can negatively impact the application's behavior and potentially disrupt its intended operation by causing performance issues or unexpected errors due to data mishandling.

This test case demonstrates how a malicious CSV input can be crafted to negatively impact the application, highlighting the lack of input validation for CSV data. Although it might not be a critical vulnerability in terms of direct code execution, it represents a medium-rank security issue due to potential data mishandling and performance impact from processing maliciously crafted input.
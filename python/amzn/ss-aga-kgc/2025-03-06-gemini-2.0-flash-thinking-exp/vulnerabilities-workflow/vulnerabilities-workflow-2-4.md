### Vulnerability List:

- Vulnerability Name: Knowledge Graph Poisoning via Malicious Data Input
- Description:
    - An attacker crafts a malicious knowledge graph dataset.
    - A user is enticed to use this malicious dataset as input for training the SS-AGA model.
    - The user executes the `run_model.py` script, pointing to the malicious dataset directory via command-line arguments `--data_path` and `--dataset`.
    - The `src/data_loader_new.py` script loads and parses the knowledge graph data from TSV files within the specified malicious dataset directory without proper validation or sanitization.
    - The SS-AGA model is trained using this poisoned dataset.
    - As a result, the model learns incorrect or biased information embedded in the malicious data.
    - The trained model now produces misleading knowledge graph completions, reflecting the biases introduced by the attacker.
- Impact:
    - The model learns incorrect or biased information.
    - The model produces misleading knowledge graph completions.
    - The trustworthiness and utility of the SS-AGA framework are undermined.
    - Applications relying on the model's output for decision-making may lead to incorrect conclusions or actions.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - None. The project lacks input validation and sanitization mechanisms for knowledge graph datasets.
- Missing Mitigations:
    - Input data validation: Implement checks in `src/data_loader_new.py` to validate the format, schema, and content of input TSV files, ensuring they conform to expected knowledge graph structures and constraints. This should include checks for:
        - File format correctness (e.g., correct number of columns, valid delimiters).
        - Data type validation for entity and relation indices (e.g., ensuring they are integers within valid ranges).
        - Schema validation to ensure the dataset adheres to an expected knowledge graph schema.
        - Detection of anomalous or suspicious data patterns that might indicate poisoning attempts.
    - Data sanitization: Implement data cleaning and sanitization procedures in `src/data_loader_new.py` to detect and remove potentially malicious or anomalous data points from the input dataset before training. This could include:
        - Outlier detection for entity and relation properties.
        - Consistency checks across the knowledge graph data.
        - Filtering or removal of triples that violate predefined rules or constraints.
    - Monitoring and anomaly detection during training: Integrate monitoring mechanisms into `run_model.py` to track training metrics (e.g., loss, validation performance) and detect anomalies that might signal data poisoning attacks during the training process.
- Preconditions:
    - An attacker must be able to create a malicious knowledge graph dataset, including crafted TSV files for KG triples and entity information.
    - A user must be persuaded to use this malicious dataset for training the SS-AGA model.
    - The user must execute the `run_model.py` script, providing the path to the malicious dataset.
- Source Code Analysis:
    - File: `/code/run_model.py`
        - The script uses `argparse` to parse command-line arguments, including `--data_path` and `--dataset` to specify the dataset location.
        - ```python
          parser.add_argument('--data_path', default="dataset", type=str,
                              help="how many rounds to train")
          parser.add_argument('--dataset', default="dbp5l", type=str,
                              help="how many rounds to train")
          ```
        - It instantiates `ParseData` class from `src.data_loader_new` to load the dataset. No validation of dataset integrity or malicious content is performed here.
    - File: `/code/src/data_loader_new.py`
        - The `ParseData` class initializes data paths based on the provided `--data_path` and `--dataset` arguments.
        - ```python
          class ParseData(object):
              def __init__(self, args):
                  self.data_path = args.data_path + args.dataset
                  self.data_entity = self.data_path + "/entity/"
                  self.data_kg = self.data_path + "/kg/"
                  self.data_align = self.data_path + "/seed_alignlinks/"
                  self.args = args
          ```
        - The `load_kg_data` function reads KG data from TSV files using `pandas.read_csv`.
        - ```python
          def load_kg_data(self, language):
              train_df = pd.read_csv(join(self.data_kg, language + '-train.tsv'), sep='\t', header=None,names=['v1', 'relation', 'v2'])
              val_df = pd.read_csv(join(self.data_kg, language + '-val.tsv'), sep='\t', header=None,names=['v1', 'relation', 'v2'])
              test_df = pd.read_csv(join(self.data_kg, language + '-test.tsv'), sep='\t', header=None,names=['v1', 'relation', 'v2'])
              # ...
              return torch.LongTensor(triples_train), torch.LongTensor(triples_val), torch.LongTensor(triples_test), entity_num, relation_num
          ```
        - **Vulnerability**: The `load_kg_data` function directly reads data from TSV files without any validation of the file format, data types, or content. This lack of input validation allows a malicious dataset to inject arbitrary or malformed data into the training process, leading to knowledge graph poisoning.
- Security Test Case:
    1. Create a directory named `malicious_dataset` inside the `dataset` directory.
    2. Inside `malicious_dataset`, create the following structure:
        ```
        malicious_dataset/
        ├── entity/
        │   └── en.tsv
        ├── kg/
        │   ├── en-train.tsv
        │   ├── en-val.tsv
        │   └── en-test.tsv
        ├── seed_alignlinks/
        │   └── en-ja.tsv
        ├── relations.txt
        └── entity_embeddings.npy
        ```
    3. Create a malicious `en-train.tsv` file in `malicious_dataset/kg/` with the following content, designed to bias relation `1` to connect entities `0` and `1`:
        ```tsv
        0	1	1
        0	1	1
        0	1	1
        0	1	1
        0	1	1
        # ... add many more lines of '0\t1\t1' to amplify the bias
        # Add some valid triples to avoid loading errors
        2	2	3
        4	3	5
        ```
    4. Copy `en.tsv` from a legitimate dataset (e.g., `dataset/dbp5l/entity/en.tsv`) to `malicious_dataset/entity/en.tsv`.
    5. Copy `en-val.tsv` and `en-test.tsv` from a legitimate dataset (e.g., `dataset/dbp5l/kg/`) to `malicious_dataset/kg/`.
    6. Copy `en-ja.tsv` from a legitimate dataset (e.g., `dataset/dbp5l/seed_alignlinks/`) to `malicious_dataset/seed_alignlinks/en-ja.tsv`.
    7. Copy `relations.txt` and `entity_embeddings.npy` from a legitimate dataset (e.g., `dataset/dbp5l/`) to `malicious_dataset/`.
    8. Run the training script, pointing to the malicious dataset:
        ```bash
        python run_model.py --data_path dataset/ --dataset malicious_dataset --target_language en --use_default
        ```
    9. After training completes, evaluate the model. You can modify `src/validate.py` or `run_model.py` to add specific test cases to check if the model is now biased towards predicting relation `1` between entities `0` and `1`. For example, add a test case that checks the rank of the true tail entity for a query (head=`0`, relation=`1`). If the poisoning is successful, the model should rank entity `1` highly for this query, even if it is not a valid completion in a legitimate knowledge graph.
    10. Observe the model's performance. If the model exhibits a noticeable bias in knowledge graph completion as intended by the malicious data (e.g., incorrectly completing triples with relation `1` between entities `0` and `1`), the vulnerability is confirmed.
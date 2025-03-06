## Combined Vulnerability List

### Vulnerability Name: Unsafe Deserialization of Entity Embeddings via `numpy.load`

#### Description:
The application loads entity embeddings from the `entity_embeddings.npy` file using the `numpy.load` function in the `/code/src/data_loader_new.py` file. The `numpy.load` function, when used with default settings or `allow_pickle=True` (which is the default in many numpy versions and implicitly assumed if not set otherwise), is vulnerable to arbitrary code execution if the provided `.npy` file is maliciously crafted. An attacker could replace the legitimate `entity_embeddings.npy` file with a malicious one containing embedded Python objects. When the application loads this file using `numpy.load`, the embedded Python objects will be deserialized and executed, potentially leading to arbitrary code execution on the server or the user's machine running the application.

**Step-by-step trigger:**
1.  An attacker crafts a malicious `entity_embeddings.npy` file. This file is created using `numpy.save` with `allow_pickle=True` and contains embedded Python code, for example using `pickle` to serialize a malicious object.
2.  The attacker replaces the legitimate `entity_embeddings.npy` file in the designated dataset directory (e.g., `dataset/dbp5l/entity_embeddings.npy` or `dataset/epkg/entity_embeddings.npy`) with the malicious file. This replacement could be achieved through various means depending on the deployment scenario, such as exploiting other vulnerabilities or social engineering. For a local setup, direct file replacement is sufficient for testing.
3.  The user or system administrator executes the `run_model.py` script, for example, using the command `python run_model.py --target_language ja --use_default`.
4.  During the data loading phase, the `ParseData.load_data()` function in `/code/src/data_loader_new.py` is called.
5.  Inside `ParseData.load_data()`, the line `entity_bert_emb = np.load(self.data_path + "/entity_embeddings.npy")` is executed.
6.  `numpy.load` deserializes the `entity_embeddings.npy` file. If the file is malicious and contains pickled Python objects, `numpy.load` will execute the embedded code as part of the deserialization process.
7.  The attacker's malicious code is executed on the machine running the script, potentially granting the attacker control over the system or allowing them to steal sensitive information.

#### Impact:
Critical. Arbitrary code execution. An attacker who can replace the `entity_embeddings.npy` file can execute arbitrary Python code on the machine running the SS-AGA framework. This could lead to complete compromise of the system, including data theft, malware installation, or denial of service.

#### Vulnerability Rank:
Critical

#### Currently Implemented Mitigations:
None. The code directly uses `numpy.load` without any input validation or security considerations regarding deserialization of untrusted data.

#### Missing Mitigations:
*   **Input Validation:** Implement checks on the loaded numpy array to ensure it conforms to the expected schema (shape, data type) before using it. This would not prevent code execution from `numpy.load` itself, but could detect unexpected or malicious data after loading if validation is designed to catch deviations from expected benign data.
*   **Secure Deserialization:**  Avoid using `numpy.load` with default settings on untrusted input. If possible, load the raw data and parse it manually, or use safer alternatives if available that do not execute arbitrary code during loading. In the context of numpy, using `np.load(..., allow_pickle=False)` can prevent the execution of arbitrary code, but it requires the `.npy` file to be saved without pickle, which might not be feasible if the data naturally contains Python objects. For numerical embeddings, it's likely the data can be saved without pickle.
*   **Principle of Least Privilege:** Ensure that the application runs with the minimum necessary privileges. This can limit the damage an attacker can do even if they achieve code execution. However, it does not prevent the vulnerability itself.
*   **Integrity Checks:** Implement integrity checks (e.g., cryptographic signatures or checksums) for the `entity_embeddings.npy` file to ensure that it has not been tampered with. This would require a mechanism to securely store and verify the integrity information.

#### Preconditions:
1.  The attacker must be able to replace the `entity_embeddings.npy` file in the dataset directory accessible to the application.
2.  The application must be executed by a user or system with sufficient privileges for the attacker's malicious code to cause significant harm.

#### Source Code Analysis:

1.  **File:** `/code/src/data_loader_new.py`
2.  **Function:** `ParseData.load_data()`
3.  **Vulnerable Line:**
    ```python
    entity_bert_emb = np.load(self.data_path + "/entity_embeddings.npy")
    ```
    This line directly uses `np.load` to load the `entity_embeddings.npy` file. `numpy.load` with default settings (or `allow_pickle=True`) is known to be unsafe when loading data from untrusted sources because it can deserialize and execute arbitrary Python code embedded in the `.npy` file.
4.  **No Validation:** There is no input validation on the `entity_bert_emb` variable after it is loaded from the file, nor are there any checks on the file itself before loading. The code proceeds to normalize the loaded embeddings using `normalize_fature()`, but this function does not perform any security-relevant validation.

#### Security Test Case:

**Step 1: Create a malicious `entity_embeddings.npy` file.**

```python
import numpy as np
import pickle
import os

# Malicious code to execute (e.g., create a file)
malicious_code = """
import os
os.system('touch /tmp/pwned')
print('PWNED!')
"""

# Create a malicious object that will execute code when unpickled
class Malicious载体(object):
    def __reduce__(self):
        return (os.system, (malicious_code,))

malicious_data = {
    '__class__': 'Malicious载体',
    '__reduce__': Malicious载体().__reduce__()
}

# Dummy embedding data (e.g., zeros) to make it look like a valid embedding file
dummy_embeddings = np.zeros((10, 768))

# Combine dummy data and malicious payload
payload = {'embeddings': dummy_embeddings, 'malicious': pickle.dumps(malicious_data)}

# Save the malicious payload as entity_embeddings.npy
np.save('malicious_entity_embeddings.npy', payload, allow_pickle=True)

print("Malicious entity_embeddings.npy file created.")
```

**Step 2: Replace the legitimate `entity_embeddings.npy` file.**

Assume the dataset is `dbp5l` and the target language is `ja`.  The legitimate file is likely located at `dataset/dbp5l/entity_embeddings.npy`.  Replace this file with the `malicious_entity_embeddings.npy` created in Step 1.

```bash
mkdir -p dataset/dbp5l # Ensure dataset directory exists
mv malicious_entity_embeddings.npy dataset/dbp5l/entity_embeddings.npy
```

**Step 3: Run the application.**

Execute the `run_model.py` script:

```bash
python run_model.py --target_language ja --use_default
```

**Step 4: Observe the behavior.**

*   **Expected outcome:** If the vulnerability is present, when `run_model.py` is executed, the malicious code embedded in `malicious_entity_embeddings.npy` will be executed by `numpy.load`. In this test case, the malicious code is designed to create a file named `/tmp/pwned` and print "PWNED!".
*   **Verification:** Check if the file `/tmp/pwned` exists after running the script. Also, observe the output in the console for the "PWNED!" message. If both are present, it confirms arbitrary code execution.

**Cleanup after test:**
Remember to remove the malicious file and restore the original `entity_embeddings.npy` to prevent unintended consequences.

This test case demonstrates that by replacing the `entity_embeddings.npy` file with a malicious one, an attacker can achieve arbitrary code execution when the application loads the data, confirming the critical vulnerability due to unsafe deserialization.

====================================================================================================

### Vulnerability Name: Data Poisoning in Knowledge Graph Data

#### Description:
    An attacker can poison the knowledge graph data used for training the SS-AGA model. This can be achieved by crafting a malicious knowledge graph dataset or by modifying existing knowledge graph data files (e.g., `xx-train.tsv`, `xx-val.tsv`, `xx-test.tsv` in the `dataset/dbp5l/kg` or `dataset/epkg/kg` folders). A user is then enticed to use this malicious dataset as input for training, either by providing a path to a malicious dataset directory via command-line arguments `--data_path` and `--dataset`, or by unknowingly using replaced malicious data files. When the `ParseData` class in `src/data_loader_new.py` loads the knowledge graph data, it reads the malicious data from these files without proper validation or sanitization. The `KnowledgeGraph` class in `src/knowledgegraph_pytorch.py` stores this poisoned data and uses it for training. During training in `run_model.py`, the `SSAGA` model in `src/ssaga_model.py` is trained on the poisoned knowledge graph data. Consequently, the poisoned data leads the model to learn incorrect relationships between entities, resulting in flawed and incorrect knowledge graph completions.

**Step-by-step trigger:**
1. An attacker crafts a malicious knowledge graph dataset, including crafted TSV files for KG triples and entity information, or modifies existing KG data files to inject malicious triples.
2. The attacker replaces the original data files with the malicious ones or provides a malicious dataset to the user.
3. A user is enticed to use this malicious dataset for training the SS-AGA model.
4. The user executes the `run_model.py` script, pointing to the malicious dataset directory via command-line arguments `--data_path` and `--dataset`.
5. The `ParseData` class in `src/data_loader_new.py` loads and parses the knowledge graph data from TSV files within the specified malicious dataset directory without proper validation or sanitization.
6. The SS-AGA model is trained using this poisoned dataset.
7. The model learns incorrect or biased information embedded in the malicious data.
8. The trained model now produces misleading knowledge graph completions, reflecting the biases introduced by the attacker.

#### Impact:
The knowledge graph completion model becomes unreliable and generates incorrect or misleading knowledge graph completions. This can severely degrade the performance of any downstream applications relying on the knowledge graph completions. For research purposes, this can lead to incorrect research findings and conclusions. The trustworthiness and utility of the SS-AGA framework are undermined. Applications relying on the model's output for decision-making may lead to incorrect conclusions or actions.

#### Vulnerability Rank:
High

#### Currently Implemented Mitigations:
None. The code does not implement any input validation or sanitization mechanisms to detect or prevent data poisoning attacks.

#### Missing Mitigations:
*   **Input data validation:** Implement checks in `src/data_loader_new.py` to validate the format, schema, and content of input TSV files, ensuring they conform to expected knowledge graph structures and constraints. This should include checks for:
    *   File format correctness (e.g., correct number of columns, valid delimiters).
    *   Data type validation for entity and relation indices (e.g., ensuring they are integers within valid ranges).
    *   Schema validation to ensure the dataset adheres to an expected knowledge graph schema.
    *   Detection of anomalous or suspicious data patterns that might indicate poisoning attempts.
*   **Data sanitization:** Implement data cleaning and sanitization procedures in `src/data_loader_new.py` to detect and remove potentially malicious or anomalous data points from the input dataset before training. This could include:
    *   Outlier detection for entity and relation properties.
    *   Consistency checks across the knowledge graph data.
    *   Filtering or removal of triples that violate predefined rules or constraints.
*   **Monitoring and anomaly detection during training:** Integrate monitoring mechanisms into `run_model.py` to track training metrics (e.g., loss, validation performance) and detect anomalies that might signal data poisoning attacks during the training process.
*   **Data provenance and integrity checks:** Verify the source and integrity of the knowledge graph data to ensure it has not been tampered with.

#### Preconditions:
1.  An attacker must be able to create a malicious knowledge graph dataset, including crafted TSV files for KG triples and entity information, or modify existing KG data files.
2.  A user must be persuaded to use this malicious dataset for training the SS-AGA model, either by using a malicious dataset directory or unknowingly using replaced malicious data files.
3.  The user must execute the `run_model.py` script, providing the path to the malicious dataset.

#### Source Code Analysis:
*   **File:** `/code/run_model.py`
    *   The script uses `argparse` to parse command-line arguments, including `--data_path` and `--dataset` to specify the dataset location.
        ```python
        parser.add_argument('--data_path', default="dataset", type=str,
                            help="how many rounds to train")
        parser.add_argument('--dataset', default="dbp5l", type=str,
                            help="how many rounds to train")
        ```
    *   It instantiates `ParseData` class from `src.data_loader_new` to load the dataset. No validation of dataset integrity or malicious content is performed here.
*   **File:** `/code/src/data_loader_new.py`
    *   The `ParseData` class initializes data paths based on the provided `--data_path` and `--dataset` arguments.
        ```python
        class ParseData(object):
            def __init__(self, args):
                self.data_path = args.data_path + args.dataset
                self.data_entity = self.data_path + "/entity/"
                self.data_kg = self.data_path + "/kg/"
                self.data_align = self.data_path + "/seed_alignlinks/"
                self.args = args
        ```
    *   The `load_kg_data` function reads KG data from TSV files using `pandas.read_csv`.
        ```python
        def load_kg_data(self, language):
            train_df = pd.read_csv(join(self.data_kg, language + '-train.tsv'), sep='\t', header=None,names=['v1', 'relation', 'v2'])
            val_df = pd.read_csv(join(self.data_kg, language + '-val.tsv'), sep='\t', header=None,names=['v1', 'relation', 'v2'])
            test_df = pd.read_csv(join(self.data_kg, language + '-test.tsv'), sep='\t', header=None,names=['v1', 'relation', 'v2'])
            # ...
            return torch.LongTensor(triples_train), torch.LongTensor(triples_val), torch.LongTensor(triples_test), entity_num, relation_num
        ```
    *   **Vulnerability**: The `load_kg_data` function directly reads data from TSV files without any validation of the file format, data types, or content. This lack of input validation allows a malicious dataset to inject arbitrary or malformed data into the training process, leading to knowledge graph poisoning.

#### Security Test Case:
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
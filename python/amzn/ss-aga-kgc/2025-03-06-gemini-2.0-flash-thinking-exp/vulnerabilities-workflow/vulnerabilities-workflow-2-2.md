- Vulnerability Name: Data Poisoning in Knowledge Graph Data
- Description:
    1. An attacker crafts malicious knowledge graph data files (e.g., `xx-train.tsv`, `xx-val.tsv`, `xx-test.tsv` in the `dataset/dbp5l/kg` or `dataset/epkg/kg` folders).
    2. The attacker replaces the original data files with the malicious ones.
    3. When the `ParseData` class in `src/data_loader_new.py` loads the knowledge graph data, it reads the malicious data from these files.
    4. The `KnowledgeGraph` class in `src/knowledgegraph_pytorch.py` stores this poisoned data and uses it for training.
    5. During training in `run_model.py`, the `SSAGA` model in `src/ssaga_model.py` is trained on the poisoned knowledge graph data.
    6. The poisoned data leads the model to learn incorrect relationships between entities.
    7. Consequently, when the model is used for knowledge graph completion, it generates flawed and incorrect completions.
- Impact: The knowledge graph completion model becomes unreliable and generates incorrect or misleading knowledge graph completions. This can severely degrade the performance of any downstream applications relying on the knowledge graph completions. For research purposes, this can lead to incorrect research findings and conclusions.
- Vulnerability Rank: High
- Currently Implemented Mitigations: None. The code does not implement any input validation or sanitization mechanisms to detect or prevent data poisoning attacks.
- Missing Mitigations:
    - Input data validation: Implement checks to validate the format and content of the input knowledge graph data files to detect anomalies or malicious patterns.
    - Data sanitization: Sanitize input data to remove or neutralize potentially malicious content.
    - Anomaly detection: Implement anomaly detection mechanisms to identify and flag unusual patterns in the training data that might indicate data poisoning.
    - Robust training techniques: Explore and implement robust training techniques that are less susceptible to data poisoning attacks, such as outlier removal or robust loss functions.
    - Data provenance and integrity checks: Verify the source and integrity of the knowledge graph data to ensure it has not been tampered with.
- Preconditions: The attacker needs to have the ability to replace or modify the knowledge graph data files used by the system, or to provide maliciously crafted data files as input to the training process. For an external attacker, this might be possible if the data loading process is not properly secured or if the attacker can compromise the data source.
- Source Code Analysis:
    - `src/data_loader_new.py`: The `ParseData.load_kg_data` function reads knowledge graph data from tsv files based on filenames.
    ```python
        def load_kg_data(self, language):
            train_df = pd.read_csv(join(self.data_kg, language + '-train.tsv'), sep='\t', header=None,names=['v1', 'relation', 'v2'])
            val_df = pd.read_csv(join(self.data_kg, language + '-val.tsv'), sep='\t', header=None,names=['v1', 'relation', 'v2'])
            test_df = pd.read_csv(join(self.data_kg, language + '-test.tsv'), sep='\t', header=None,names=['v1', 'relation', 'v2'])
            ...
            triples_train = train_df.values.astype(np.int)
            triples_val = val_df.values.astype(np.int)
            triples_test = val_df.values.astype(np.int)
            return torch.LongTensor(triples_train), torch.LongTensor(triples_val), torch.LongTensor(triples_test), entity_num, relation_num
    ```
    - If the files `xx-train.tsv`, `xx-val.tsv`, `xx-test.tsv` are replaced with malicious content, `pd.read_csv` will read the malicious data.
    - `src/knowledgegraph_pytorch.py`: The `KnowledgeGraph` class stores the loaded data.
    ```python
    class KnowledgeGraph(nn.Module):
        def __init__(self, lang, kg_train_data, kg_val_data, kg_test_data, num_entity, num_relation, is_supporter_kg, ...):
            ...
            self.train_data = kg_train_data  # training set
            self.val_data = kg_val_data
            self.test_data = kg_test_data
            ...
            self.h_train, self.r_train, self.t_train = self.train_data[:, 0], self.train_data[:, 1], self.train_data[:, 2]
            self.h_val, self.r_val, self.t_val = self.val_data[:, 0], self.val_data[:, 1], self.val_data[:, 2]
            self.h_test, self.r_test, self.t_test = self.test_data[:, 0], self.test_data[:, 1], self.test_data[:, 2]
    ```
    - `run_model.py`: The `main` function uses `ParseData` to load data and trains the model.
    ```python
        dataset = ParseData(args)
        kg_object_dict, seeds_masked, seeds_all, entity_bert_emb = dataset.load_data()
        ...
        for i in range(args.round):
            ...
            train_kg_batch(args,kg_object_dict[args.target_language], optimizer, args.epoch10, model)
            for kg1_name in src_langs:
                kg1 = kg_object_dict[kg1_name]
                train_kg_batch(args, kg1, optimizer, args.epoch11, model)
    ```
    - The training process uses the poisoned data loaded into `kg_object_dict`.
- Security Test Case:
    1. Prepare a malicious training data file, e.g., `dataset/dbp5l/kg/ja-train.tsv`. This file should contain triples that introduce incorrect relationships. For example, create triples that contradict existing knowledge or introduce false statements. A simple example could be to change the tail entity in some triples to an incorrect entity, or to introduce new triples with wrong relations.
    2. Replace the original `dataset/dbp5l/kg/ja-train.tsv` file with the malicious file.
    3. Run the `run_model.py` script with the target language set to 'ja' and using default settings: `python run_model.py --target_language ja --use_default`.
    4. After training, run the test or validation using `run_model.py` or by manually using the `Tester` class in `src/validate.py`.
    5. Observe the performance metrics (Hits@1, Hits@10, MRR) on the test set. Compare the metrics with the performance when trained on clean data. A significant degradation in performance, especially an increase in incorrect completions related to the poisoned data, would indicate successful data poisoning.
    6. To further verify the poisoning, manually inspect some knowledge graph completions generated by the poisoned model and check for the injected incorrect relationships. For example, query for the head and relation from the poisoned triples and check if the predicted tail is the intended incorrect tail.
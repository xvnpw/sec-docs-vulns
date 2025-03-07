### Vulnerability List

- Vulnerability Name: Malicious Pre-training Data Injection
- Description:
    1. An attacker crafts a malicious pre-training dataset. This dataset could contain biased, harmful, or backdoored content.
    2. The attacker convinces a user to use this malicious dataset as input for pre-training the Korean language model, instead of using trusted and verified datasets like Wiki Dump or CC-100. This could be achieved through social engineering, by hosting the malicious dataset on a seemingly legitimate website, or by sharing it through file-sharing platforms.
    3. The user, following the project's guidelines, uses the scripts `prepare_corpus.py`, `train_tokenizer.py`, `prepare_pretrain_data.py`, and `prophetnet-ko_pretrain.py` with the attacker-provided malicious dataset.
    4. The script `prepare_corpus.py` (if modified to use the malicious source or if the user directly provides a malicious file) processes the data.
    5. `train_tokenizer.py` trains a tokenizer on the malicious corpus.
    6. `prepare_pretrain_data.py` prepares the data in a format suitable for pre-training.
    7. `prophetnet-ko_pretrain.py` pre-trains the ProphetNet-Ko model using the malicious data and the malicious tokenizer.
    8. The resulting pre-trained language model is now compromised. It may exhibit biased or harmful behavior, generate inappropriate content, or underperform in intended tasks depending on the nature of the injected malicious data.

- Impact:
    - The pre-trained language model can generate biased, harmful, or inappropriate text.
    - The model's performance on downstream tasks can be degraded.
    - If the malicious data includes sensitive information, the model might inadvertently leak this information in its generated text.
    - The credibility and trustworthiness of the language model and applications using it are severely damaged.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    - None. The project code does not include any mechanisms to validate the integrity or source of the pre-training data.

- Missing Mitigations:
    - **Input Validation and Sanitization:** Implement checks to validate the source and integrity of the pre-training datasets. This could include:
        - Using checksums or digital signatures to verify the datasets' authenticity.
        - Downloading datasets from trusted and official sources only, and hardcoding these sources in the scripts.
        - Implementing data sanitization steps to detect and remove potentially harmful content from the datasets before training.
    - **Documentation and Warnings:** Clearly document the risks of using untrusted or unverified datasets for pre-training. Warn users about the potential for malicious data injection and its consequences in `README.md` and other relevant documentation files.

- Preconditions:
    - The attacker must be able to provide a malicious dataset to the user.
    - The user must choose to use this malicious dataset for pre-training, either unknowingly or due to lack of security awareness.

- Source Code Analysis:
    - `script/prepare_corpus.py`: This script is responsible for downloading and preparing the pre-training corpus.
        ```python
        cc100_ko = load_dataset("cc100", lang="ko") # Downloads from HuggingFace datasets which is generally trusted, but still a potential point.
        wiki_ko = load_dataset("text", data_files="./wiki_ko.txt")["train"] # Loads local file, potential injection point if user replaces with malicious file.
        namuwikitext = Korpora.load("namuwikitext") # Downloads from Korpora, needs trust in Korpora.
        korean_petitions = Korpora.load("korean_petitions") # Downloads from Korpora, needs trust in Korpora.
        ```
        The script relies on external data sources. If an attacker can compromise these sources or trick the user into using a malicious local file (`wiki_ko.txt`), they can inject malicious data. There is no validation of the content downloaded or loaded.
    - `script/prepare_pretrain_data.py` and `script/prophetnet-ko_pretrain.py`: These scripts use the datasets prepared by `prepare_corpus.py` without any further validation. They directly process and use this data for tokenizer training and model pre-training.

- Security Test Case:
    1. **Prepare Malicious Dataset:** Create a text file named `malicious_wiki_ko.txt` containing harmful text, for example, hate speech or propaganda.
    2. **Modify `prepare_corpus.py`:**  Change the `wiki_ko` data loading part in `script/prepare_corpus.py` to use the malicious file:
        ```python
        wiki_ko = load_dataset("text", data_files="./malicious_wiki_ko.txt")["train"]
        ```
    3. **Run Data Preparation and Pre-training Scripts:** Execute the following scripts in order:
        ```bash
        python script/prepare_corpus.py
        python script/train_tokenizer.py
        python script/prepare_pretrain_data.py
        python script/prophetnet-ko_pretrain.py
        ```
    4. **Run Demo Application:** Run the demo application `demo/app.py` using the pre-trained model generated in the previous steps.
    5. **Test Model Output:** Input various contexts into the demo application and observe the generated questions. Compare the generated questions with those from a model pre-trained on legitimate data. Check if the model trained on malicious data generates harmful, biased, or nonsensical questions or if it reflects the harmful content from `malicious_wiki_ko.txt`. For example, if `malicious_wiki_ko.txt` contains hate speech against a certain group, test if the generated questions are biased against that group.
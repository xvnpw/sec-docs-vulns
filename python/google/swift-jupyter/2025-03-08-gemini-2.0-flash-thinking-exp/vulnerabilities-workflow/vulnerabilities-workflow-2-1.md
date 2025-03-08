- Vulnerability Name: Path Traversal in `%include` Directive
- Description:
  1. An attacker crafts a Swift notebook containing a cell with the `%include` directive.
  2. The `%include` directive is followed by a filename string.
  3. The attacker provides a filename string that includes path traversal sequences like `../` to navigate to directories outside the intended include paths.
  4. When the Swift kernel processes this cell, the `_read_include` function is called.
  5. The `_read_include` function attempts to open the specified file by joining the provided filename with predefined include paths, which include the directory of `swift_kernel.py` and the current working directory.
  6. Due to the lack of sanitization of the filename, the path traversal sequences are not removed or neutralized.
  7. The `open()` function resolves the path, potentially leading outside the intended directory.
  8. The content of the traversed file is then included in the preprocessed code and sent to the Swift interpreter.
  9. If the attacker includes a Swift file, it can lead to arbitrary code execution when the cell is executed. If a non-Swift file is included, it can lead to arbitrary file reading, as the content might be displayed as output or processed by subsequent Swift code if it's syntactically valid Swift.
- Impact:
  - High
  - Arbitrary File Reading: An attacker can read any file on the server's filesystem that the Swift kernel process has access to. This could include sensitive configuration files, source code, or data.
  - Arbitrary Code Execution: If the attacker includes a Swift file containing malicious code, they can execute arbitrary code on the server when the notebook cell is executed. This could lead to complete compromise of the server running the Jupyter kernel.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
  - None. The code directly uses the provided filename in the `%include` directive without any sanitization or validation against path traversal sequences.
- Missing Mitigations:
  - Path Sanitization: Implement sanitization of the filename in the `_read_include` function to remove path traversal sequences like `../` and `./`.
  - Path Validation: Validate that the resolved file path is within the intended directory or a set of allowed directories. Use secure path handling functions to resolve paths and check for canonicalization.
  - Restrict Include Paths: Limit the `include_paths` to only necessary directories and ensure the current working directory is not inadvertently exposed if not needed.
- Preconditions:
  - The attacker needs to be able to create and execute Swift notebooks on a Swift-Jupyter instance. This is typically the standard access for users of Jupyter environments.
- Source Code Analysis:
  1. In `swift_kernel.py`, the `_preprocess_line` function handles line-by-line preprocessing of the code cell.
  2. It uses the regex `r'^\s*%include (.*)$'` to identify lines starting with `%include`.
  ```python
  def _preprocess_line(self, line_index, line):
      include_match = re.match(r'^\s*%include (.*)$', line)
      if include_match is not None:
          return self._read_include(line_index, include_match.group(1))
      # ... other preprocessing directives ...
      return line
  ```
  3. If an `%include` directive is found, the `_read_include` function is called with the rest of the line (filename).
  ```python
  def _read_include(self, line_index, rest_of_line):
      name_match = re.match(r'^\s*"([^"]+)"\s*$', rest_of_line)
      if name_match is None:
          raise PreprocessorException(...)
      name = name_match.group(1)

      include_paths = [
          os.path.dirname(os.path.realpath(sys.argv[0])), # Directory of swift_kernel.py
          os.path.realpath("."), # Current working directory
      ]

      code = None
      for include_path in include_paths:
          try:
              with open(os.path.join(include_path, name), 'r') as f: # Vulnerable path joining
                  code = f.read()
          except IOError:
              continue
      if code is None:
          raise PreprocessorException(...)
      return '\n'.join([
          '#sourceLocation(file: "%s", line: 1)' % name,
          code,
          '#sourceLocation(file: "%s", line: %d)' % (
              self._file_name_for_source_location(), line_index + 1),
          ''
      ])
  ```
  4. The `_read_include` function extracts the filename `name` from the directive.
  5. It defines `include_paths` which include the directory of the `swift_kernel.py` script and the current working directory.
  6. Critically, it uses `os.path.join(include_path, name)` to construct the file path without any validation or sanitization of `name`. If `name` contains `../`, `os.path.join` will resolve the path, potentially leading to directory traversal.
  7. The `open()` function then opens the file at the potentially traversed path.
- Security Test Case:
  1. Set up a Swift-Jupyter environment as described in the `README.md`.
  2. Create a new Swift notebook in Jupyter.
  3. In the first cell of the notebook, enter the following code to attempt to read the `/etc/passwd` file (or any other accessible sensitive file on the server):
  ```swift
  %include "../../../../../../../../../../../../etc/passwd"
  ```
  4. Execute the cell.
  5. Observe the output of the cell. If the vulnerability is present, the content of the `/etc/passwd` file (or the target sensitive file) will be displayed as output in the notebook cell. This confirms arbitrary file reading.
  6. To test for potential code execution (if including Swift files from outside), create a simple Swift file with malicious code outside the intended directory, for example, in `/tmp/malicious.swift`:
  ```swift
  import Foundation
  print("Malicious code executed!")
  let task = Process()
  task.executableURL = URL(fileURLWithPath: "/bin/bash")
  task.arguments = ["-c", "touch /tmp/pwned"]
  try! task.run()
  task.waitUntilExit()
  ```
  7. In the Swift notebook, include this file using path traversal:
  ```swift
  %include "../../../../../tmp/malicious.swift"
  ```
  8. Execute this cell and subsequent cells.
  9. Check if the file `/tmp/pwned` is created, indicating code execution from the included file.
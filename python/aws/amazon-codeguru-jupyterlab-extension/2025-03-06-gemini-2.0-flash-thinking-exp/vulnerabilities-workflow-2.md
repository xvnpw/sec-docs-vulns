## Vulnerability Report

### Command Injection in Notebook Conversion

- **Description:**
    1. A malicious user crafts a Jupyter notebook containing a code cell with specially designed content to inject shell commands.
    2. The user scans this notebook using the Amazon CodeGuru JupyterLab extension.
    3. The extension utilizes `parseNotebookIntoScript.py` to convert the notebook into a Python script for analysis.
    4. Due to insufficient sanitization in the `parseNotebookIntoScript.py` script, malicious shell commands embedded within the notebook cell are directly incorporated into the generated Python script. The `is_command` function, intended to prevent command execution, is easily bypassed.
    5. While the injected code is not directly executed by the CodeGuru scan itself, the generated Python file now contains attacker-controlled shell commands.
    6. If this generated Python file is subsequently processed by the CodeGuru Security service or inadvertently executed by the user or another tool, the injected malicious commands will be executed, leading to arbitrary code execution in the user's environment or on the server processing the script.

- **Impact:**
    Arbitrary code execution on the user's machine or the server where JupyterLab is running. An attacker could potentially gain full control of the system by crafting a malicious notebook. This can lead to severe consequences such as:
    - Data exfiltration and theft of sensitive information.
    - Installation of malware, ransomware, or other malicious software.
    - Complete system compromise, allowing the attacker to perform any action on the affected machine.
    - Further exploitation and lateral movement within the network.

- **Vulnerability Rank:** Critical

- **Currently Implemented Mitigations:**
    - The `is_command` function in `/code/amazon_codeguru_jupyterlab_extension/parseNotebookIntoScript.py` attempts to comment out lines starting with certain shell commands (`cd`, `ls`, `pip`).
    ```python
    commands = ['cd', 'ls', 'pip']
    def is_command(line):
      for command in commands:
        if line.lstrip().startswith(command):
          return True
      return False
    ```
    This mitigation is located in `/code/amazon_codeguru_jupyterlab_extension/parseNotebookIntoScript.py`. However, it is easily bypassed due to its limited scope and simple string matching.

- **Missing Mitigations:**
    - **Robust Input Sanitization:** Implement comprehensive sanitization and validation of notebook cell content before incorporating it into the generated Python script. This should go beyond simple blacklisting of a few commands.
    - **Secure Code Generation:** Employ secure code generation techniques, such as using Abstract Syntax Tree (AST) manipulation, instead of string concatenation to construct the Python script. This would prevent direct code injection vulnerabilities.
    - **Sandboxing:** Isolate the notebook conversion and analysis process within a sandboxed environment. This would limit the potential damage if code injection occurs by restricting the permissions and access of the conversion process.
    - **Disallow Shell Commands:**  Consider completely disallowing or strictly controlling the use of shell commands within notebooks processed by the extension. If shell commands are necessary, implement a secure and controlled mechanism for their execution.
    - **Input Validation and Filtering:** Thoroughly validate and filter the content of Jupyter notebooks to remove or neutralize any potentially harmful shell commands or code constructs before processing them.

- **Preconditions:**
    - The user must install and enable the Amazon CodeGuru JupyterLab extension.
    - The user must open and scan a maliciously crafted Jupyter notebook using the extension.
    - The attacker needs to be able to provide or convince the user to open a malicious Jupyter notebook.

- **Source Code Analysis:**
    1. **File:** `/code/amazon_codeguru_jupyterlab_extension/parseNotebookIntoScript.py`
    2. **Function:** `run(inp, out)`
    3. The `run` function processes the input notebook file (`inp`) and writes the generated Python script to the output file (`out`). It iterates through each cell in the notebook.
    4. For 'code' cells, the code extracts the source code (`cell['source']`).
    5. The code then iterates through lines of code in a cell, concatenating them into `codeStr`.
    6. `ipython2python(codeStr)` function (not detailed in provided snippets) is called, likely for IPython syntax conversion.
    7. `is_command(code[0])` is called to check the first line of single-line code cells for a limited set of commands (`cd`, `ls`, `pip`). If a command is detected, it is commented out using `pass #`.
    8. The extracted and potentially modified `cellCode` is then appended to the `notebookScript` string using simple string concatenation:
    ```python
    for cm in cellMetaWithEC: # append executed code cells.
        notebookScript += '__CELL_EDGE__('+str(cm[0])+')\n'+cm[2]+'\n'
    for cm in cellMetaWoEC: # append unexecuted code cells in the end.
        notebookScript += '__CELL_EDGE__('+str(cm[0])+')\n'+cm[2]+'\n'
    ```
    9. **Vulnerability:** The core vulnerability lies in the direct string concatenation of `cellCode` into `notebookScript` without proper sanitization. The `is_command` function provides a weak and easily bypassable defense. Attackers can inject arbitrary code, including shell commands, by using various techniques that are not caught by `is_command`, such as:
        - Using different shell commands not in the blacklist (`cd`, `ls`, `pip`).
        - Employing shell command execution methods not starting with blacklisted commands, like backticks `` `command` ``, `$(command)`, or Python's `os.system`, `subprocess` etc.
        - Utilizing notebook "magic commands" like `!command` or `%%bash`.

    ```
    Malicious Notebook Cell Content --> parseNotebookIntoScript.py --> Vulnerable String Concatenation --> Python Script with Injected Code/Commands
    ```

- **Security Test Case:**
    1. **Create a malicious Jupyter Notebook:** Create a new file named `malicious.ipynb`.
    2. **Add a code cell with a command injection payload:** Insert the following JSON content into `malicious.ipynb`:
    ```json
    {
     "cells": [
      {
       "cell_type": "code",
       "execution_count": null,
       "metadata": {},
       "outputs": [],
       "source": [
        "import os\n",
        "os.system('touch /tmp/codeguru_pwned')"
       ]
      }
     ],
     "metadata": {
      "kernelspec": {
       "display_name": "Python 3",
       "language": "python",
       "name": "python3"
      },
      "language_info": {
       "codemirror_mode": {
        "name": "ipython",
        "version": 3
       },
       "file_extension": ".py",
       "mimetype": "text/x-python",
       "name": "python",
       "nbconvert_exporter": "python",
       "pygments_lexer": "ipython3",
       "version": "3.8.5"
      }
     },
     "nbformat": 4,
     "nbformat_minor": 4
    }
    ```
    This notebook contains a Python code cell that, when executed, will attempt to create a file named `codeguru_pwned` in the `/tmp` directory.
    3. **Execute `parseNotebookIntoScript.py`:** Run the `parseNotebookIntoScript.py` script from the command line, providing the malicious notebook as input and specifying an output Python file:
    ```sh
    python /code/amazon_codeguru_jupyterlab_extension/parseNotebookIntoScript.py malicious.ipynb malicious.py
    ```
    4. **Examine the generated Python script (`malicious.py`):** Inspect the content of `malicious.py`. It should contain the injected code, similar to:
    ```python
    def __CELL_EDGE__(x):
    	pass
    __CELL_EDGE__(0)
    import os
    os.system('touch /tmp/codeguru_pwned')
    ```
    5. **Check for file creation:** Verify if the file `/tmp/codeguru_pwned` has been created. Execute the following command in a shell with access to the JupyterLab environment:
    ```sh
    ls /tmp/codeguru_pwned
    ```
    6. **Verification:** If the command `ls /tmp/codeguru_pwned` successfully lists the file, it confirms that the injected code from the malicious notebook was executed (when the generated python script is processed or executed), demonstrating the Command Injection vulnerability. The presence of `/tmp/codeguru_pwned` proves that arbitrary code execution was achieved through notebook conversion.
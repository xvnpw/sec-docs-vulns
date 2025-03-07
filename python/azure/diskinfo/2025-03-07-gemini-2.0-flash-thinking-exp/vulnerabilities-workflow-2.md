## Combined Vulnerability List

### Arbitrary Code Execution via Malicious Vendor Extension

* Vulnerability Name: Arbitrary Code Execution via Malicious Vendor Extension
* Description:
    1. The `diskinfo` tool is designed to load and execute vendor-specific Python code to collect telemetry data from storage devices. This is achieved through the `classify.py` module, which, based on device identification, selects and utilizes functions from vendor-specific model files located in the `src/Models/` directory.
    2. An attacker could compromise an Independent Hardware Vendor's (IHV) development environment.
    3. The attacker modifies a vendor-specific model file (e.g., `src/Models/ExampleVendorFile.py`) by injecting malicious Python code into it. This malicious code could be placed within existing functions like `GETVULOGSNVME`, `NVME`, `SATA`, or even at the top level of the Python file to be executed upon import.
    4. The compromised vendor-specific model file is then included in a distribution of the `diskinfo` tool, either intentionally by the attacker or unintentionally through a compromised IHV build process.
    5. When a user runs `diskinfo` on a Windows system, the `runner.py` script executes `collectDiskInfo(classify)`.
    6. The `classify` function in `classify.py` determines the vendor and device type and, based on this, might select the compromised vendor-specific model file (e.g., `ExampleVendorFile.py`) to handle the device.
    7. The `classify` function returns a tuple containing a function (e.g., `src.Models.ExampleVendorFile.NVME`) from the vendor-specific model file.
    8. Inside `sequencer.py`, this returned function (e.g., `src.Models.ExampleVendorFile.NVME`) is called, and it returns another function `vu_log_function` (e.g., `GETVULOGSNVME`).
    9. Subsequently, in `storeNVMeDevice` or `storeATADevice` within `nvme.py` or `ata.py`, the `vu_log_function` from the compromised vendor file is executed.
    10. As the malicious code is embedded within the vendor-specific Python file and executed as part of the normal program flow, it achieves arbitrary code execution on the system running `diskinfo`.
* Impact:
    - **Critical Impact:** Successful exploitation of this vulnerability can lead to complete compromise of the IHV's system or any system running the compromised tool.
    - **Arbitrary code execution:** An attacker can execute arbitrary code on the system running `diskinfo`.
    - **Full system compromise:**  Complete compromise of the confidentiality, integrity, and availability of the system.
    - **Data exfiltration:** Potential for data exfiltration, including sensitive telemetry data.
    - **Malware installation:** Potential for malware installation or further propagation within the network.
    - **Privilege escalation:** Potential for privilege escalation depending on the context and the nature of the malicious code.
* Vulnerability Rank: Critical
* Currently Implemented Mitigations:
    - None. The tool currently does not have any mechanisms to verify the integrity or authenticity of vendor extension files. It relies on the assumption that IHVs will only use trusted and unmodified versions of the tool and its extensions. The project currently lacks any mechanisms to validate the integrity or security of vendor-specific extensions. The `README.md` suggests using private branches for vendor extensions, but this is a procedural recommendation, not a technical mitigation implemented in the code itself.
* Missing Mitigations:
    - **Vendor Extension Verification:** Implement a mechanism to verify the integrity and authenticity of vendor extension files. This could involve:
        - **Code Signing:** Require vendor extension files to be digitally signed by a trusted authority. The tool would then verify the signature before loading and executing the extension.
        - **Checksum Verification:**  Provide a mechanism (e.g., a manifest file or configuration) for IHVs to specify expected checksums or hashes of vendor extension files. The tool would verify these checksums before loading extensions.
    - **Sandboxing/Isolation:**  Consider running vendor extensions in a sandboxed or isolated environment to limit the potential impact of malicious code. This might be complex to implement in Python but could involve techniques like process isolation or restricted execution environments. Run vendor-specific extension code in a sandboxed or isolated environment with restricted privileges. This would limit the potential damage if a malicious extension is executed.
    - **Input Validation and Sanitization:** While the primary vulnerability is in loading external code, ensure that any data processed by vendor extensions is properly validated and sanitized to prevent secondary vulnerabilities within the extensions themselves (e.g., if extensions process user-provided data or external data sources). Although not directly related to code execution, ensure that any data processed by vendor extensions is properly validated and sanitized to prevent other types of vulnerabilities (e.g., data corruption, injection attacks if extensions process external data).
    - **Clear Security Guidance for IHVs:** Provide clear and prominent security guidance to IHVs, emphasizing the risks of using modified versions of the `diskinfo` tool and the importance of obtaining the tool and vendor extensions from trusted sources. Provide clear security guidelines and best practices for IHVs on how to develop and distribute their extensions securely. Emphasize the risks of introducing vulnerabilities through insecure extensions.
    - **Review and Auditing Process:** Establish a process for reviewing and auditing vendor-specific extensions before they are integrated or distributed with the tool, even in private branches.
* Preconditions:
    - The attacker must be able to create or modify a vendor extension file in the `src/Models/` directory or compromise an IHV's development environment or the distribution channel for vendor-specific extensions.
    - The attacker must successfully socially engineer an IHV into using a modified version of the `diskinfo` tool that includes the malicious extension or a user must run the `diskinfo` tool with a compromised vendor-specific extension installed.
    - The IHV or user must execute the modified `diskinfo` tool on a Windows system with a storage device that is classified to use the malicious vendor extension (or the classification logic in `classify.py` must be modified to trigger loading of the malicious extension for common devices). The `classify.py` logic must select the compromised vendor-specific extension based on the detected storage device.
* Source Code Analysis:
    1. **`runner.py`**: The `runner.py` script is the entry point of the tool and calls `collectDiskInfo` function from `sequencer.py`:
    ```python
    from src.classify     import classify
    from src.sequencer    import collectDiskInfo

    if __name__ == "__main__":

        collectDiskInfo(classify)
    ```
    2. **`sequencer.py`**: The `collectDiskInfo` function in `sequencer.py` is responsible for orchestrating the disk information collection process. It uses the `classifier` function (passed as an argument, which is `classify` from `classify.py`) to determine the vendor-specific logic:
    ```python
    from .classify     import classify # ... other imports

    def collectDiskInfo(classifier): # ... function code
        # ... disk discovery ...
        for disk in disks:
            # ... disk info extraction ...
            itsa = classifier(drive) # Calling the classify function
            logging.debug("itsa {0}".format(itsa))

            if itsa is not None:
                result = itsa() # Executing the function returned by classify
                vendor = result[0]
                bus = result[1]
                vu_log_function = result[2] # Getting the vendor unique log function
                logging.debug("Vendor = {0}, bus = {1} = {2}".format(vendor, bus, BUS_TYPE_NAMES[bus]))

                device_dict = {} # ... data collection and output ...
                if bus == BUS_TYPE_NVME:
                    storeNVMeDevice(disk_number, model, device_dict, drive, vu_log_function) # Passing vendor function
                elif bus == BUS_TYPE_SATA:
                    storeATADevice(disk_number, model, device_dict, drive, vu_log_function) # Passing vendor function
                # ... output data ...
    ```
    3. **`classify.py`**: The `classify` function in `classify.py` determines the vendor and selects the vendor-specific module. It imports `src.Models.ExampleVendorFile` and uses it as an example. The core logic is in checking `isExampleVendor(model)` and returning functions from `ExampleVendorFile.py` if the model matches, otherwise returning `UNKNOWN_SATA` or `UNKNOWN_NVME`.
    ```python
    import src.Models.ExampleVendorFile # Importing ExampleVendorFile

    from .constants                 import *
    from .Models.ExampleVendorFile  import * # Importing functions and variables from ExampleVendorFile

    def classify(drive):
        model = drive[0].upper()
        bus = drive[1]
        mnfgr = drive[2].upper()

        if (bus == BUS_TYPE_NVME):
            if (isExampleVendor(model)): # Check if it is ExampleVendor
                return (src.Models.ExampleVendorFile.NVME) # Return NVME function from ExampleVendorFile
            # ... other vendor checks ...
            else:
                return (UNKNOWN_NVME)
        elif (bus == BUS_TYPE_SATA or (bus == BUS_TYPE_SAS and mnfgr.startswith(SATA_ON_SAS_ID))):
            if (isExampleVendor(model)): # Check if it is ExampleVendor
                return (src.Models.ExampleVendorFile.SATA) # Return SATA function from ExampleVendorFile
            # ... other vendor checks ...
            else:
                return (UNKNOWN_SATA)
        else:
            return (None)
    ```
    4. **`src/Models/ExampleVendorFile.py`**: This file shows how vendor-specific logic is intended to be implemented. It defines functions like `NVME()` and `SATA()` that return vendor name, bus type, and a vendor-unique log function (`GETVULOGSNVME`). The `GETVULOGSNVME` function is designed to return a list of vendor-specific log pages to collect. A malicious vendor file could replace the legitimate log collection logic with arbitrary malicious code.
    ```python
    # ... imports and definitions ...

    def GETVULOGSNVME(drive, modelNumber, firmware): # Example vendor unique log function
        result = [
            ("Example1",    NVME_LOG_PAGE_VU1,  ExampleLog)
            ]
        # ... log page logic ...
        return(result);

    def NVME(): # Function returned for NVMe ExampleVendor
        vendor = "ExampleVendor"
        bus = BUS_TYPE_NVME
        result = (vendor, bus, GETVULOGSNVME) # Returns vendor unique log function
        return(result);

    def SATA(): # Function returned for SATA ExampleVendor
        vendor = "ExampleVendor"
        bus = BUS_TYPE_SATA
        result = (vendor, bus, None) # No vendor unique log function for SATA example
        return(result);

    def isExampleVendor(model): # Vendor classification logic
        if (model.startswith("ExampleProdId")):
            return True
        else:
            return False
    ```
    5. **`nvme.py` & `ata.py`**: `storeNVMeDevice` and `storeATADevice` receive and execute the `vu_log_function`.
    ```python
    # File: /code/src/nvme.py
    def storeNVMeDevice(disk_number, model, devicedict, drive, vu_log_function): # Receives vu_log_function
        # ...
        store_nvme_vu_log_pages(disk_number, model, devicedict, drive, vu_log_function) # Calls function to handle VU logs

    def store_nvme_vu_log_pages(disk_number, model, devicedict, drive, vu_log_function): # Receives vu_log_function
        if vu_log_function is not None: # Checks if function is provided
            vuLogs = vu_log_function(drive, model, get_fw_rev(devicedict)) # Executes the vendor provided function!
            # ... process logs ...
    ```

    **Visualization:**

    ```mermaid
    graph LR
        A[runner.py] --> B(collectDiskInfo);
        B --> C(classify);
        C -- Vendor Match --> D[ExampleVendorFile.py:NVME/SATA];
        C -- No Vendor Match --> E[UNKNOWN_SATA/NVME];
        B -- NVMe Device & Vendor Function from D --> F(storeNVMeDevice);
        B -- SATA Device & Vendor Function from D --> G(storeATADevice);
        B -- NVMe Device & No Vendor Function from E --> H(storeNVMeDevice);
        B -- SATA Device & No Vendor Function from E --> I(storeATADevice);
        D --> J(GETVULOGSNVME - Malicious Code Here);
        F -- Executes GETVULOGSNVME --> J;
        G -- Executes Vendor Function (None in Example) --> K[No Vendor Logs];
        H -- No Vendor Function --> L[No Vendor Logs];
        I -- No Vendor Function --> M[No Vendor Logs];
    ```

* Security Test Case:
    1. **Prerequisites:**
        - Access to the project source code.
        - Ability to modify files in the `src/Models/` directory.
        - A Windows system with Python installed and the `diskinfo` tool running.
    2. **Steps:**
        a. Modify the `src/Models/ExampleVendorFile.py` file to inject malicious code into the `GETVULOGSNVME` function. For example, add code to create a file named `pwned.txt` in the `C:\` drive.
        ```python
        # File: /code/src/Models/ExampleVendorFile.py (Modified)
        from ctypes import *
        from ..constants import *
        import os # Import os module

        # ... (rest of the file) ...

        def GETVULOGSNVME(drive, modelNumber, firmware):
            # Injected malicious code:
            try:
                with open("C:\\pwned.txt", "w") as f:
                    f.write("You have been PWNED!")
            except Exception as e:
                print(f"Error writing file: {e}")
            # ... (original GETVULOGSNVME code) ...
            result = [
                ("Example1",    NVME_LOG_PAGE_VU1,  ExampleLog)
                ]
            return(result);

        # ... (rest of the file) ...
        ```
        b. Ensure a storage device is connected to the test system that will be classified as an "ExampleVendor" device by `classify.py`. Based on `ExampleVendorFile.py`, any model starting with "ExampleProdId" will trigger this vendor classification. For a generic test, you can modify `classify.py` to always return `src.Models.ExampleVendorFile.NVME` for NVMe devices to force the use of the modified vendor file.
        ```python
        # File: /code/src/classify.py (Modified for testing - DO NOT USE IN PRODUCTION)
        # ... imports ...

        def classify(drive):
            model = drive[0].upper()
            bus = drive[1]
            mnfgr = drive[2].upper()

            if (bus == BUS_TYPE_NVME):
                return (src.Models.ExampleVendorFile.NVME) # Force ExampleVendorFile for NVMe
            elif (bus == BUS_TYPE_SATA or ...):
                # ... original SATA classification ...
                pass
            else:
                return (None)
        ```
        c. Run the `diskinfo` tool using `python runner.py`.
    3. **Expected Result:**
        - After running `diskinfo`, a file named `pwned.txt` should be created in the `C:\` drive of the test system, indicating successful arbitrary code execution.
        - The tool should otherwise function as expected, collecting telemetry data (though potentially with errors due to the injected code if it disrupts normal operations).

---

### Path Traversal in Output Directory

* Vulnerability Name: Path Traversal in Output Directory
* Description:
    1. The tool accepts a command-line argument to specify the output directory for telemetry JSON files.
    2. The `runner.py` script parses this argument using `ArgumentParser` and stores it in `options.file`.
    3. The `collectDiskInfo` function in `src/sequencer.py` calls `outputData` from `src/datahandle.py`, passing `options.file` as the `result_folder` argument.
    4. The `outputData` function in `src/datahandle.py` uses `os.path.join(result_folder, result_file)` to construct the full path for the output file.
    5. The `os.path.join` function concatenates the user-provided `result_folder` with the filename without proper sanitization.
    6. An attacker can provide a malicious path like "../../" or an absolute path like `/tmp` as the output directory.
    7. `os.path.join` resolves this path, allowing the tool to write JSON files to arbitrary locations outside the intended directory.
* Impact:
    - **Arbitrary File Write:** An attacker can control the destination path of the output JSON files.
    - **Overwrite Sensitive Files:** By crafting a path traversal payload, an attacker could potentially overwrite sensitive system files, leading to system instability or privilege escalation.
    - **Write to Protected Directories:** Attackers might be able to write files to directories where they normally lack write permissions.
* Vulnerability Rank: High
* Currently Implemented Mitigations:
    - None. The code directly uses the user-provided path in `os.path.join` without any validation or sanitization.
* Missing Mitigations:
    - **Input Sanitization:** Implement sanitization for the output directory path provided by the user.
    - **Path Validation:** Validate the user-provided path to ensure it is within an expected or allowed directory.
    - Use `os.path.abspath` to resolve the provided path and then check if it is a subdirectory of a designated safe output directory. Alternatively, if the intention is to only allow output to a specific directory, consider using `os.path.basename` on the user input and joining it to a fixed output directory path.
* Preconditions:
    - The attacker must have the ability to execute the `runner.py` script.
    - The attacker needs to be able to provide command-line arguments to the script, specifically the output directory path.
* Source Code Analysis:
    - File: `/code/src/sequencer.py`
        ```python
        from argparse       import ArgumentParser
        # ...
        def collectDiskInfo(classifier):
            # ...
            parser = ArgumentParser(description=usage)
            parser.add_argument("file", default=".", nargs="?") # Output directory argument
            # ...
            options = parser.parse_args()
            # ...
            outputData(device_dict, options.file, options.output) # Passing user input to outputData
        ```
    - File: `/code/src/datahandle.py`
        ```python
        import os
        import json
        # ...
        def outputData(dict, result_folder, outputToScreen):
            # ...
            result_file = "diskData{0}.json".format(int(dict['DeviceId']))
            # Vulnerable path construction using user input 'result_folder'
            with open(os.path.join(result_folder, result_file), 'w') as f:
                json.dump(dict, f, indent=2)
        ```
    - Visualization:
        ```
        User Input (directory) --> runner.py (ArgumentParser "file") --> options.file --> sequencer.py (collectDiskInfo) --> outputData(options.file) --> datahandle.py (os.path.join(result_folder, ...)) --> File System (Arbitrary Write)
        ```
* Security Test Case:
    1. Open a command-line interface in the project's root directory.
    2. Execute the `runner.py` script with a path traversal payload as the output directory argument:
        ```bash
        python runner.py "../../traversal_test_output"
        ```
        or with absolute path:
        ```bash
        python runner.py "/tmp" # Linux/macOS
        python runner.py "C:\Users\Public" # Windows
        ```
    3. After execution, check the parent directory of the project's root (or further up depending on the payload, in this case two levels up), or the absolute path directory specified (`/tmp` or `C:\Users\Public`).
    4. Verify if a file named `diskData<disk_number>.json` (e.g., `diskData0.json`, `diskData1.json`) has been created in the `traversal_test_output` directory, or in the absolute path directory, which is located outside the intended project directory.
    5. If the file is found in the specified directory outside the project, it confirms the path traversal vulnerability, as the tool wrote data to a location outside the intended output directory based on user-controlled path manipulation.
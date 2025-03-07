## Combined Vulnerability List

The following vulnerabilities have been identified in the HPC Advisor project. These vulnerabilities are considered to be of high or critical severity and pose a realistic threat to the security of the application.

### 1. Cross-Site Scripting (XSS) in GUI via User Input

* Description:
    1. An attacker crafts a malicious user input file (YAML format) containing Javascript code within a text field, for example, in the `appname` or `tags` fields.
    2. The attacker provides this malicious input file to the HPC Advisor tool via the `-u` flag when launching the GUI using the command `./hpcadvisor gui -u malicious_input.yaml`.
    3. The HPC Advisor GUI, upon processing this user input, might render the values from the YAML file on the web page without proper sanitization.
    4. If the GUI directly embeds these values into the HTML content, the malicious Javascript code from the input file will be executed within the user's browser when they access the GUI.
    5. This allows the attacker to perform actions like stealing cookies, session tokens, or redirecting the user to a malicious website.

* Impact:
    - Execution of malicious Javascript code in the victim's browser when they use the HPC Advisor GUI.
    - Potential cookie theft, session hijacking, and redirection to attacker-controlled websites.
    - Could lead to account compromise if session cookies are stolen.
    - Defacement of the GUI page.
    - Potential for further attacks against the user's system depending on the nature of the injected script.

* Vulnerability Rank: High

* Currently Implemented Mitigations:
    - None apparent from the provided project files. The files focus on functionality and deployment, not input sanitization or security in the GUI. There is no code related to GUI rendering logic provided to confirm any mitigations.

* Missing Mitigations:
    - Input sanitization and output encoding in the GUI code.
    - Context-aware output encoding should be applied when rendering user-provided data from the input YAML file in the HTML of the GUI.
    - Using a templating engine that automatically escapes HTML content by default.
    - Content Security Policy (CSP) to restrict the sources from which the browser is allowed to load resources, which can help mitigate the impact of XSS attacks.

* Preconditions:
    - The attacker needs to be able to create a YAML input file.
    - The HPC Advisor GUI must be launched using the `./hpcadvisor gui -u <input_file>` command, processing the attacker's malicious input file.
    - A user must access the HPC Advisor GUI in their browser after it has processed the malicious input.

* Source Code Analysis:
    1. **File: `/code/docs/commands.md` and `/code/docs/gui.md`**: These files document the `gui` command and the `-u USERINPUT` option. This confirms that user input can be provided via a file to the GUI.
    2. **File: `/code/src/hpcadvisor/__main__.py`**: The `gui_handler` function is defined, which imports `main_gui.main(debug, userinput)`. This indicates that the `userinput` argument, derived from the `-u` flag, is passed to the GUI's main function.
    3. **File: `/code/src/hpcadvisor/main_gui.py`**: This file contains the Streamlit application code for the GUI. It shows that user input files are read using `utils.get_userinput_from_file(user_input_file)`.  The code then uses values from this `user_input` dictionary to pre-fill text input fields in the GUI (e.g., `text_subscription = st.text_input("Azure subscription", user_input["subscription"], type="password")`).
    4. **Vulnerable Point:** The vulnerability lies in how these values from `user_input` are rendered in the Streamlit application. If Streamlit directly renders these values as HTML without proper encoding, and if a user can inject Javascript code into these input values (e.g., in `ui_defaults.yaml`), then XSS is possible. For example, if the `appname` from `ui_defaults.yaml` is displayed directly in the GUI's HTML without sanitization, injecting `<script>alert("XSS")</script>` as the `appname` in the YAML could trigger an alert box in the user's browser.
    5. **Visualization:**
        ```
        [malicious_input.yaml] --> `./hpcadvisor gui -u malicious_input.yaml` --> [hpcadvisor GUI backend (Python)] --> [Streamlit GUI rendering] --> [User's Browser (XSS execution)]
        ```
        The user input from `malicious_input.yaml` flows through the HPC Advisor backend and is rendered by Streamlit. If this rendering is not secure, XSS occurs in the user's browser.

* Security Test Case:
    1. **Prepare Malicious Input File (`malicious_input.yaml`):**
        ```yaml
        subscription: mysubscription
        skus: [Standard_HC44rs]
        rgprefix: xss-test
        appsetupurl: https://raw.githubusercontent.com/Azure/hpcadvisor/main/examples/matrixmult/appsetup_matrix.sh
        nnodes: [2]
        appname: "<script>alert('XSS Vulnerability in HPC Advisor GUI');</script> Malicious App Name"
        tags:
          appname: matrixmult
          version: v1
        region: southcentralus
        createjumpbox: false
        taskselector:
          policy: sequential
          paralleltasks: 1
        ppr: 100
        appinputs:
          appinteractions: 1
          appmatrixsize: [1000]
        ```
        Notice the `<script>alert('XSS Vulnerability in HPC Advisor GUI');</script>` injected into the `appname` field.
    2. **Launch HPC Advisor GUI with Malicious Input:**
        Open a terminal and execute the command:
        ```bash
        ./hpcadvisor gui -u malicious_input.yaml
        ```
    3. **Access the GUI in a Browser:**
        Open a web browser and navigate to the URL provided by the `hpcadvisor gui` command (typically `http://localhost:8501`).
    4. **Observe for XSS:**
        Check if an alert box appears in the browser with the message "XSS Vulnerability in HPC Advisor GUI". If the alert box appears, it confirms that the Javascript code injected in the `appname` field of `malicious_input.yaml` was executed, demonstrating a successful XSS attack.
    5. **Further Verification (Optional):**
        Inspect the HTML source code of the GUI page in the browser's developer tools. Search for the injected script or the `appname` value to confirm that it is being rendered in the HTML without proper encoding.

### 2. Cross-Site Scripting (XSS) in Browser-Based GUI via Dataset

* Description:
  1. An attacker crafts a malicious application input or manipulates the application execution to generate output data containing malicious JavaScript code.
  2. This malicious data is stored in the `dataset.json` file as part of the application execution results, specifically within fields like `appinputs`, `appmetrics`, or task output logs.
  3. A user accesses the HPC Advisor's browser-based GUI and views analysis results, plots, or advice that are generated based on the data in `dataset.json`.
  4. The GUI, while rendering the analysis results, directly embeds the unsanitized malicious JavaScript code from `dataset.json` into the HTML of the webpage.
  5. When the user's browser loads the webpage, the malicious JavaScript code is executed within the user's browser session. This can lead to various attacks, including session hijacking, cookie theft, redirection to malicious websites, or displaying misleading information within the HPC Advisor GUI.

* Impact:
  - Account Compromise: An attacker can potentially steal session cookies or other sensitive information, leading to account hijacking if the GUI has authentication or session management functionalities (though not evident in provided files).
  - Data Theft: Malicious JavaScript can be used to exfiltrate data displayed in the GUI or data accessible within the user's browser context.
  - Redirection to Malicious Sites: The injected script can redirect users to attacker-controlled websites, potentially leading to further phishing or malware attacks.
  - Defacement: The attacker can alter the content of the HPC Advisor GUI as seen by the user, displaying misleading or harmful information.

* Vulnerability Rank: High

* Currently Implemented Mitigations:
  - Based on the provided project files, there are no explicit mitigations implemented within the project to prevent XSS vulnerabilities in the browser-based GUI. The files focus on backend functionality, documentation, and example application setups, lacking any code related to GUI input sanitization or output encoding. The provided files do not contain any code for the GUI itself, so it's impossible to verify any mitigations in place within the GUI codebase from these files alone.

* Missing Mitigations:
  - Input Sanitization: The application needs to sanitize all data originating from application executions or user inputs before storing it in `dataset.json`. This involves encoding or escaping special characters that could be interpreted as HTML or JavaScript code.
  - Output Encoding: When displaying data from `dataset.json` in the browser-based GUI, the application must use proper output encoding (e.g., HTML entity encoding) to prevent the browser from interpreting data as executable code. This is crucial for data displayed in tables, text outputs, plots labels, and any other part of the GUI that renders data from the dataset.
  - Content Security Policy (CSP): Implementing a Content Security Policy (CSP) can help mitigate the impact of XSS by controlling the sources from which the browser is allowed to load resources (scripts, stylesheets, etc.). This can limit the actions an attacker can take even if they manage to inject malicious scripts.

* Preconditions:
  - An attacker needs to be able to influence the input or output of an application execution managed by HPC Advisor. This could be through direct control over the application code, input parameters, or by exploiting vulnerabilities in the application itself.
  - A user must access the browser-based GUI and view analysis results that include the attacker's malicious data.

* Source Code Analysis:
  - The provided project files do not include the source code for the browser-based GUI, making a direct source code analysis for XSS vulnerability impossible based on these files alone.
  - However, based on the project description and file structure, the following assumptions can be made:
    - The GUI is likely built using web technologies, potentially Python with Streamlit, as suggested by `pyproject.toml` and `src/hpcadvisor/main_gui.py`.
    - The GUI reads data from `dataset.json` to generate plots, advice, and display analysis results.
    - If the GUI directly embeds data from `dataset.json` into HTML without proper sanitization, it will be vulnerable to XSS.
    - For example, if the `appmetrics` or `appinputs` values from `dataset.json` are used to populate table cells or plot labels in the GUI, and these values are not HTML-encoded, then XSS is possible.

  - Visualization:
    ```
    [Application Execution] --> [Dataset Generation (dataset.json with potentially malicious data)] --> [HPC Advisor GUI (reads dataset.json)] --> [Browser (renders GUI with unsanitized data)] --> [XSS Vulnerability]
    ```

* Security Test Case:
  1. **Setup:**
     - Deploy a publicly accessible instance of HPC Advisor, if possible based on provided files (though deployment instructions are focused on Azure Batch, not GUI deployment). Alternatively, set up a local development environment if GUI source code were available.
     - Prepare a user input file and application setup script for one of the example applications (e.g., matrixmult).
     - Modify the application setup script (`appsetup_matrix.sh` for matrixmult) to include malicious JavaScript in the output. For example, within `hpcadvisor_run()`, modify the output to include a line like: `echo "HPCADVISORVAR APPEXECTIME='<script>alert(\"XSS Vulnerability\")</script>'"` or modify application input within `ui_defaults.yaml` to include `<script>alert("XSS Vulnerability")</script>` in `appinputs` values if those are reflected in output/dataset.
  2. **Execute Data Collection:**
     - Use the HPC Advisor CLI to run data collection for the modified application setup: `./hpcadvisor collect -n <deploymentname> -u <modified_ui_defaults.yaml>`.
  3. **Access GUI:**
     - Run the HPC Advisor GUI: `./hpcadvisor gui`.
     - Navigate to the sections in the GUI that display analysis results, plots, or advice (e.g., "View Plots" or "Get Advice").
     - Select the relevant data filter or deployment to view the results from the execution that included the malicious JavaScript.
  4. **Observe for XSS:**
     - Check if an alert box with "XSS Vulnerability" (or the injected JavaScript payload) appears in the browser when viewing the analysis results in the GUI.
     - Inspect the HTML source code of the GUI page using browser developer tools to confirm if the malicious JavaScript code is directly embedded in the HTML, indicating a lack of output encoding.
  5. **Expected Result:**
     - If the alert box appears and the JavaScript code is embedded in the HTML, the XSS vulnerability is confirmed. This demonstrates that unsanitized data from `dataset.json` is being directly rendered in the GUI, allowing for JavaScript injection and execution within the user's browser.

### 3. Command Injection in Task Setup Script URL

* Description:
An attacker can inject arbitrary commands into the Azure Batch compute node by providing a malicious URL for the application setup script (`appsetupurl`) in the user input configuration file (`ui_defaults.yaml`).

    1. The HPC Advisor tool reads the user input configuration file, which can be provided via the `-u` flag in the CLI or through the GUI.
    2. The `appsetupurl` value from the user input is used in the `create_setup_task` function in `batch_handler.py` to construct a shell command.
    3. This shell command, which includes a `curl` command to download the script from the provided URL and `source` command to execute it, is then executed within an Azure Batch task on a compute node.
    4. If an attacker provides a malicious URL containing command injection payloads, these payloads will be executed by the shell on the compute node during the task setup phase.

* Impact:
    * **High**: Successful command injection allows the attacker to execute arbitrary shell commands with the privileges of the Azure Batch task user (which, by default, is an administrator).
    * This can lead to:
        * **Data Breaches**: Stealing sensitive data stored on or accessible to the compute node.
        * **System Compromise**: Modifying system configurations, installing backdoors, or further compromising the Azure Batch environment.
        * **Denial of Service (DoS)**: Disrupting the availability of the compute node or the entire Azure Batch pool by executing resource-intensive commands or crashing the system.
        * **Lateral Movement**: Potentially using the compromised compute node as a stepping stone to attack other resources within the Azure environment.

* Vulnerability Rank: Critical

* Currently Implemented Mitigations:
    * None: There is no input validation or sanitization implemented for the `appsetupurl` in the provided source code. The URL is directly used to construct shell commands in `batch_handler.py`.

* Missing Mitigations:
    * **Input Validation**: Implement strict validation for the `appsetupurl` in `utils.get_userinput_from_file` or earlier in the processing flow.  The validation should check for allowed URL schemes (e.g., `https://` for trusted sources) and potentially block or sanitize special characters and command injection sequences within the URL.
    * **Command Sanitization/Parameterization**: Instead of directly embedding the `appsetupurl` into the shell command string, use parameterized commands or safer command construction techniques to prevent interpretation of malicious characters as shell commands. For example, download the script to a fixed, safe location first, and then execute it separately.
    * **Principle of Least Privilege**:  While not directly mitigating command injection, running Batch tasks with the least necessary privileges can limit the impact of a successful exploit. However, the current code elevates task privileges to admin.

* Preconditions:
    - The attacker needs to be able to provide a malicious user input configuration file (`ui_defaults.yaml`) to the HPC Advisor tool. This could be achieved if:
        * The attacker has control over the user input file if the tool is used locally.
        * In a web-based deployment (GUI), if user input fields are not properly secured and allow injection of malicious URLs. Although no GUI code is provided in PROJECT FILES, the README.md indicates a web-based GUI exists.

* Source Code Analysis:
    1. **File: `/code/src/hpcadvisor/batch_handler.py`**:
    2. **Function: `create_setup_task(jobid, appsetupurl)`**:
    3. The `appsetupurl` parameter, directly derived from user input, is used to construct the `curl` command:
       ```python
       task_commands = [
           f"/bin/bash -c 'set ; cd {anfmountdir} ; curl -sLO {app_setup_url} ; source {script_name} ; {HPCADVISOR_FUNCTION_SETUP}'"
       ]
       ```
    4. The `curl -sLO {app_setup_url}` part of the command directly uses the user-provided URL.
    5. The `task_commands` list is then used to create a `batchmodels.TaskAddParameter` object:
       ```python
       task = batchmodels.TaskAddParameter(
           id=task_id,
           user_identity=user,
           command_line=task_commands[0], # User input directly embedded here
       )
       ```
    6. This task is added to the Azure Batch job, and the `command_line` is executed on the compute node.
    7. **Visualization:**
       ```
       UserInput (ui_defaults.yaml) --> appsetupurl --> create_setup_task() --> command_line (shell command with appsetupurl) --> Azure Batch Task Execution --> Command Injection
       ```

* Security Test Case:
    1. **Setup HPC Advisor**: Ensure the HPC Advisor tool is set up and runnable, either via CLI or GUI (if accessible).
    2. **Create Malicious User Input File**: Create a file named `malicious_ui_defaults.yaml` with the following content, replacing `<YOUR_SUBSCRIPTION_ID>` and `<YOUR_REGION>` with your Azure details:
       ```yaml
       subscription: <YOUR_SUBSCRIPTION_ID>
       skus: [Standard_HC44rs]
       rgprefix: vuln-test
       appsetupurl: "https://raw.githubusercontent.com/Azure/hpcadvisor/main/examples/matrixmult/appsetup_matrix.sh; touch /tmp/pwned" # Malicious URL with command injection
       nnodes: [1]
       appname: matrixmult
       tags:
         appname: matrixmult
         version: v1
       region: <YOUR_REGION>
       createjumpbox: false
       taskselector:
         policy: sequential
         paralleltasks: 1
       ppr: 100
       appinputs:
         appinteractions: 1
         appmatrixsize: [100]
       ```
       **Note**: The `appsetupurl` is modified to append `; touch /tmp/pwned` to the legitimate URL. This will attempt to execute the `touch /tmp/pwned` command after downloading and (attempting to) execute the legitimate script.
    3. **Run Deployment and Data Collection**: Execute the following commands in the HPC Advisor CLI:
       ```bash
       ./hpcadvisor deploy create -u malicious_ui_defaults.yaml
       DEPLOYMENT_NAME=$(./hpcadvisor deploy list | grep vuln-test) # Capture deployment name, may need adjustment based on output
       ./hpcadvisor collect -n $DEPLOYMENT_NAME -u malicious_ui_defaults.yaml
       ```
    4. **Access Compute Node (Optional - for verification)**: To definitively confirm command injection, you would ideally need to access one of the Azure Batch compute nodes.  Direct SSH access might not be enabled by default. If a jumpbox or similar access is set up, you can attempt to SSH into a compute node.
    5. **Check for File Creation**: If you can access a compute node, check for the existence of the file `/tmp/pwned`. If the file exists, the command injection was successful. Alternatively, observe the task logs (stdout/stderr) in Azure Batch for any signs of the `touch` command execution or errors that might indicate successful command injection.
    6. **Expected Result**: If the vulnerability is present, the `touch /tmp/pwned` command will be executed on the Azure Batch compute node, and the `/tmp/pwned` file will be created (if you have access to verify). Even without direct access, errors in task execution or unexpected behavior could indicate successful command injection.
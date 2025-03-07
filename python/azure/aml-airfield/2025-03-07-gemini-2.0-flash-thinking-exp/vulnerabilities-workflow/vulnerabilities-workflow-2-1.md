### Vulnerability List

- Vulnerability Name: Insecure Authentication Configuration (Authentication Disabled for UI Access)
- Description:
    1. The project documentation explicitly instructs users to disable authentication for the deployed web services to access the provided HTML UI page.
    2. This is done by using `kubectl label --overwrite services [service_name] auth.enabled=false`.
    3. Disabling authentication makes the web service publicly accessible without any credentials.
    4. An attacker can access the service URL and interact with the deployed machine learning models without authorization.
- Impact:
    - Unauthorized access to the deployed machine learning models.
    - Potential misuse of the models for malicious purposes (e.g., feeding arbitrary data to the models, potentially leading to unexpected behavior or data leaks depending on the model and its application).
    - Exposure of internal service details to unauthorized users.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations:
    - The `README.md` file includes a warning box: `:warning: **!!! Note that your service will be publicly exposed if you disable authentication !!!** :warning:`. This is a documentation-level warning, not a technical mitigation.
- Missing Mitigations:
    - **Enforce Authentication:** The service should enforce authentication by default. Disabling authentication should be strongly discouraged and require explicit configuration with clear security warnings.
    - **Role-Based Access Control (RBAC):** Implement RBAC to control access to different functionalities of the service, even if basic authentication is disabled for UI access.
    - **Network Segmentation:** Deploy the service in a private network segment, not directly exposed to the public internet, even if authentication is disabled.
- Preconditions:
    1. The user must follow the documentation and explicitly disable authentication for the deployed service using `kubectl label --overwrite services [service_name] auth.enabled=false`.
    2. The service must be deployed and accessible over the network.
- Source Code Analysis:
    - **File: /code/README.md**
        - The `README.md` file in the root directory and subdirectories (e.g., `/code/MLeap/airbnb/README.md`) contains the following instructions:
        ```markdown
        :warning: **!!! Note that your service will be publicly exposed if you disable authentication !!!** :warning:

        To disable authentication of your service:

           * Get your deployed service's name:

                 kubectl get services

           * Edit your service's configuration:

                 kubectl label --overwrite services [service_name] auth.enabled=false
        ```
        - This clearly indicates that disabling authentication is a documented feature for UI access, but it comes with a significant security risk.
    - **File: /code/MLeap/airbnb/app.py, /code/TimeSeries/solar/app.py, /code/Image/inceptionv3/app.py, /code/Image/yolov3/app.py, /code/Text/deepmoji/app.py**
        - Review of all `app.py` files reveals that there is no authentication or authorization logic implemented within the Flask application itself for the `/score` and `/ui` endpoints.
        - The application logic directly serves requests to these endpoints without checking for any credentials.
        - For example, in `/code/MLeap/airbnb/app.py`:
        ```python
        @main.route('/ui', methods=['GET'])
        def html_ui():
            resp = flask.send_file('ui.html', add_etags=False)
            resp.headers['Content-Encoding'] = 'identity'
            return resp

        @main.route('/score', methods=['GET'])
        @main.route('/score', methods=['POST'])
        def score_realtime():
            # ... scoring logic ...
        ```
        - No decorators or code blocks are present to enforce authentication before serving these routes.
    - **Visualization:**
        ```mermaid
        graph LR
            A[External Attacker] --> B(Public Network);
            B --> C{Azure ML Service (Publicly Exposed)};
            C --> D[/ui Endpoint];
            C --> E[/score Endpoint];
            D -- No Authentication --> F[HTML UI Page];
            E -- No Authentication --> G[ML Model Inference];
            A -- Unauthorized Access --> C;
        ```
- Security Test Case:
    1. Deploy any of the provided services (e.g., YOLOv3) following the instructions in the `README.md`.
    2. After deployment, get the service name using `kubectl get services`.
    3. Disable authentication for the deployed service by running: `kubectl label --overwrite services [service_name] auth.enabled=false`. Replace `[service_name]` with the actual service name.
    4. Obtain the service URL using `az ml service list realtime` and `az ml service usage realtime -i [full_service_id]`.
    5. Open a web browser and navigate to `your_service_url/ui`. Verify that the UI is accessible without any login or authentication.
    6. Use `curl` or a similar tool to send a scoring request to `your_service_url/score` (e.g., using the `call.sh` script without providing an authentication key).
    7. Verify that the scoring request is successfully processed and a response is returned, demonstrating unauthorized access to the ML model.

- Vulnerability Name: Verbose Error Handling (Information Disclosure)
- Description:
    1. The Flask application's error handlers are configured to return detailed exception tracebacks in the response when errors occur during request processing.
    2. Specifically, the `app.py` files use `traceback.format_exc()` in error handlers for `ServerSideException`, `ClientSideException`, `RunFunctionException`, `TimeoutException`, and the generic `Exception` handler.
    3. These tracebacks can expose sensitive information about the server's internal state, file paths, and potentially dependency versions to an attacker.
- Impact:
    - Information Disclosure: Attackers can gain insights into the application's internal workings, potentially aiding in further attacks by revealing file paths, library versions, and code structure.
    - Debugging information intended for developers is exposed to potentially malicious users.
- Vulnerability Rank: Medium
- Currently Implemented Mitigations:
    - None. The error handlers are designed to return detailed tracebacks.
- Missing Mitigations:
    - **Generic Error Responses:** Implement error handlers that return generic, user-friendly error messages instead of detailed tracebacks in production environments.
    - **Logging:** Log detailed error information (including tracebacks) securely on the server-side for debugging purposes, but do not expose it in client responses.
    - **Conditional Error Detail:** Consider providing detailed error responses only in development/debugging modes and generic errors in production.
- Preconditions:
    1. An error must occur during the processing of a request to the web service. This could be due to invalid input, model errors, or internal server issues.
    2. The attacker must be able to trigger an error condition and observe the service's response.
- Source Code Analysis:
    - **File: /code/MLeap/airbnb/app.py, /code/TimeSeries/solar/app.py, /code/Image/inceptionv3/app.py, /code/Image/yolov3/app.py, /code/Text/deepmoji/app.py**
        - All `app.py` files contain similar error handlers like this (example from `/code/MLeap/airbnb/app.py`):
        ```python
        # Unhandled Error
        # catch all unhandled exceptions here and return the stack encountered in the response body
        @main.errorhandler(Exception)
        def unhandled_exception(error):
            main.stop_hooks()
            main.logger.debug("Unhandled exception generated")
            error_message = "Encountered Exception: {0}".format(traceback.format_exc())
            main.logger.error(error_message)
            internal_error = "An unexpected internal error occurred. {0}".format(error_message)
            return AMLResponse(internal_error, 500, json_str=False)
        ```
        - The line `error_message = "Encountered Exception: {0}".format(traceback.format_exc())` captures the full traceback and includes it in the `internal_error` message, which is then returned in the `AMLResponse`.
    - **Visualization:**
        ```mermaid
        graph LR
            A[External Attacker] --> B(Public Network);
            B --> C{Azure ML Service};
            C -- Error Triggered --> D[Error Handler in app.py];
            D --> E{traceback.format_exc()};
            E --> F[Detailed Traceback in Response];
            F --> B;
            B --> A[Attacker Gains Information];
        ```
- Security Test Case:
    1. Deploy any of the provided services (e.g., Inceptionv3).
    2. Send an invalid scoring request that is likely to cause an error. For example, for Inceptionv3, send a non-image binary data.
    3. Observe the response from the service.
    4. Verify that the response body contains a detailed Python traceback, including file paths and potentially other sensitive information. For example, sending invalid image to InceptionV3 service:
       ```bash
       curl your_service_url/score -H "Content-Type: application/json" -d '{"invalid": "input"}'
       ```
    5. Examine the response body and confirm the presence of a full traceback.

- Vulnerability Name: Outdated Dependencies (PyTorch in DeepMoji)
- Description:
    1. The DeepMoji service in `/code/Text/deepmoji/` uses an outdated version of PyTorch, specifically version 0.2.0, as specified in `/code/Text/deepmoji/conda_dependencies.yml`.
    2. Outdated dependencies may contain known security vulnerabilities that have been fixed in later versions.
    3. Using vulnerable dependencies can expose the service to potential exploits.
- Impact:
    - Increased attack surface due to known vulnerabilities in outdated PyTorch 0.2.0.
    - Potential for various exploits depending on the specific vulnerabilities present in PyTorch 0.2.0 (e.g., arbitrary code execution, denial of service).
- Vulnerability Rank: Medium (can be High or Critical depending on specific vulnerabilities in PyTorch 0.2.0)
- Currently Implemented Mitigations:
    - None. The project explicitly specifies the outdated version in the dependency file.
- Missing Mitigations:
    - **Dependency Updates:** Update PyTorch to the latest stable version in `/code/Text/deepmoji/conda_dependencies.yml`.
    - **Dependency Scanning:** Implement regular dependency scanning to identify and update vulnerable dependencies proactively.
    - **Vulnerability Monitoring:** Monitor security advisories and vulnerability databases for PyTorch and other dependencies used in the project.
- Preconditions:
    1. The DeepMoji service must be deployed and running.
    2. Attackers must be able to exploit vulnerabilities present in PyTorch 0.2.0. The feasibility and preconditions for exploiting these vulnerabilities would depend on the specific vulnerabilities present.
- Source Code Analysis:
    - **File: /code/Text/deepmoji/conda_dependencies.yml**
        - This file specifies the conda environment dependencies for the DeepMoji service:
        ```yaml
        name: deepmojienv
        channels:
          - defaults
          - soumith
        dependencies:
          - python=3.5.2
          - pytorch=0.2.0
          - torchvision
          - pip:
            - numpy
            - cython
            - pyyaml
            - scikit-learn
            - scipy
            - text-unidecode
            - emoji
        ```
        - The line `- pytorch=0.2.0` clearly indicates the use of PyTorch version 0.2.0, which is significantly outdated. Current stable PyTorch versions are much higher (e.g., 1.x or 2.x).
- Security Test Case:
    1. Deploy the DeepMoji service as instructed.
    2. Identify the PyTorch version installed in the deployed environment. This can be done by accessing the deployed container (if possible) or by modifying the `score.py` to print `torch.__version__` and checking the service logs.
    3. Verify that the installed PyTorch version is indeed 0.2.0 or a version within the 0.2.x range.
    4. Search for known Common Vulnerabilities and Exposures (CVEs) associated with PyTorch version 0.2.0. Public vulnerability databases like NIST NVD or Mitre CVE can be used for this purpose.
    5. If CVEs are found, assess their severity and exploitability in the context of the deployed service. While a direct exploit test within this project's scope might be complex and depend on specific CVEs, demonstrating the presence of the outdated and potentially vulnerable dependency is sufficient evidence of the vulnerability.
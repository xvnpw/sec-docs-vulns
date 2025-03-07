- Vulnerability Name: Insecure Service Configuration - Disabled Authentication
- Description: The service, as configured by the provided README instructions for UI testing, explicitly disables authentication. This is achieved by using the `kubectl label --overwrite services [service_name] auth.enabled=false` command, as documented in the main README. By disabling authentication, the deployed web service becomes publicly accessible to anyone who can discover its URL. This allows unauthorized users to send requests to the service, query the machine learning models, and potentially misuse them for unintended purposes. An attacker can directly interact with the `/score` endpoint or access the UI at `/ui` without needing any credentials.
- Impact: The most critical impact is unauthorized access to the deployed machine learning models. Depending on the nature of the models and the data they process, this could lead to various security breaches. For example, an attacker could:
    - Query the models for their own purposes, potentially consuming resources and impacting service availability for legitimate users (though not a denial-of-service vulnerability in itself, but a misuse of resources).
    - Gain insights into the model's behavior and potentially extract sensitive information if the model is designed to process or expose such data.
    - In some scenarios, misuse the model for malicious purposes if the model's predictions can be leveraged for harmful activities.
    - Access potentially sensitive data through the UI if the UI is designed to display model outputs in a way that could reveal such data.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations: There are no mitigations implemented in the service configuration when authentication is disabled. The README.md file contains a warning message: `:warning: **!!! Note that your service will be publicly exposed if you disable authentication !!!** :warning:`, which serves as a documentation warning but not an active mitigation.
- Missing Mitigations: The most critical missing mitigation is the enforcement of authentication for the web service.  A proper authentication mechanism should be in place to verify the identity of users or applications before granting access to the service. This could include:
    - Enabling Azure ML's built-in authentication mechanisms instead of disabling them.
    - Implementing API key-based authentication if a simpler approach is desired.
    - Utilizing more robust authentication methods like OAuth 2.0 or similar standards for production deployments.
- Preconditions:
    - The Azure ML web service must be deployed using the provided scripts.
    - The user must follow the README instructions to disable authentication for UI testing by executing the `kubectl label --overwrite services [service_name] auth.enabled=false` command.
    - The service must be publicly accessible over the internet, meaning the Azure ML deployment is not isolated within a private network.
- Source Code Analysis:
    - `/code/README.md`: This file explicitly instructs users on how to disable authentication for UI testing. It highlights the command `kubectl label --overwrite services [service_name] auth.enabled=false` and includes a warning about public exposure when authentication is disabled.
    - `/code/MLeap/airbnb/app.py`, `/code/TimeSeries/solar/app.py`, `/code/Image/inceptionv3/app.py`, `/code/Image/yolov3/app.py`, `/code/Text/deepmoji/app.py`: These `app.py` files define the Flask application that serves the machine learning models. Examining these files reveals that there is no authentication or authorization logic implemented within the application code itself. The application relies on the underlying Azure ML service infrastructure to handle authentication, which is intentionally disabled as per the README instructions. The code does not check for any API keys, tokens, or user credentials before processing requests to the `/score` or `/ui` endpoints.
    - The `deploy.sh` scripts across different model types (`/code/MLeap/airbnb/deploy.sh`, etc.) do not include any authentication configuration steps. They focus on model deployment and service creation, assuming authentication is managed separately or disabled.

- Security Test Case:
    1. Deploy the `yolov3` service by following the steps in `/code/Image/yolov3/README.md`, specifically on a Linux environment as required.
    2. Once the service is deployed and running, execute the command provided in the main `README.md` to disable authentication:
       ```bash
       kubectl label --overwrite services [service_name] auth.enabled=false
       ```
       Replace `[service_name]` with the actual name of your deployed service, which can be obtained using `kubectl get services`.
    3. Obtain the service URL. Follow the instructions in the README to get the service URL using Azure ML CLI:
       ```bash
       az ml service list realtime                            # Get your full service id
       az ml service usage realtime -i [full_service_id]      # Get your service URL
       ```
    4. Use `curl` to send a request to the `/score` endpoint of the service URL without any authentication headers or credentials. For example, using the sample image provided in the repository:
       ```bash
       curl <your_service_url>/score --data-binary @/code/Image/SampleImages/dog.jpg
       ```
       Replace `<your_service_url>` with the actual service URL obtained in the previous step and adjust the path to the sample image if needed.
    5. Observe the response. If the vulnerability exists, the service will respond with the YOLOv3 model's predictions, indicating successful unauthorized access to the service and the model. The response will be either JSON output (default) or an image if the `output=image` parameter is used, depending on the model and request.
    6. Additionally, access the UI by navigating to `<your_service_url>/ui` in a web browser. Verify that the UI is accessible and functional without any login or authentication, further confirming unauthorized access.
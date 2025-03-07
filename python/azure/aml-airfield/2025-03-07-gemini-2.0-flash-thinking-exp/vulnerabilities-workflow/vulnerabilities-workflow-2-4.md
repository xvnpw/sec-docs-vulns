- vulnerability name: Unprotected Public Endpoint due to Disabled Authentication
- description:
    1. A user deploys a machine learning model as a web service on Azure ML following the provided examples.
    2. The user intends to test the HTML UI page provided with the service.
    3. The user reads the "Test your deployed service using a UI web page" section in the `README.md` file.
    4. Following the instructions, the user executes the command `kubectl label --overwrite services [service_name] auth.enabled=false` to disable authentication for the deployed service.
    5. The user successfully tests the UI page, which now works without requiring authentication keys.
    6. After testing, the user forgets or neglects to re-enable authentication for the service.
    7. As a result, the deployed web service remains publicly accessible without any form of authentication.
    8. An external attacker can now access the `/score` endpoint of the service URL without needing any credentials.
    9. The attacker can send arbitrary requests to the machine learning model, potentially gaining unauthorized predictions or exploiting any vulnerabilities in the model itself.
- impact:
    - Public exposure of the machine learning model's prediction endpoint.
    - Unauthorized access to the machine learning model's functionalities.
    - Potential leakage of sensitive data if the model processes confidential information.
    - Misuse of the machine learning model for unintended or malicious purposes by unauthorized parties.
- vulnerability rank: High
- currently implemented mitigations:
    - A warning message is included in the `README.md` file under the "Test your deployed service using a UI web page" section. This warning explicitly states: ":warning: **!!! Note that your service will be publicly exposed if you disable authentication !!!** :warning:". This serves as a documentation-based mitigation, alerting users to the security implications of disabling authentication.
- missing mitigations:
    - Lack of automated re-enablement of authentication: The project does not provide any scripts or automated mechanisms to easily re-enable authentication after it has been disabled for UI testing. Users must manually remember and execute commands to restore authentication.
    - Absence of clear re-enablement instructions: While instructions to disable authentication are provided, the `README.md` does not explicitly detail how to re-enable authentication. This omission increases the chance of users forgetting or not knowing how to secure their endpoints again.
    - No proactive security enforcement: The deployment scripts and service configurations do not enforce authentication by default or provide options to prevent accidental disabling of authentication in production environments.
    - No reminders or alerts: The system does not provide any reminders or alerts to users about the disabled authentication, increasing the risk of leaving services unprotected unintentionally.
- preconditions:
    - The user must deploy a machine learning web service using the provided project examples and scripts.
    - The user must follow the instructions in the `README.md` to disable authentication for the purpose of testing the UI page.
    - The user must not re-enable authentication after completing UI testing, leaving the service in a publicly accessible state.
- source code analysis:
    - `/code/README.md`: This file contains the core vulnerability by explicitly instructing users how to disable authentication.
        ```markdown
        To disable authentication of your service:

           * Get your deployed service's name:

                 kubectl get services

           * Edit your service's configuration:

                 kubectl label --overwrite services [service_name] auth.enabled=false
        ```
        The `README.md` provides a direct command to disable authentication using `kubectl`. This command, when executed, modifies the Kubernetes service configuration to remove the authentication requirement.
        There is no corresponding instruction or script provided to re-enable authentication. The documentation relies solely on the user's memory and security awareness to manually re-enable it.

    - `/code/MLeap/airbnb/app.py`, `/code/TimeSeries/solar/app.py`, `/code/Image/inceptionv3/app.py`, `/code/Image/yolov3/app.py`, `/code/Text/deepmoji/app.py`: These `app.py` files are Flask applications that serve as the web service endpoint.
        - They do not contain any authentication enforcement logic within the application code itself.
        - The security of the endpoint is entirely dependent on the external Kubernetes service configuration and whether authentication is enabled or disabled at the service level using `kubectl`.
        - The application code is designed to process requests as long as they reach the `/score` endpoint, regardless of authentication status.

    - Deployment scripts (`deploy.sh` in each service directory): These scripts automate the deployment process but do not include any steps to enforce or manage authentication settings beyond the initial service creation (which defaults to authentication enabled). They do not address the vulnerability of users disabling authentication for UI testing and forgetting to re-enable it.

- security test case:
    1. Deploy the `yolov3` service by navigating to `/code/Image/yolov3` and running `./deploy.sh`.
    2. After successful deployment, obtain the service name by executing `kubectl get services` in your terminal. Let's assume the service name is `yolov3-service`.
    3. Disable authentication for the deployed service by running the command: `kubectl label --overwrite services yolov3-service auth.enabled=false`.
    4. Retrieve the service URL using the Azure ML CLI:
        ```bash
        az ml service list realtime
        ```
        Note the `service_id` (e.g., `myservice-yolov3-xxxxxxxxxx`). Then, get the service URL:
        ```bash
        az ml service usage realtime -i myservice-yolov3-xxxxxxxxxx
        ```
        Let's assume the service URL is `http://<service-url>/score`.
    5. Send a request to the `/score` endpoint without any authentication headers. For example, using `curl`:
        ```bash
        curl http://<service-url>/score --data-binary @/code/Image/SampleImages/dog.jpg
        ```
    6. Observe the response. If the service is vulnerable, it will return the prediction results (e.g., JSON output for YOLOv3) without requiring any authentication. This confirms that the endpoint is publicly accessible and unprotected.
    7. To further verify, try accessing the UI page at `http://<service-url>/ui`. It should also be accessible without any authentication prompt, confirming the disabled authentication state.
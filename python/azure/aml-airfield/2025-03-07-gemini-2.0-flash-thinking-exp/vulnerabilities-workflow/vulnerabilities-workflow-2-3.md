- Vulnerability name: Insecure Service Configuration due to Disabled Authentication for UI Testing
- Description:
    - The project provides instructions to deploy machine learning models as web services on Azure ML.
    - For UI testing purposes, the main README.md instructs users to disable authentication for the deployed service.
    - This is achieved by using the `kubectl label --overwrite services [service_name] auth.enabled=false` command, which modifies the service configuration in Kubernetes to disable authentication.
    - The README.md explicitly warns "!!! Note that your service will be publicly exposed if you disable authentication !!!".
    - If administrators follow these instructions for UI testing and fail to re-enable authentication afterwards, the web service remains publicly accessible without any form of authentication.
- Impact:
    - Unauthorized access to the deployed machine learning model web service.
    - Public exposure of the model's functionality and any data processed by it.
    - Potential misuse of the model by unauthorized users for unintended or malicious purposes.
    - If the model processes sensitive data, this could lead to data leakage and privacy violations.
- Vulnerability rank: High
- Currently implemented mitigations:
    - Warning message in the main `README.md` file ( `/code/README.md` ) that explicitly states the security risk of disabling authentication: `:warning: **!!! Note that your service will be publicly exposed if you disable authentication !!!** :warning:`.
- Missing mitigations:
    - Automated enforcement of authentication by default. The default deployment should have authentication enabled.
    - Clear and easily discoverable instructions on how to re-enable authentication after UI testing. The current documentation only describes how to disable it.
    - Security checklist or best practices document reminding administrators to re-enable authentication after UI testing and before production deployment.
    - Scripts or tools to easily re-enable authentication, potentially integrated into the `deploy.sh` scripts.
- Preconditions:
    - An administrator must follow the instructions in the main `README.md` file to disable authentication for UI testing.
    - The administrator must fail to manually re-enable authentication after completing UI testing.
    - The Azure ML web service must be deployed in a publicly accessible environment, which is the default configuration unless explicitly changed.
- Source code analysis:
    - The source code itself does not contain the vulnerability. The vulnerability is introduced by the configuration instructions provided in the `README.md` file.
    - The relevant part of the `README.md` is under the section "Test your deployed service using a UI web page":
        ```markdown
        To disable authentication of your service:

           * Get your deployed service's name:

                 kubectl get services

           * Edit your service's configuration:

                 kubectl label --overwrite services [service_name] auth.enabled=false
        ```
    - This instruction directly leads to disabling authentication by modifying the Kubernetes service configuration using `kubectl`.
    - The `app.py` files in each service directory (e.g., `/code/MLeap/airbnb/app.py`, `/code/TimeSeries/solar/app.py`, `/code/Image/inceptionv3/app.py`, `/code/Image/yolov3/app.py`, `/code/Text/deepmoji/app.py`) do not implement any authentication mechanisms themselves. They rely on the Azure ML platform to handle authentication. Disabling authentication at the service level using `kubectl` bypasses any platform-level security.
- Security test case:
    - Precondition: Deploy the `yolov3` service following the instructions in `/code/Image/yolov3/README.md`. Ensure the service is running and accessible.
    - Step 1: Get the service name by running `kubectl get services` in the Azure ML environment where the service is deployed. Let's assume the service name is `yolov3-service`.
    - Step 2: Disable authentication by running the command: `kubectl label --overwrite services yolov3-service auth.enabled=false`.
    - Step 3: Get the service URL using Azure ML CLI:
        ```bash
        az ml service list realtime
        az ml service usage realtime -i <full_service_id_from_previous_command>
        ```
        Let's assume the service URL is `http://<service_url>/score`.
    - Step 4: Access the service URL using `curl` without any authentication headers:
        ```bash
        curl http://<service_url>/score -H "Content-Type: application/octet-stream" --data-binary @/code/Image/SampleImages/dog.jpg
        ```
    - Step 5: Verify that the service responds with a prediction. For YOLOv3, the response will be a JSON array of detected objects. If a valid prediction is returned, it confirms that authentication is disabled and the service is publicly accessible.
    - Step 6: Access the UI page by navigating to `http://<service_url>/ui` in a web browser. Verify that the UI is accessible without any login or authentication.
    - Expected result: The service should successfully process the request and return a prediction, and the UI page should be accessible, demonstrating that authentication is disabled and the service is vulnerable to unauthorized access.
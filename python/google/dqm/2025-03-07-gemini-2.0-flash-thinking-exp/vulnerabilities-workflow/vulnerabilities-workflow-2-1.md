### Vulnerability List

* Vulnerability Name: Insecure Access Control - Missing Authentication and Authorization

* Description:
    1. An attacker gains access to the DQM application deployed on Google Cloud Platform (GCP).
    2. The attacker uses a web browser to navigate to the public URL of the DQM application.
    3. The application frontend and backend are accessible without any login or authentication mechanism.
    4. The attacker can now interact with the DQM application as an unauthorized user.
    5. The attacker can view data quality checks, configurations, and potentially manipulate or delete data depending on the application's functionalities and implemented authorization (which is non-existent).
    6. If sensitive advertising data is exposed through the DQM application, the attacker can access and potentially exfiltrate this data.

* Impact:
    - Confidentiality: Unauthorized access allows attackers to view sensitive data quality checks and potentially related advertising data.
    - Integrity: Attackers may be able to manipulate data quality checks, leading to incorrect data quality assessments and potentially impacting advertising campaign performance.
    - Availability: While not a denial of service vulnerability, unauthorized modifications could disrupt the intended functionality of the DQM application.
    - Reputational Damage: Data breaches and unauthorized access can lead to loss of trust and reputational damage for the organization using DQM.

* Vulnerability Rank: High

* Currently Implemented Mitigations:
    - None: The provided code explicitly lacks any built-in user access control mechanisms. The README.md file mentions that "DQM has no per-user access restriction".

* Missing Mitigations:
    - Authentication: The application is missing an authentication mechanism to verify the identity of users accessing the application. This could be implemented using username/password login, integration with Google Sign-In, or other authentication providers.
    - Authorization:  The application lacks an authorization mechanism to control what actions authenticated users are permitted to perform. Role-Based Access Control (RBAC) or Attribute-Based Access Control (ABAC) could be implemented to manage user permissions.
    - Identity-Aware Proxy (IAP) Enforcement: While the documentation recommends using Google Cloud IAP, the application itself does not enforce or check for IAP being enabled. The application should ideally check for IAP or implement its own access control if IAP is not enabled, or at least provide clear warnings and instructions to the user during setup and runtime if IAP is not active.

* Preconditions:
    - DQM application is deployed on Google Cloud Platform (GCP) and is publicly accessible via a URL.
    - Identity-Aware Proxy (IAP) is not enabled or configured for the deployed DQM application.

* Source Code Analysis:
    - `/code/README.md`:
        -  The "Optional features" section explicitly states: "#### Access restriction (recommended) DQM has no per-user access restriction, but you do so by enabling GCP [Identity-Aware Proxy (IAP)](https://cloud.google.com/iap/docs/app-engine-quickstart)." This clearly indicates the lack of built-in access control and reliance on external GCP features.

    - `/code/backend/app.yaml`:
        - This file defines the App Engine deployment configuration. It does not contain any security related configurations for authentication or authorization. It only configures static file handlers and script handlers.
        -  ```yaml
          handlers:
          - url: /
            static_files: www/index.html
            upload: www/index.html
            secure: always

          - url: /favicon.ico
            static_files: www/favicon.ico
            upload: www/favicon.ico
            secure: always

          - url: /js/(.*)
            static_files: www/js/\1
            upload: www/js/(.*)
            secure: always

          - url: /css/(.*)
            static_files: www/css/\1
            upload: www/css/(.*)
            secure: always

          - url: /.*
            script: auto
            secure: always
          ```

    - Codebase Review:
        - A review of the Python backend code (`/code/backend/dqm/api/views.py` and other backend files) and the Typescript frontend code (`/code/frontend/`) does not reveal any implementation of user authentication or authorization logic within the DQM application itself. API endpoints in `views.py` are decorated with `@csrf_exempt` but lack decorators for authentication or permission checks.

* Security Test Case:
    1. Deploy DQM application on GCP using the provided `installer.py` script, ensuring that IAP is not enabled during or after deployment.
    2. Obtain the public URL of the deployed DQM application from GCP App Engine.
    3. Open a web browser and navigate to the DQM application URL.
    4. Verify that the application frontend is fully accessible without any login prompt or authentication requirement.
    5. Explore the application's functionalities, such as viewing suites, checks, and executions.
    6. Attempt to perform actions that modify data, such as creating or deleting suites or checks.
    7. Observe that all functionalities are accessible and modifiable without authentication, confirming the vulnerability.
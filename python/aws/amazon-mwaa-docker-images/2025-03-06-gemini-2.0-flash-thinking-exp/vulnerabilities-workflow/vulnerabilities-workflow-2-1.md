### Vulnerability Name: AWS Credentials Exposure in `run.sh`

- Description:
    1. A user cloning the repository is instructed by the `README.md` to update the `run.sh` file located in `images/airflow/2.9.2` (and similarly for other Airflow versions).
    2. The `README.md` explicitly states: "Update `run.sh` file with your account ID, environment name and account credentials." and provides placeholders for `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and `AWS_SESSION_TOKEN`.
    3. If a user directly inputs their actual AWS credentials into these placeholder variables within the `run.sh` script, these credentials will be hardcoded in the script file.
    4. An attacker gaining access to this `run.sh` file (e.g., if inadvertently committed to a public repository, or accessible due to misconfigured permissions on a local or shared development environment) can extract these AWS credentials.
    5. These exposed AWS credentials can then be used by the attacker to gain unauthorized access to the user's AWS account.

- Impact:
    - High: Unauthorized access to the user's AWS account. Depending on the permissions associated with the exposed credentials, an attacker could potentially perform a wide range of actions, including:
        - Accessing and exfiltrating sensitive data stored in AWS services (S3, databases, etc.).
        - Modifying or deleting data and resources.
        - Launching or stopping AWS services, potentially leading to denial of service or increased AWS costs.
        - Pivoting to other AWS resources or accounts if the credentials have broader access.

- Vulnerability Rank: Critical

- Currently Implemented Mitigations:
    - None: The project explicitly instructs users to place credentials in `run.sh` without warnings about security implications.

- Missing Mitigations:
    - Secure Credential Management Guidance: The documentation should strongly discourage hardcoding AWS credentials directly in `run.sh`.
    - Environment Variable Best Practices:  The documentation should guide users to use environment variables in a secure manner, external to the script itself, for providing AWS credentials. For local testing, suggesting methods like AWS profiles, or temporary credentials.
    - Security Warnings in README: Add prominent security warnings in the `README.md` about the dangers of hardcoding credentials and best practices for secure credential management.
    - Automated Credential Scanning: Implement a pre-commit hook or CI check that scans `run.sh` (and potentially DAG files) for patterns resembling AWS credentials and warns or blocks commits. (Although this might be bypassed, it adds a layer of defense).

- Preconditions:
    1. User follows the `README.md` instructions and hardcodes their AWS credentials directly into the `run.sh` file.
    2. The `run.sh` file with hardcoded credentials becomes accessible to an attacker. This could happen if:
        - The user inadvertently commits the `run.sh` file to a public or accessible repository.
        - The user's local development environment or shared development environment is compromised.
        - The user shares the `run.sh` file insecurely.

- Source Code Analysis:
    1. **File: `/code/README.md`**:
        - The `README.md` in the root directory contains instructions on how to use the Airflow image locally.
        - Step 3 of "Using the Airflow Image" explicitly instructs users to: "Update `run.sh` file with your account ID, environment name and account credentials."
        - It further clarifies: "Update `run.sh` file with your account ID, environment name and account credentials. The permissions associated with the provided credentials will be assigned to the Airflow components that would be started with the next step. "
        - Placeholders are provided directly within the `README.md` content, which are mirrored in the `run.sh` files.

    2. **File: `/code/images/airflow/2.10.1/run.sh` (and similar `run.sh` in other versions)**:
        ```bash
        ACCOUNT_ID="" # Put your account ID here.
        ENV_NAME="" # Choose an environment name here.
        REGION="us-west-2" # Keeping the region us-west-2 as default.

        # AWS Credentials
        AWS_ACCESS_KEY_ID="" # Put your credentials here.
        AWS_SECRET_ACCESS_KEY="" # Put your credentials here.
        AWS_SESSION_TOKEN="" # Put your credentials here.
        export AWS_ACCESS_KEY_ID
        export AWS_SECRET_ACCESS_KEY
        export AWS_SESSION_TOKEN
        ```
        - The `run.sh` script in each Airflow version directory includes commented-out placeholders for AWS credentials (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`) and explicitly instructs the user to "Put your credentials here.".
        - These variables are then immediately exported as environment variables, making them available to the Docker containers.

    **Visualization:**

    ```
    README.md --> Instructions to edit run.sh --> run.sh (with credential placeholders) --> User hardcodes credentials in run.sh --> run.sh (with hardcoded credentials) --> Potential exposure
    ```

- Security Test Case:
    1. **Setup**:
        - Clone the repository to a local machine.
        - Navigate to the directory `images/airflow/2.9.2`.
        - Edit the `run.sh` file and **intentionally** hardcode **dummy** AWS credentials in the placeholder variables:
          ```bash
          AWS_ACCESS_KEY_ID="FAKE_ACCESS_KEY"
          AWS_SECRET_ACCESS_KEY="FAKE_SECRET_KEY"
          AWS_SESSION_TOKEN="FAKE_SESSION_TOKEN"
          export AWS_ACCESS_KEY_ID
          export AWS_SECRET_ACCESS_KEY
          export AWS_SESSION_TOKEN
          ```
        - Run `./run.sh` to build and start the Docker containers. (The containers will start, although AWS functionality will likely fail with fake credentials, this step is for demonstration).
    2. **Exploit**:
        - As an attacker, assume you have gained access to the `run.sh` file (e.g., through accidental public commit, or compromised dev environment).
        - Open the `run.sh` file and read the values of `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and `AWS_SESSION_TOKEN`.
        - In a separate terminal, use the AWS CLI configured with these extracted (dummy in this test case, but real in a vulnerable scenario) credentials to attempt to access AWS resources:
          ```bash
          aws configure set aws_access_key_id FAKE_ACCESS_KEY
          aws configure set aws_secret_access_key FAKE_SECRET_KEY
          aws configure set aws_session_token FAKE_SESSION_TOKEN
          aws configure set region us-west-2 # or the region from run.sh
          aws sts get-caller-identity # Attempt a harmless AWS API call
          ```
        - Observe that the `aws sts get-caller-identity` command (or other AWS CLI commands if using real credentials in a real attack scenario) would successfully execute (or fail due to fake credentials in this test case, but succeed with valid credentials in a real exploit), demonstrating successful credential extraction and potential unauthorized AWS access.

This test case proves that if a user follows the default instructions and hardcodes credentials in `run.sh` and an attacker gains access to this file, AWS credentials can be exposed and potentially misused.
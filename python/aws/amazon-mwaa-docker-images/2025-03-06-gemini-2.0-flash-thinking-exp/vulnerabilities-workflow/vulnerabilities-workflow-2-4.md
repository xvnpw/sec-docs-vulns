- Vulnerability Name: Startup Script Command Injection
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
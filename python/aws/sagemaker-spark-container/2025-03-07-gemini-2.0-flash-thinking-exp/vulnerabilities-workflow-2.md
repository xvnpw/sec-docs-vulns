## Vulnerabilities Found

### Vulnerability 1: Apache Spark Version Vulnerabilities
- **Description:**
    1. The SageMaker Spark Container bundles a specific version of Apache Spark.
    2. This bundled Apache Spark version may contain known security vulnerabilities.
    3. An attacker can exploit these known vulnerabilities by crafting a malicious Spark job.
    4. When this malicious Spark job is submitted to the SageMaker Spark Container within Amazon SageMaker, it gets executed by the vulnerable Apache Spark instance.
    5. Successful exploitation can lead to arbitrary code execution within the container environment during the processing of the Spark job.
- **Impact:**
    - Arbitrary code execution within the Amazon SageMaker Spark Container environment.
    - Potential unauthorized access to data and resources within the SageMaker environment, depending on the permissions of the execution role.
    - Compromise of the Spark processing workload and potentially the underlying infrastructure.
- **Vulnerability Rank:** Critical
- **Currently Implemented Mitigations:**
    - The project provides build scripts and configurations to build the Docker image, but there is no explicit vulnerability mitigation for the bundled Apache Spark version within the provided project files. The `new_images.yml` file suggests different Spark versions can be built, implying version management is considered, but active vulnerability patching isn't evident in the code.
- **Missing Mitigations:**
    - **Regularly update the bundled Apache Spark version:** The project should implement a process to regularly update the Apache Spark version bundled in the container to the latest stable release. This includes applying security patches released by the Apache Spark project.
    - **Vulnerability Scanning:** Integrate vulnerability scanning into the container build process. This would involve scanning the Docker image for known vulnerabilities in the installed packages, including Apache Spark and its dependencies. Tools like Clair, Trivy, or Anchore can be used for this purpose.
    - **Dependency Management:** Implement a clear dependency management strategy to track and manage the versions of Apache Spark and other libraries included in the container. This will facilitate easier updates and vulnerability patching.
- **Preconditions:**
    - An attacker must be able to submit a Spark job to a SageMaker Processing or Training job that utilizes the vulnerable SageMaker Spark Container image. This typically requires access to an Amazon SageMaker environment and the ability to create and run Processing or Training jobs.
- **Source Code Analysis:**
    - The provided project files do not directly expose the specific version of Apache Spark being bundled. However, files like `new_images.yml` suggest different Spark versions are supported (e.g., "spark: "3.5"").
    - The `buildspec.yml`, `buildspec_test.yml`, `scripts/build.sh` files outline the image build process. These scripts use `docker build` commands, but they do not include steps for vulnerability scanning or patching of the base OS or Apache Spark installation.
    - The vulnerability is not within the project's code itself but rather in the external dependency (Apache Spark) that is included in the Docker image.
    - There is no code in the provided files that actively mitigates known vulnerabilities in the bundled Apache Spark version. The project focuses on containerizing and running Spark, not on actively securing the Spark distribution itself beyond potentially choosing a specific version.
- **Security Test Case:**
    1. Identify a known Remote Code Execution (RCE) vulnerability in a specific Apache Spark version (e.g., CVE-2022-33891 if using Spark 3.0.x, 3.1.x, 3.2.0, or CVE-2018-1284 if using older versions).
    2. Determine the exact Apache Spark version bundled in the SageMaker Spark Container image (this might require inspecting the Dockerfile or running a container and checking the Spark version). For example, based on `new_images.yml`, it could be Spark 3.5.
    3. Craft a Spark job (e.g., in Python, Scala, or Java) that is designed to exploit the identified vulnerability. For CVE-2022-33891, this might involve sending a specially crafted request to the Spark Master UI. For other vulnerabilities, it might involve manipulating job configurations or data inputs.
    4. Deploy the SageMaker Spark Container image in an Amazon SageMaker Processing Job using the SageMaker Python SDK.
    5. Submit the crafted malicious Spark job to the running SageMaker Processing Job.
    6. Monitor the Processing Job logs and the SageMaker environment to confirm if the vulnerability is successfully exploited and if arbitrary code execution occurs. For example, check for unexpected system calls, network connections, or file system modifications originating from the Spark container.
    7. If successful, this test case demonstrates the presence of the Apache Spark version vulnerability in the SageMaker Spark Container.

### Vulnerability 2: Command Injection via Malicious User Configuration in Environment Files
- **Description:**
    An attacker can inject arbitrary commands into the environment configuration files (`spark-env.sh`, `hadoop-env.sh`, `yarn-env.sh`, `hive-env.sh`) through a maliciously crafted `configuration.json` file. This file is read and processed by the `write_user_configuration` function in `smspark/bootstrapper.py`. The `env_serializer` in `smspark/config.py` is then used to serialize these configurations into shell scripts. The `env_serializer` directly writes the property values without any sanitization, leading to command injection if a malicious value is provided. When the container starts and these scripts are executed, the injected commands will be executed with the privileges of the container user.

    Steps to trigger vulnerability:
    1. An attacker crafts a `configuration.json` file containing a malicious configuration for one of the environment files (e.g., `hadoop-env`).
    2. Within the `Properties` of a configuration with `Classification` like `hadoop-env`, the attacker injects a property where the `value` contains shell commands. For example:
       ```json
       [
         {
           "Classification": "hadoop-env",
           "Properties": {},
           "Configurations": [
             {
               "Classification": "export",
               "Properties": {
                 "MALICIOUS_COMMAND": "$(touch /tmp/pwned)"
               }
             }
           ]
         }
       ]
       ```
    3. The attacker provides this malicious `configuration.json` file as input to the SageMaker Spark Processing job. This can be done by uploading it to the input S3 path specified in the SageMaker Processing job request, under the `conf` folder, named `configuration.json`.
    4. When the SageMaker Spark Processing job starts, the container's entrypoint scripts will execute `smspark-submit`.
    5. `smspark-submit` will call `write_user_configuration` in `smspark/bootstrapper.py`.
    6. `write_user_configuration` will read and deserialize the malicious `configuration.json`.
    7. The `env_serializer` will serialize the `hadoop-env` configuration into `/usr/lib/hadoop/etc/hadoop/hadoop-env.sh` without sanitizing the `MALICIOUS_COMMAND` property value.
    8. When Hadoop daemons are started, `/usr/lib/hadoop/etc/hadoop/hadoop-env.sh` is executed, and the injected command `touch /tmp/pwned` will be executed within the container.
- **Impact:**
    Successful command injection allows an attacker to execute arbitrary commands within the SageMaker Spark container. This can lead to:
        - Data exfiltration: Attacker can access and upload sensitive data from the SageMaker environment to external locations.
        - Credential theft: Attacker can potentially access AWS credentials used by the SageMaker role, leading to further compromise of the AWS account.
        - Container takeover: Attacker gains full control of the Spark container, potentially pivoting to other containers or resources within the SageMaker environment.
        - Denial of Service: Attacker can disrupt the Spark job or the entire SageMaker Processing environment.
- **Vulnerability Rank:** Critical
- **Currently Implemented Mitigations:**
    None. The code directly writes user-provided configuration values into shell scripts without any sanitization or validation.
- **Missing Mitigations:**
    - Input validation and sanitization: Implement strict validation and sanitization of all user-provided configuration values, especially those intended for environment files. Any values containing shell metacharacters or command injection attempts should be rejected or properly escaped.
    - Principle of least privilege: While not a direct mitigation for command injection, running container processes with the least necessary privileges can limit the impact of a successful exploit.
    - Content Security Policy: For web UIs (like Spark History Server), implement a strong Content Security Policy to prevent execution of injected scripts within the browser context. This is less relevant for command injection in backend scripts but is a general security best practice.
- **Preconditions:**
    - The attacker needs to be able to provide a malicious `configuration.json` file to the SageMaker Spark Processing job. This is possible if the attacker can control the input S3 path of the SageMaker Processing job, or through other SageMaker input mechanisms if available.
    - The SageMaker Spark Processing job must be configured to read and apply user configurations from the provided `configuration.json` file. This is the default behavior if the configuration input is provided.
- **Source Code Analysis:**

    ```python
    File: /code/src/smspark/config.py
    Content:
    ...
    def env_serializer(configuration: Configuration) -> str:
        """Serialize configuration to .env files.

        The inner nested Configuration object contains
        the keys, values, and properties to create lines of env.
        """
        lines = []
        for inner_configuration in configuration.Configurations:
            if inner_configuration.Classification != "export":
                raise ValueError(
                    "env classifications must use the 'export' sub-classification. Please refer to {} for more information.".format(
                        EMR_CONFIGURE_APPS_URL
                    )
                )
            for key, val in inner_configuration.Properties.items(): # Vulnerable code: No sanitization of 'val'
                lines.append(f"export {key}={val}") # Directly writing to shell script
        return "\n".join(lines) + "\n"
    ...
    ```

    ```python
    File: /code/src/smspark/bootstrapper.py
    Content:
    ...
        def write_user_configuration(self) -> None:
            config_input_path = get_config_path(ConfigPathTypes.USER_CONFIGURATION_INPUT)

            def _write_conf(conf: Configuration) -> None:
                logging.info("Writing user config to {}".format(conf.path))
                conf_string = conf.write_config() # Calls Configuration.write_config which uses serializers
                logging.info("Configuration at {} is: \n{}".format(conf.path, conf_string))

            if config_input_path: # User configuration path exists
                path = pathlib.Path(config_input_path)
                logging.info("reading user configuration from {}".format(str(path)))
                with open(str(path), "r") as config:
                    user_configuration_list_or_dict = json.load(config) # User provided JSON is loaded
                    logging.info(
                        "User configuration list or dict: {} , type {}".format(
                            user_configuration_list_or_dict,
                            type(user_configuration_list_or_dict),
                        )
                    )
                    user_confs = self.deserialize_user_configuration(user_configuration_list_or_dict)
                    if isinstance(user_confs, Configuration):
                        _write_conf(user_confs) # Write configuration
                    elif isinstance(user_confs, list):
                        for user_conf in user_confs:
                            _write_conf(user_conf) # Write configuration
                    else:
                        raise ValueError(
                            "Could not determine type of user configuration {}. Please consult {} for more information.".format(
                                user_configuration_list_or_dict, Bootstrapper.EMR_CONFIGURE_APPS_URL
                            )
                        )
            else:
                logging.info("No user input configuration file exists, skipping user configuration")
    ...
    ```

    The code snippet in `env_serializer` directly concatenates `export {key}={val}` without any escaping or sanitization of `val`. When `write_user_configuration` processes the user-provided JSON configuration, it uses this vulnerable serializer to write to environment files.
- **Security Test Case:**

    1. Create a malicious `configuration.json` file with the following content:
       ```json
       [
         {
           "Classification": "hadoop-env",
           "Properties": {},
           "Configurations": [
             {
               "Classification": "export",
               "Properties": {
                 "MALICIOUS_COMMAND": "$(touch /tmp/pwned_hadoop_env)"
               }
             }
           ]
         },
         {
           "Classification": "spark-env",
           "Properties": {},
           "Configurations": [
             {
               "Classification": "export",
               "Properties": {
                 "MALICIOUS_COMMAND": "$(touch /tmp/pwned_spark_env)"
               }
             }
           ]
         },
         {
           "Classification": "yarn-env",
           "Properties": {},
           "Configurations": [
             {
               "Classification": "export",
               "Properties": {
                 "MALICIOUS_COMMAND": "$(touch /tmp/pwned_yarn_env)"
               }
             }
           ]
         },
         {
           "Classification": "hive-env",
           "Properties": {},
           "Configurations": [
             {
               "Classification": "export",
               "Properties": {
                 "MALICIOUS_COMMAND": "$(touch /tmp/pwned_hive_env)"
               }
             }
           ]
         }
       ]
       ```
    2. Upload this `configuration.json` file to an S3 bucket, for example, `s3://<YOUR_BUCKET>/test/conf/configuration.json`.
    3. Create a SageMaker Processing job using the SageMaker Python SDK. Configure the `PySparkProcessor` with:
        - `image_uri`: Use the image URI of the SageMaker Spark container being tested.
        - `role`: Use an appropriate IAM role for SageMaker execution.
        - `instance_count`: Set to 1 or more.
        - `instance_type`: e.g., `ml.c5.xlarge`.
        - `inputs`: Configure an input pointing to the S3 path where you uploaded `configuration.json`. Set `destination='/opt/ml/processing/input/conf'` and `input_name='conf'`.
        - `submit_app`: Use any simple PySpark application, e.g., `test/resources/code/python/hello_py_spark/hello_py_spark_app.py`.
    4. Run the SageMaker Processing job with `wait=True`.
    5. After the job completes (successfully or fails), execute an `exec` command into the running container (if the job is still running or if you can access the container logs if it has finished).
    6. Inside the container, check if the files `/tmp/pwned_hadoop_env`, `/tmp/pwned_spark_env`, `/tmp/pwned_yarn_env`, and `/tmp/pwned_hive_env` exist. If these files are present, it confirms that the injected commands were executed, demonstrating the command injection vulnerability.
    7. Alternatively, if direct container access is not feasible, modify the malicious command to exfiltrate data to an attacker-controlled server or create some observable side effect that can be detected from outside the container. For example, the command could attempt to connect to an external server or write logs to CloudWatch if permissions allow.

    This test case will demonstrate that an attacker can inject and execute arbitrary commands within the SageMaker Spark container by providing a malicious `configuration.json` file.
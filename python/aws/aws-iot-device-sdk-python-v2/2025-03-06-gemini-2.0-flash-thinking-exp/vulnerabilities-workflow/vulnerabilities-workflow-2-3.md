- Vulnerability Name: Insecure Storage of PKCS#12 Passwords in Samples

- Description:
  - Step 1: An attacker reviews the sample code, specifically `pkcs12_connect.md` and `samples/pkcs12_connect.md`.
  - Step 2: The attacker notes that the sample code instructs users to pass the PKCS#12 password directly as a command-line argument: `--pkcs12_password <password here>`.
  - Step 3: The attacker understands that command-line arguments are often stored in shell history and process listings, making them accessible to local users or attackers who gain unauthorized access to the system.
  - Step 4: If a developer follows this sample and uses command-line arguments to provide the PKCS#12 password in a production environment, the password could be compromised.

- Impact:
  - If an attacker gains access to the command history or process listings of a system running an application that follows this sample, they can retrieve the PKCS#12 password.
  - With the PKCS#12 password and the PKCS#12 file (which might be stored insecurely as well, although not directly suggested by this sample), the attacker can extract the private key and certificate.
  - This compromised key and certificate can then be used to impersonate the device, potentially leading to unauthorized access to the AWS IoT platform and device control.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
  - None. The sample code explicitly instructs users to pass the password as a command-line argument.

- Missing Mitigations:
  - The sample code should be updated to strongly discourage passing passwords as command-line arguments.
  - It should recommend secure password handling practices, such as using environment variables, secure configuration files with restricted access, or secrets management solutions.
  - The documentation could include a security warning about the risks of insecure password storage.

- Preconditions:
  - A developer uses the `pkcs12_connect.md` sample as a basis for their application.
  - The developer follows the sample's instructions and passes the PKCS#12 password as a command-line argument in a non-test environment.
  - An attacker gains unauthorized access to the system's command history or process listings.

- Source Code Analysis:
  - File: `/code/samples/pkcs12_connect.md`
  - The "How to run" section provides the command:
    ```sh
    python3 pkcs12_connect --endpoint <endpoint> --pkcs12_file <path to PKCS12 file> --pkcs12_password <password for PKCS12 file>
    ```
  - This command explicitly shows `--pkcs12_password <password for PKCS12 file>` as the way to provide the password.
  - No alternative secure method for password input is suggested within this sample.

- Security Test Case:
  - Step 1: Create a test script based on the `samples/pkcs12_connect.py` sample.
  - Step 2: Modify the test script to accept the PKCS#12 password as a command-line argument, as shown in the sample's README.
  - Step 3: Run the test script with a dummy PKCS#12 file and a password passed via command-line.
  - Step 4: While the script is running (or after execution), examine the process list (e.g., using `ps aux | grep python` on Linux or Task Manager on Windows).
  - Step 5: Verify that the PKCS#12 password is visible in the command-line arguments of the running process.
  - Step 6: Check shell history (e.g., `.bash_history` on Linux) and confirm the command with the password is logged.
  - Step 7: This demonstrates that the password is being passed insecurely and is accessible through system logs and process information.

- Vulnerability Name: Potential Exposure of Credentials in Greengrass Component Recipes

- Description:
  - Step 1: An attacker reviews the Greengrass component recipe examples, specifically in `/code/test/greengrass/basic_discovery/recipe.yaml` and `/code/test/greengrass/ipc/recipe.yaml`.
  - Step 2: The attacker observes that these `recipe.yaml` files, intended for testing purposes, contain embedded AWS account-specific information, such as `thingName=CI_Greengrass_Discovery_Thing`.
  - Step 3: The attacker recognizes that while these examples are for testing, developers might inadvertently use these recipe files as templates and directly embed sensitive configuration details or even credentials within their component recipes.
  - Step 4: If developers include sensitive information directly in `recipe.yaml` and commit these files to version control or distribute them insecurely, these details could be exposed.

- Impact:
  - If developers embed AWS IoT credentials or other sensitive configuration directly into Greengrass component recipe files, and these files are exposed (e.g., through public repositories, insecure file sharing, or unauthorized access to development environments), attackers could gain access to this information.
  - Exposed AWS IoT credentials could allow attackers to impersonate devices, publish/subscribe to MQTT topics, control devices, or access other AWS IoT resources, depending on the permissions associated with the compromised credentials.
  - Exposed configuration details might reveal information about the system's architecture or intended behavior, potentially aiding further attacks.

- Vulnerability Rank: Medium

- Currently Implemented Mitigations:
  - None. The recipe examples themselves do not contain credentials, but they demonstrate embedding account-specific names, and there is no explicit warning against embedding credentials in recipe files.

- Missing Mitigations:
  - The documentation and sample recipes should include a clear security warning against embedding any type of credentials or sensitive information directly within component recipe files.
  - Best practices for secure configuration management in Greengrass components should be documented, such as using environment variables (fetched securely), secure configuration stores, or secrets management mechanisms.
  - Samples should be reviewed to ensure they do not inadvertently encourage insecure practices.

- Preconditions:
  - A developer uses the example `recipe.yaml` files as templates for creating their own Greengrass components.
  - The developer, misunderstanding the security implications, embeds AWS IoT credentials or other sensitive configuration details directly into the `recipe.yaml` file.
  - The `recipe.yaml` file containing embedded sensitive information is then exposed through insecure storage, version control, or distribution methods.

- Source Code Analysis:
  - File: `/code/test/greengrass/basic_discovery/recipe.yaml`
  - File: `/code/test/greengrass/ipc/recipe.yaml`
  - These recipe files contain lines like `thingName=CI_Greengrass_Discovery_Thing` and `<S3 Bucket URL>/GreengrassIPC/1.0.0/GreengrassIPC.zip`.
  - While these specific examples do not embed credentials, they illustrate the practice of hardcoding configuration details directly into recipe files.
  - The general structure of `recipe.yaml` files allows for embedding arbitrary strings, which could include credentials if developers are not security-conscious.

- Security Test Case:
  - Step 1: Create a modified `recipe.yaml` file (based on the examples provided) that includes a placeholder for an AWS IoT access key and secret key within the `ComponentConfiguration` section (e.g., as environment variables).
  - Step 2: Build and deploy this modified component to a test Greengrass core device (using GDK or manual deployment).
  - Step 3: Examine the deployed component's configuration on the Greengrass core device (e.g., by inspecting the component's recipe in the Greengrass file system).
  - Step 4: Verify that the recipe file (or the deployed component's configuration) contains the embedded access key and secret key placeholder (or, if actually replaced with values for testing, the actual embedded credentials).
  - Step 5: This proves that it is possible to embed credentials directly into the `recipe.yaml` files, and that these credentials would be deployed as part of the component's configuration, potentially exposing them if the recipe or component configuration is accessed insecurely.
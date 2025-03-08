- vulnerability name: Protocol Injection
- description: |
  The application is vulnerable to protocol injection due to insufficient input validation when processing WhatsApp messages.

  1. The application uses a regular expression `f"({_protocol_message}|{_ctm_message}) (\w+)"` in the `get_protocol_by_phone` function to extract the protocol from incoming WhatsApp messages.
  2. This regex is overly permissive, as `\w+` matches any word character (letters, digits, and underscores). This allows an attacker to inject arbitrary strings as valid protocols.
  3. An attacker can craft a WhatsApp message containing the configured `PROTOCOL_MESSAGE` (or `CTM_PROTOCOL_MESSAGE`) followed by a space and a malicious protocol string of their choice.
  4. When the application processes this message, it extracts the attacker-controlled string as the protocol.
  5. This attacker-injected protocol is then saved into the `leads` table in BigQuery, associating it with the attacker's phone number.
  6. This can lead to the injection of fraudulent conversion data, as the system will treat these attacker-generated protocols as legitimate conversion events.
- impact: |
  - Fraudulent conversion data can be injected into the system, leading to inflated or manipulated conversion metrics.
  - Advertisers' conversion reports and campaign performance data can be skewed and unreliable.
  - Malicious actors can exploit this vulnerability to misrepresent advertising performance, potentially harming advertisers or gaining unfair advantages.
- vulnerability rank: High
- currently implemented mitigations: None
- missing mitigations: |
  - Implement robust input validation for the extracted protocol in the `get_protocol_by_phone` function.
    - Validate that the extracted protocol conforms to the expected format (e.g., numeric, alphanumeric with a specific length, or matches a predefined set of valid protocols).
    - Reject or sanitize messages containing invalid protocols.
  - Consider using a more secure protocol generation method if protocol predictability is a concern. However, input validation is the primary mitigation for this specific vulnerability.
- preconditions: |
  - The attacker needs to know the WhatsApp Business Account number configured for the WCI application.
  - The attacker needs to discover the configured `PROTOCOL_MESSAGE` or `CTM_PROTOCOL_MESSAGE`. This can be done by initiating a legitimate lead generation flow or through social engineering.
- source code analysis: |
  1. **`app/helpers/webhook/helpers.py:get_protocol_by_phone` function:**
     ```python
     def get_protocol_by_phone(message: str, sender: str, receiver: str) -> Optional[str]:
         ...
         _protocol_message = os.environ.get("PROTOCOL_MESSAGE").strip()
         _ctm_message = os.environ.get("CTM_PROTOCOL_MESSAGE").strip()
         has_protocol = re.search(f"({_protocol_message}|{_ctm_message}) (\w+)", message)
         protocol = None

         if has_protocol:
             protocol = has_protocol.group(2) # Vulnerable line - extracts anything matching \w+
             data_source.save_phone_protocol_match(sender, protocol)
             ...
         ...
         return protocol
     ```
     - This code snippet shows that the `get_protocol_by_phone` function uses a regular expression to extract the protocol from the incoming message.
     - The vulnerable part is `(\w+)` which matches one or more word characters. This regex pattern is too broad and allows any word-like string to be captured as a valid protocol.
     - The extracted `protocol` is directly assigned the value from the regex group without any further validation.

  2. **`app/data_sources/bigquery/bigquery_data_source.py:save_phone_protocol_match` function:**
     ```python
     def save_phone_protocol_match(self, phone: str, protocol: str):
         """
         Saves a protocol matched to a number (phone)
         ...
         """
         rows_to_insert = [
             {
                 "phone": phone,
                 "protocol": protocol, # Vulnerable line - saves unvalidated protocol
                 "timestamp": datetime.datetime.now().timestamp(),
             }
         ]

         errors = self._bq_client.insert_rows_json(BQ_LEAD_TABLE, rows_to_insert)
         ...
     ```
     - The `save_phone_protocol_match` function in `BigQueryDataSource` takes the `protocol` extracted by `get_protocol_by_phone` and directly saves it into the `BQ_LEAD_TABLE`.
     - There is no validation or sanitization of the `protocol` before it is inserted into the database. This means any string that matches the `\w+` regex in `get_protocol_by_phone` will be accepted and stored as a valid protocol.

- security test case: |
  1. **Prerequisites:**
     - Deploy the WCI application to Google Cloud.
     - Configure a WhatsApp Business Account and set up the webhook to point to the deployed WCI application's `/webhook-wci` endpoint.
     - Obtain the deployed application's endpoint URL.
     - Determine the configured `PROTOCOL_MESSAGE`. Assume it is "Your protocol is".

  2. **Steps:**
     - Open the WhatsApp application on a mobile device or web browser.
     - Initiate a chat with the configured WhatsApp Business Account number.
     - Compose a message in the chat that starts with the `PROTOCOL_MESSAGE`, followed by a space, and then a fraudulent protocol string. For example: "Your protocol is INJECTED_PROTOCOL_123".
     - Send the message to the WhatsApp Business Account.

  3. **Verification:**
     - Access the Google Cloud Console and navigate to BigQuery.
     - Query the `BQ_LEAD_TABLE` within the configured dataset (e.g., `wci.leads`).
     - Execute a query to search for entries with the injected protocol "INJECTED_PROTOCOL_123". For example: `SELECT * FROM \`<your-project-id>.<your-dataset-name>.leads\` WHERE protocol = 'INJECTED_PROTOCOL_123'`.
     - Check if a new row exists in the `BQ_LEAD_TABLE` where the `protocol` column contains "INJECTED_PROTOCOL_123" and the `phone` column contains the WhatsApp ID of the phone number from which the message was sent.

  4. **Expected Result:**
     - A new row will be present in the `BQ_LEAD_TABLE` with the `protocol` field set to "INJECTED_PROTOCOL_123" and the `phone` field corresponding to the attacker's WhatsApp number. This confirms that the attacker was able to successfully inject a fraudulent protocol into the system by crafting a WhatsApp message.
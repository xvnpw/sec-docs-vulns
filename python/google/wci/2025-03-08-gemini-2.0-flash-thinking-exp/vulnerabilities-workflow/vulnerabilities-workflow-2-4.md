- Vulnerability Name: Unsanitized WhatsApp Message Payload leading to Data Injection in BigQuery
- Description:
    1. An attacker sends a WhatsApp message to the configured WhatsApp Business Account.
    2. The WCI application's webhook `/webhook-wci` receives this message.
    3. The `process_message` function in `WhatsAppPartner` extracts the message content from the webhook payload.
    4. The `get_protocol_by_phone` function is called, which further processes the message body.
    5. The `save_message` function in `helpers/webhook/helpers.py` is called to store the message.
    6. This function calls `data_source.save_message` to save the message in BigQuery.
    7. The `BigQueryDataSource.save_message` function uses `_bq_client.insert_rows_json` to insert the message content directly into the `BQ_CHAT_TABLE` in BigQuery, without any sanitization or validation.
    8. A malicious user can craft a WhatsApp message containing arbitrary text, including potentially harmful content or control characters. This content will be directly inserted into the BigQuery table.
- Impact:
    - Data Integrity Issues: Malicious or unexpected data can be injected into the BigQuery `BQ_CHAT_TABLE`. This can corrupt the data and affect any downstream processes or reports that rely on this data.
    - Potential for Exploitation in Downstream Systems: If other applications or systems consume data from the `BQ_CHAT_TABLE` without proper sanitization, the injected malicious content could potentially be exploited in those downstream systems. For example, if the data is used to generate reports vulnerable to injection attacks or displayed in a web interface without proper escaping, it could lead to further security issues.
    - Although not a direct code execution vulnerability in WCI itself, it represents a data injection vulnerability with potential downstream impacts on data consumers.
- Vulnerability Rank: Medium
- Currently Implemented Mitigations: None. The code directly saves the message content to BigQuery without any sanitization.
- Missing Mitigations:
    - Input Sanitization: Implement input sanitization for the message content before saving it to BigQuery in `BigQueryDataSource.save_message` or `helpers/webhook/helpers.py`. This should include escaping special characters, limiting message length, and potentially filtering out control characters or other potentially harmful content.
    - Data Validation: Implement validation on the message content to ensure it conforms to expected formats and does not contain unexpected or malicious data.
- Preconditions:
    - An attacker needs to know the WhatsApp Business Account number associated with the WCI application.
    - The WCI application must be deployed and configured to receive webhook messages from the WhatsApp Business Account.
- Source Code Analysis:
    1. `app/blueprints/webhook/blueprint.py` - `process_message` function receives the webhook POST request and calls `partner.process_message`.
    2. `app/partners/whatsapp/whatsapp_partner.py` - `WhatsAppPartner.process_message` extracts the message body from the webhook payload and calls `get_protocol_by_phone`.
    3. `app/helpers/webhook/helpers.py` - `get_protocol_by_phone` extracts the message body and calls `data_source.save_message(message, sender, receiver)` to save the message.
    4. `app/data_sources/bigquery/bigquery_data_source.py` - `BigQueryDataSource.save_message` receives the message and uses `_bq_client.insert_rows_json` to insert it into BigQuery's `BQ_CHAT_TABLE` without any sanitization.
    ```
    File: /code/app/data_sources/bigquery/bigquery_data_source.py
    Content:
    ...
    class BigQueryDataSource(DataSource):
        ...
        def save_message(self, message: str, sender: str, receiver: str):
            ...
            rows_to_insert = [
                {
                    "sender": sender,
                    "receiver": receiver,
                    "message": message, # No sanitization of message here
                    "timestamp": datetime.datetime.now().timestamp(),
                }
            ]
            errors = self._bq_client.insert_rows_json(BQ_CHAT_TABLE, rows_to_insert)
            ...
    ```
- Security Test Case:
    1. Deploy the WCI application and configure it to receive WhatsApp webhook messages. Obtain the webhook URL for `/webhook-wci`.
    2. Craft a malicious WhatsApp message payload. For example: `Malicious message: <script>alert("XSS")</script> Very long message:  ` + "A"*2000 + ` Special characters: !@#$%^&*()_+=-`
    3. Send this crafted message to the WhatsApp Business Account associated with the WCI application.
    4. Access the BigQuery console and query the `BQ_CHAT_TABLE` to inspect the stored messages.
    5. Verify that the `message` column for the latest entry contains the exact malicious payload sent in the WhatsApp message, without any sanitization or encoding, demonstrating successful data injection.
### Vulnerability List

- Vulnerability Name: Insecure Direct Object Reference in Protocol Generation
- Description:
An attacker can directly manipulate the `id` and `type` parameters in the `/webhook` endpoint to generate and save conversion protocols associated with arbitrary identifiers. This endpoint is intended to be used when a user clicks on a "Contact via WhatsApp" link, and it associates a generated protocol with an identifier like `gclid`. However, there is no validation or authorization to ensure that the provided `id` and `type` are legitimate or belong to the intended user or campaign.

Step-by-step trigger:
1. An attacker identifies the `/webhook` endpoint URL of a WCI instance.
2. The attacker crafts a malicious URL to the `/webhook` endpoint, including arbitrary values for the `id` and `type` parameters. For example: `https://<wci-instance-url>/webhook?id=malicious_campaign_id&type=campaign_override`.
3. The attacker accesses this crafted URL.
4. The WCI application generates a new protocol and saves it in the `pending_leads` BigQuery table, associating it with the attacker-provided `id` (`malicious_campaign_id`) and `type` (`campaign_override`).
5. This allows the attacker to inject arbitrary identifiers into the conversion tracking system, potentially manipulating conversion attribution or data analysis.

- Impact:
    - **Data Integrity:** Attackers can inject fabricated conversion data into the system, associating protocols with incorrect or malicious identifiers. This can corrupt the conversion tracking data, leading to inaccurate reports and misinformed advertising campaign optimization.
    - **Conversion Misattribution:** By controlling the `id` and `type`, an attacker might be able to misattribute conversions to their own campaigns or identifiers, potentially gaining undue credit or insights.
    - **Reporting Skewing:** The injected data can skew reports and dashboards, making it difficult for advertisers to understand the true performance of their campaigns.

- Vulnerability Rank: Medium

- Currently Implemented Mitigations:
    - None. The code directly accepts and processes the `id` and `type` parameters without any validation or authorization checks.

- Missing Mitigations:
    - **Input Validation:** Implement validation on the `id` and `type` parameters in the `/webhook` endpoint to ensure they conform to expected formats and prevent injection of arbitrary or malicious values.
    - **Authorization:** Implement authorization mechanisms to verify the legitimacy of the request and ensure that the requester is allowed to associate protocols with the provided identifiers. This could involve API keys, session management, or other authentication methods depending on the intended use case.
    - **Rate Limiting:** Implement rate limiting on the `/webhook` endpoint to prevent automated abuse and injection of large volumes of malicious data.

- Preconditions:
    - The WCI instance must be publicly accessible.
    - The attacker must know or be able to discover the `/webhook` endpoint URL.

- Source Code Analysis:
    - File: `/code/app/blueprints/webhook/blueprint.py`
    - Function: `process_protocol`
    ```python
    @webhook_page.route("/webhook", methods=["GET", "POST"])
    def process_protocol():
        """
        Generates a new protocol
        ...
        """
        # Collects gclid, phone from the URL
        identifier = request.args.get("id") # [VULNERABILITY] - Directly taking 'id' from request parameters
        type = request.args.get("type") or "gclid" # [VULNERABILITY] - Directly taking 'type' from request parameters

        # ...

        # Save protocol
        save_protocol(identifier, type, has_protocol, payload) # Saves the protocol with attacker-controlled identifier and type

        # ...
    ```
    - The `process_protocol` function directly retrieves the `id` and `type` parameters from the URL query string using `request.args.get()`.
    - These parameters are then passed directly to the `save_protocol` function, which stores them in the BigQuery `pending_leads` table without any validation or sanitization.
    - There are no checks to ensure that the `id` and `type` are valid, expected values, or that the request is authorized to associate protocols with these identifiers.

- Security Test Case:
    - **Step 1:** Identify the base URL of the deployed WCI application. This can be found using `gcloud run services list` as mentioned in `deployment/deploy.sh`.
    - **Step 2:** Construct a malicious URL to the `/webhook` endpoint with a crafted `id` and `type` parameter. For example, if the WCI URL is `https://<wci-instance-url>`, the malicious URL could be `https://<wci-instance-url>/webhook?id=ATTACKER_CONTROLLED_ID&type=ATTACKER_CONTROLLED_TYPE`.
    - **Step 3:** Send a GET request to the crafted URL using a tool like `curl` or a web browser.
    ```bash
    curl "https://<wci-instance-url>/webhook?id=ATTACKER_CONTROLLED_ID&type=ATTACKER_CONTROLLED_TYPE"
    ```
    - **Step 4:** Verify in the BigQuery `pending_leads` table (using BigQuery console or `bq` command-line tool) that a new entry has been created with `identifier` set to `ATTACKER_CONTROLLED_ID` and `type` set to `ATTACKER_CONTROLLED_TYPE`.
    ```bash
    bq query "SELECT identifier, type FROM `<your-gcp-project>.<your-bq-dataset>.pending_leads` WHERE identifier = 'ATTACKER_CONTROLLED_ID'"
    ```
    - **Step 5:** If the query in step 4 returns a row with the attacker-controlled `identifier` and `type`, the vulnerability is confirmed. This shows that an attacker can successfully inject arbitrary identifiers into the system.

---
- Vulnerability Name: Lack of Authentication on Message Processing Webhook
- Description:
The `/webhook-wci` endpoint, responsible for processing incoming WhatsApp messages, lacks authentication. This endpoint is intended to receive webhook notifications from the WhatsApp Business Account when users send messages. However, anyone who discovers the endpoint URL can send arbitrary POST requests to it, potentially simulating valid WhatsApp messages and triggering unintended application behavior.

Step-by-step trigger:
1. An attacker identifies the `/webhook-wci` endpoint URL of a WCI instance.
2. The attacker crafts a malicious JSON payload that mimics the structure of a valid WhatsApp webhook message. This payload can contain arbitrary message content, sender IDs, and other parameters.
3. The attacker sends a POST request to the `/webhook-wci` endpoint with the crafted JSON payload.
4. The WCI application processes this crafted message as if it originated from WhatsApp, potentially leading to incorrect protocol matching, data storage, or triggering Enhanced Conversion for Leads (ECL) in unintended scenarios.

- Impact:
    - **Spoofed Conversions:** An attacker can send crafted messages containing valid-looking protocols, potentially spoofing conversions and manipulating conversion metrics.
    - **Data Injection:** Arbitrary messages can be injected into the chat logs, potentially polluting the data used for analysis and reporting.
    - **ECL Trigger Abuse:** If ECL is enabled, an attacker might be able to trigger ECL events by crafting messages with protocols and sender phone numbers, potentially leading to inaccurate conversion reporting in Google Ads.
    - **Resource Abuse:**  Processing of spoofed messages can consume server resources and potentially lead to performance degradation.

- Vulnerability Rank: Medium

- Currently Implemented Mitigations:
    - None. The `/webhook-wci` POST endpoint is publicly accessible without any authentication. The GET endpoint for webhook verification uses `auth_required`, but this does not protect the POST endpoint.

- Missing Mitigations:
    - **Webhook Authentication:** Implement proper webhook authentication to verify that incoming requests to `/webhook-wci` are genuinely from WhatsApp. WhatsApp provides mechanisms like signature verification or token-based authentication that should be implemented.
    - **Input Validation and Sanitization:** Thoroughly validate and sanitize the data received in the webhook payload to prevent injection attacks and ensure data integrity.

- Preconditions:
    - The WCI instance must be publicly accessible.
    - The attacker must know or be able to discover the `/webhook-wci` endpoint URL.
    - The attacker needs to understand the expected format of the WhatsApp webhook payload (which is publicly documented by WhatsApp).

- Source Code Analysis:
    - File: `/code/app/blueprints/webhook/blueprint.py`
    - Function: `process_message`
    ```python
    @webhook_page.route("/webhook-wci", methods=["POST"])
    def process_message():
        """
        Process message received
        ...
        """
        # Collects the payload received
        partner = PartnerFactory(os.environ.get("PARTNER_TYPE")).get()
        partner.process_message(request.get_json()) # [VULNERABILITY] - Processes payload without authentication

        # Always return success
        return "Success", 200
    ```
    - The `process_message` function is directly accessible via a POST request to `/webhook-wci`.
    - It retrieves the JSON payload using `request.get_json()` and passes it to the `partner.process_message()` function without any authentication or verification of the request origin.
    - This allows anyone to send POST requests to this endpoint and have them processed by the application.

- Security Test Case:
    - **Step 1:** Identify the base URL of the deployed WCI application.
    - **Step 2:** Obtain a sample valid WhatsApp webhook payload. This can be found in the WhatsApp Cloud API documentation or by capturing a real webhook message. A simplified example is provided in `/code/run_local_webhook.sh`.
    - **Step 3:** Modify the sample payload to include a specific protocol that you want to test, and potentially a spoofed sender phone number. For example, in the `messages[0].text.body` field, include a known protocol like "Chat ID: TEST_PROTOCOL".
    - **Step 4:** Send a POST request to the `/webhook-wci` endpoint with the modified JSON payload using `curl` or a similar tool.
    ```bash
    curl -X POST "https://<wci-instance-url>/webhook-wci" \
    -H "Content-Type: application/json" \
    -d '{
      "object": "whatsapp_business_account",
      "entry": [
        {
          "id": "1234",
          "changes": [
            {
              "value": {
                "messaging_product": "whatsapp",
                "metadata": {
                  "display_phone_number": "+1 234-5678",
                  "phone_number_id": "12345678"
                },
                "contacts": [
                  {
                    "profile": {
                      "name": "Test, Test"
                    },
                    "wa_id": "ATTACKER_SPOOFED_WA_ID"
                  }
                ],
                "messages": [
                  {
                    "from": "ATTACKER_SPOOFED_PHONE_NUMBER",
                    "id": "test_1",
                    "timestamp": "1723232055",
                    "text": {
                      "body": "Chat ID: TEST_PROTOCOL"
                    },
                    "type": "text"
                  }
                ]
              },
              "field": "messages"
            }
          ]
        }
      ]
    }'
    ```
    - **Step 5:** Check the BigQuery tables (`leads` and `chat_leads`) to verify if the spoofed message and protocol were processed and saved. Specifically, check if a record exists in `leads` table with `protocol = 'TEST_PROTOCOL'` and `phone = 'ATTACKER_SPOOFED_PHONE_NUMBER'` (or the spoofed `wa_id` depending on how `get_protocol_by_phone` processes it). Also check `chat_leads` for the spoofed message content.
    - **Step 6:** If the spoofed data is successfully saved in BigQuery, it confirms that the `/webhook-wci` endpoint is vulnerable to unauthenticated message injection.
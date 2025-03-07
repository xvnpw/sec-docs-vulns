### Vulnerability List

- Vulnerability Name: Data Injection via Crafted Application ID in Notification Endpoint
- Description:
    - An attacker can send a crafted HTTP POST request to the Notification Endpoint URL.
    - The attacker manipulates the `applicationId` parameter within the JSON payload of the POST request.
    - The `NotificationHandler` function parses this `applicationId` and extracts the `app_name` and `app_subscription_id`.
    - These extracted values from the attacker-controlled `applicationId` are directly used as `RowKey` and `PartitionKey` when storing data in Azure Table Storage.
    - By crafting a malicious `applicationId`, an attacker can control the storage location in the table.
    - This can lead to overwriting or inserting data associated with different managed applications than intended by legitimate system operations.
- Impact:
    - Inaccurate monitoring data in Azure Table Storage.
    - Misleading alerts and analytics for managed application solution owners relying on this data.
    - Potential for attackers to inject false or malicious data, disrupting the intended monitoring and management processes.
- Vulnerability Rank: Medium
- Currently Implemented Mitigations:
    - None. The code uses `parse_resource_id` to parse the `applicationId`, which validates the format but does not prevent manipulation for data injection in table storage.
- Missing Mitigations:
    - Input validation and sanitization: Implement robust validation to ensure the `applicationId` corresponds to a legitimate and expected managed application context before using its components to construct table storage keys. Verify if the `applicationId` belongs to the expected scope or tenant.
    - Authorization: While likely handled by Azure Marketplace to some extent, consider implementing additional authorization checks within the function to verify the source of the notification and the legitimacy of the `applicationId`.
    - Data Sanitization for Table Storage: Sanitize or encode the `app_name` and `app_subscription_id` before using them as `RowKey` and `PartitionKey` to prevent any potential injection or encoding issues, although direct injection into keys is less of a concern than data values in NoSQL. The primary concern here is logical injection by controlling the keys.
- Preconditions:
    - The attacker needs to discover the URL of the publicly accessible Notification Endpoint Azure Function. This URL is configured in the Managed Application offer in Partner Center, but could potentially be exposed or guessed.
    - The attacker needs to be able to send HTTP POST requests to this URL.
- Source Code Analysis:
    - File: `/code/applications/NotificationHandler/__init__.py`
    - Step 1: The `main` function in `NotificationHandler/__init__.py` is triggered by an HTTP request.
    - Step 2: It retrieves the JSON request body and extracts `applicationId`, `eventType`, and `provisioningState`.
    - Step 3: It calls `parse_resource_id(application_id)` to parse the `applicationId` string.
    - Step 4: In the case of `provisioning_state == "Succeeded"` and `event_type == "PUT"`, it proceeds to store data in Azure Table Storage.
    - Step 5: The code constructs an entity dictionary for Azure Table Storage. Critically, `PartitionKey` is set to `app_subscription_id` and `RowKey` is set to `app_name`, both of which are derived directly from the parsed `applicationId` provided in the HTTP request body by the external caller.
    - Step 6: There is no validation to check if the provided `applicationId` is expected or authorized to be stored under the derived `PartitionKey` and `RowKey`.
    - Visualization:
        ```
        [External Attacker] --> HTTP POST Request (Crafted applicationId) --> [Notification Endpoint Function]
                                                                         |
                                                                         V
        [Notification Endpoint Function] --> parse_resource_id(applicationId) --> app_name, app_subscription_id
                                                                         |
                                                                         V
        [Notification Endpoint Function] --> Azure Table Storage (Store Entity with PartitionKey=app_subscription_id, RowKey=app_name)
        ```
- Security Test Case:
    - Step 1: Deploy the `NotificationHandler` Azure Function and obtain its function URL.
    - Step 2: Identify a target `subscription_id` (e.g., `bb5840c6-bd1f-4431-b82a-bcff37b7fd07`) and a target `app_name` (e.g., `existing-app`). Assume there is already legitimate data in the table storage with `PartitionKey = bb5840c6-bd1f-4431-b82a-bcff37b7fd07` and `RowKey = existing-app`.
    - Step 3: Craft a malicious JSON payload for a POST request. In the `applicationId` field, use the target `subscription_id` and the target `app_name`, but potentially use a different `resourceGroup` or other parts of the `applicationId` to differentiate the injected data if needed.
        ```json
        {
            "eventType": "PUT",
            "applicationId": "subscriptions/bb5840c6-bd1f-4431-b82a-bcff37b7fd07/resourceGroups/attacker-rg/providers/Microsoft.Solutions/applications/existing-app",
            "eventTime": "2024-01-01T12:00:00Z",
            "provisioningState": "Succeeded",
            "plan": {
                "name": "attacker-plan",
                "product": "attacker-product",
                "publisher": "attacker-publisher",
                "version": "1.0-malicious"
            }
        }
        ```
    - Step 4: Send the crafted HTTP POST request to the Notification Endpoint URL.
    - Step 5: Access the Azure Table Storage and examine the entity with `PartitionKey = bb5840c6-bd1f-4431-b82a-bcff37b7fd07` and `RowKey = existing-app`.
    - Step 6: Verify if the data for this entity has been modified or overwritten with the data from the malicious payload (e.g., check for "version": "1.0-malicious" or "attacker-plan").
    - Step 7: If the entity has been modified with attacker-controlled data, the vulnerability is confirmed, demonstrating that an attacker can inject/manipulate data by crafting the `applicationId` in the notification request.
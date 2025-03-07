## Combined Vulnerability List

### 1. SSML Injection Vulnerability

*   **Vulnerability Name:** SSML Injection
*   **Description:**
    An attacker can inject malicious SSML code into the `text` field of the Google Sheet configuration. This field is directly used as input to the Google Text-to-Speech (TTS) API without proper sanitization or validation. By crafting a malicious SSML payload, an attacker can manipulate the audio synthesis process in unintended ways.

    Steps to trigger the vulnerability:
    1.  An attacker gains access to the Google Sheet used to configure the AI Dubbing process. While direct write access to the sheet might be restricted, an attacker could potentially compromise an account with write access or exploit any vulnerabilities in the sheet's sharing settings.
    2.  The attacker locates the `text` column in the configuration sheet.
    3.  The attacker injects malicious SSML code into the `text` field of a new or existing row. For example, the attacker could inject SSML tags that cause the TTS engine to produce unexpected sounds, include external audio files, or potentially exploit any vulnerabilities in the SSML processing engine itself. A sample malicious payload could be: `<speak><audio src='https://attacker.com/malicious.mp3'>Fallback text</audio></speak>`. This SSML payload attempts to include an audio file from an attacker-controlled external source.
    4.  The AI Dubbing application, running on a schedule or triggered manually, reads the configuration from the Google Sheet, including the malicious SSML payload.
    5.  The `generate_tts_files` Cloud Function processes this row and calls the Google TTS API with the unsanitized SSML payload.
    6.  The Google TTS API processes the malicious SSML, potentially executing the injected commands or accessing external resources as instructed by the attacker's payload.
    7.  The TTS API generates audio based on the malicious SSML, which could include unexpected audio content or behavior.
    8.  The generated audio file, potentially containing malicious content, is stored in the designated Google Cloud Storage bucket.
    9.  Subsequently, the `generate_video_file` Cloud Function uses this audio file to create the final dubbed video.

*   **Impact:**
    Successful exploitation of this vulnerability can lead to several negative impacts:
    *   **Reputation Damage:** The generated videos could contain inappropriate or malicious audio content, damaging the reputation of the video creator or the organization using the AI Dubbing tool.
    *   **Dissemination of Misinformation:**  Malicious audio content can be injected, leading to the spread of incorrect or misleading information if the injected audio contradicts the video content.
    *   **Offensive Content Injection:** Offensive or inappropriate audio content can be injected, further damaging reputation and potentially causing legal issues.
    *   **Unauthorized Promotion:** Attackers could inject audio advertisements or promotional material for their own purposes, hijacking the video content for unintended promotion.
    *   **Unexpected Behavior:** Malicious SSML could cause the TTS engine to behave unexpectedly, leading to errors or disruptions in the video dubbing process.
    *   **Information Disclosure (Potential):** While not immediately apparent in the provided code, vulnerabilities in SSML processing engines *could* potentially be exploited to access or disclose sensitive information, depending on the complexity of the SSML processing engine and the nature of potential SSML injection flaws. This is a less direct impact in this specific project, but a general risk associated with unsanitized SSML processing.
    *   **Resource Consumption (Potential):** An attacker could potentially craft SSML to consume excessive TTS processing resources, although this project is explicitly excluding denial-of-service vulnerabilities.

*   **Vulnerability Rank:** High

*   **Currently Implemented Mitigations:**
    There are no mitigations currently implemented in the provided code. The application directly takes the `text` field from the Google Sheet and uses it as SSML input to the Google TTS API without any sanitization or validation.

*   **Missing Mitigations:**
    *   **Input Sanitization:** The most critical missing mitigation is input sanitization of the `text` field from the Google Sheet. The application should sanitize the SSML input to remove or neutralize any potentially malicious SSML tags or attributes before sending it to the TTS API. A whitelist approach, allowing only a predefined set of safe SSML tags and attributes, would be recommended.
    *   **Input Validation:** Input validation should be implemented to verify that the `text` field contains valid SSML and conforms to expected structure. This could involve parsing the SSML and checking for disallowed tags or attributes.
    *   **Access Control:** Implement robust access control measures for the Google Sheet to restrict write access only to authorized users. Utilize Google Workspace's sharing and permission settings to manage access effectively. Consider using a dedicated service account with minimal necessary permissions to access the sheet programmatically, rather than relying on broad user access.
    *   **Content Security Policy (CSP) for SSML (If applicable):** If the TTS engine and the context in which the audio is used support any form of Content Security Policy for SSML, this could be used to restrict the capabilities of the SSML processing and mitigate certain types of injection attacks (e.g., preventing the inclusion of external audio sources if not needed). However, CSP for SSML is not a widely standardized concept and might have limited applicability depending on the specific TTS engine. In this case, sanitization is the primary needed mitigation.

*   **Preconditions:**
    *   **Access to Google Sheet Configuration:** An attacker needs to have the ability to modify the Google Sheet configuration, specifically the `text` field. This could be achieved through direct authorized access, compromised credentials, or exploiting vulnerabilities in the Google Sheet sharing mechanism.
    *   **Project Deployment:** The AI Dubbing project must be deployed and running, with the Cloud Functions and Google Sheet properly configured.
    *   **Scheduled Execution or Manual Trigger:** The system needs to be triggered to process the configuration sheet, either through its scheduled execution or a manual "Force Run".

*   **Source Code Analysis:**

    1.  **Configuration Reading (`src/cfs/generate_tts_files/main.py`, `_read_config_from_google_sheet`):**
        The `_read_config_from_google_sheet` function fetches data from the Google Sheet using the Google Sheets API. It retrieves all values within the specified `CONFIG_RANGE_NAME` and organizes them into a list of dictionaries, where each dictionary represents a row and keys are column headers. The `text` field is read as a plain string without any processing at this stage.

        ```python
        def _read_config_from_google_sheet(sheet_id, sheet_name) -> List[Dict]:
            # ...
            result = sheet.values().get(spreadsheetId=CONFIG_SPREADSHEET_ID,
                                        range=CONFIG_RANGE_NAME).execute()
            values = result.get('values', [])
            # ...
            for row in values[1:]:
                if row:
                    new_row = {field: value for field, value in zip(headers, row)} # No sanitization here
                    # ...
                    rows.append(new_row)
            return rows
        ```

    2.  **TTS API Call (`src/cfs/generate_tts_files/main.py`, `_tts_api_call`):**
        The `_tts_api_call` function receives a `line` dictionary, which includes the `text` field from the Google Sheet. It directly uses this `line['text']` value to create a `texttospeech.SynthesisInput` object with `ssml=line['text']`.  This `SynthesisInput` object is then passed to the `client.synthesize_speech` method to generate the TTS audio.

        ```python
        def _tts_api_call(line: Dict, file_name: str):
            # ...
            # Set the text input to be synthesized
            synthesis_input = texttospeech.SynthesisInput(ssml=line['text']) # Unsanitized input from Google Sheet
            # ...
            response = client.synthesize_speech(
                input=synthesis_input, voice=voice, audio_config=audio_config
            )
            # ...
        ```

    **Visualization:**

    ```
    Google Sheet (text field) --> _read_config_from_google_sheet --> line['text'] (Unsanitized) --> _tts_api_call --> texttospeech.SynthesisInput(ssml=line['text']) --> Google TTS API
    ```

    The data flow clearly shows that the `text` field from the Google Sheet is directly passed to the TTS API as SSML without any intermediate sanitization or validation, making the system vulnerable to SSML injection.

*   **Security Test Case:**

    1.  **Pre-requisites:**
        *   Deploy the AI Dubbing application to Google Cloud.
        *   Create a copy of the configuration Google Sheet.
        *   Ensure you have access to modify the configuration Google Sheet.
        *   Identify the Google Cloud Storage bucket used by the application.

    2.  **Steps:**
        a.  Open the configuration Google Sheet.
        b.  In a new row (or an existing row that you can modify), in the `text` column, insert the following malicious SSML payload:
            ```xml
            <speak><audio src='https://interactive-examples.mdn.mozilla.net/media/examples/t-rex-roar.mp3'>Fallback text</audio></speak>
            ```
            This payload attempts to include an external audio file (a T-Rex roar in this example). You can replace this URL with any publicly accessible audio file URL for testing.
        c.  Fill in the other mandatory fields in the row (campaign, topic, gcs_bucket, video_file, voice_id, audio_encoding) with valid values as required by the application.
        d.  Trigger the AI Dubbing process. This can be done by either waiting for the scheduled execution or by manually triggering the `ai-dubbing-trigger` Cloud Scheduler job in your Google Cloud project (as described in the README).
        e.  Monitor the "Status" column in the Google Sheet. Wait until the status for the row you modified becomes "TTS OK" and then "Video OK".
        f.  Once the status is "Video OK", check the Google Cloud Storage bucket configured for output.
        g.  Download the generated video file (mp4) corresponding to the row you modified.
        h.  Open and play the downloaded video file.

    3.  **Expected Result:**
        The generated video should contain the audio from the external URL injected in the SSML payload (the T-Rex roar in this example), instead of synthesized speech from the "Fallback text" or the intended text. This confirms that the malicious SSML payload was successfully processed by the TTS engine, demonstrating the SSML injection vulnerability.

    4.  **Cleanup:**
        After testing, remove or modify the malicious SSML payload from the Google Sheet to prevent unintended video generation with malicious audio.


### 2. Uncontrolled Output Bucket Leading to Potential Data Exfiltration

*   **Vulnerability Name:** Uncontrolled Output Bucket
*   **Description:**
    The AI Dubbing application reads the output Google Cloud Storage (GCS) bucket from the configuration Google Spreadsheet. The `generate_video_file` Cloud Function then uses this configured bucket to store the generated video files. If an attacker gains unauthorized write access to the configuration spreadsheet, they can modify the `gcs_bucket` parameter to point to a GCS bucket under their control. This allows the attacker to redirect the output of the video dubbing process, effectively exfiltrating the generated video content.

    Steps to trigger the vulnerability:
    1.  The AI Dubbing application reads configuration parameters, including the output Google Cloud Storage (GCS) bucket, from a Google Spreadsheet.
    2.  The `generate_video_file` Cloud Function uses the `gcs_bucket` parameter from the spreadsheet configuration to store the generated video file.
    3.  An attacker who gains unauthorized write access to the configuration spreadsheet can modify the `gcs_bucket` parameter.
    4.  By changing the `gcs_bucket` value to a GCS bucket under their control, the attacker can redirect the output of the video dubbing process to their own bucket.
    5.  When the application processes a configuration row with the attacker-modified `gcs_bucket`, the generated video file, which could contain sensitive content from the victim's `video_file`, will be uploaded to the attacker's bucket.
    6.  This allows the attacker to exfiltrate video content processed by the AI Dubbing application.

*   **Impact:**
    *   **Data Exfiltration:** Attackers can gain unauthorized access to potentially sensitive video and audio content processed by the application. This content is intended to be stored in the victim's GCS bucket but is redirected to an attacker-controlled bucket.
    *   **Confidentiality Breach:**  Compromises the confidentiality of the video and audio data.

*   **Vulnerability Rank:** High

*   **Currently Implemented Mitigations:**
    *   None in the application code itself.
    *   The README.md mentions that Google Cloud IAM roles are granted to the service account, suggesting that access control should be managed at the Google Cloud project level. However, there are no specific controls within the application to prevent using arbitrary output buckets.

*   **Missing Mitigations:**
    *   **Input Validation and Sanitization:** The application should validate and sanitize the `gcs_bucket` parameter read from the spreadsheet. It should verify that the bucket name conforms to expected patterns and potentially check if the target bucket is within an allowed list or the same Google Cloud project.
    *   **Output Bucket Restriction:** The application should enforce that the output GCS bucket must be within the same Google Cloud project as the application or a pre-defined list of allowed buckets. It should not blindly use any `gcs_bucket` value provided in the configuration spreadsheet without validation.
    *   **Spreadsheet Access Control:** While not a code mitigation, it's crucial to properly configure Google Spreadsheet sharing permissions to restrict write access only to authorized users and service accounts, as highlighted in the initial threat vector description.

*   **Preconditions:**
    *   Attacker gains unauthorized write access to the Google Spreadsheet used for configuration (CONFIG_SPREADSHEET_ID). This could be due to compromised Google account credentials, misconfigured sharing settings on the spreadsheet, or other access control vulnerabilities.

*   **Source Code Analysis:**
    *   **File: `/code/src/cfs/generate_video_file/main.py`**
        *   Function: `_copy_file_to_gcs(gcs_bucket, source_local_filename, destination_blob_name)`
            ```python
            def _copy_file_to_gcs(gcs_bucket: str, source_local_filename: str, destination_blob_name: str):
                """Copies a file to Google Cloud Storage from a temporary local filename.

                Args:
                  gcs_bucket: string containing the bucket name.
                  source_local_filename: Name of the local file that will be copied.
                  destination_blob_name: Name of the blob to be created in GCS.
                """
                storage_client = storage.Client()
                bucket = storage_client.bucket(gcs_bucket) # [VULNERABLE LINE] - gcs_bucket is taken directly from config
                blob = bucket.blob(destination_blob_name)
                print(gcs_bucket)
                print(source_local_filename)
                print(destination_blob_name)
                print('Checking if blob exists')
                if blob.exists():
                    print('Deleting existing target file')
                    blob.delete()
                blob.upload_from_filename(source_local_filename)
            ```
            *   **Vulnerability Point:** Line `bucket = storage_client.bucket(gcs_bucket)` directly uses the `gcs_bucket` variable, which originates from the Google Spreadsheet configuration without any validation or restriction.
            *   **Flow:**
                1.  The `main` function in `generate_video_file/main.py` is triggered by a Pub/Sub message.
                2.  The message data (configuration) includes the `gcs_bucket` value, which is read from the spreadsheet in the `generate_tts_files` Cloud Function.
                3.  `_mix_video_and_speech` function is called with the configuration.
                4.  Inside `_mix_video_and_speech`, after generating the video file, `_copy_file_to_gcs` is called to upload the video.
                5.  The `gcs_bucket` parameter passed to `_copy_file_to_gcs` is directly taken from the configuration, which can be manipulated by an attacker via the spreadsheet.
                6.  The generated video is then uploaded to the attacker-specified `gcs_bucket`.

*   **Security Test Case:**
    1.  **Prerequisites:**
        *   Deploy the AI Dubbing application in a Google Cloud project.
        *   Create and configure the Google Spreadsheet with valid input data, including a `gcs_bucket` that you control for testing purposes initially.
        *   Ensure the application is functioning correctly and generating videos in your test GCS bucket.
        *   Create a separate Google Cloud project and a GCS bucket within it. This will be the attacker-controlled bucket. Note the name of this attacker bucket.
    2.  **Exploit Steps:**
        *   Assume you have gained write access to the configuration Google Spreadsheet (e.g., through compromised credentials or misconfiguration).
        *   Open the configuration spreadsheet.
        *   Locate a row that will be processed by the application (or create a new row).
        *   Modify the `gcs_bucket` column in this row to the name of the attacker-controlled GCS bucket you created in step 1. Keep other mandatory fields valid, such as `video_file`, `text`, and `voice_id`, pointing to valid resources in the victim's project (or your test project if testing end-to-end).
        *   Save the changes to the spreadsheet.
        *   Trigger the AI Dubbing process. This can be done by waiting for the scheduled execution of the Cloud Scheduler job or by manually triggering the `ai-dubbing-trigger` Cloud Scheduler job from the Google Cloud Console (as described in the README.md under "Note" in "Trigger the generation process").
    3.  **Verification Steps:**
        *   After triggering the process, wait for the Cloud Functions to execute (check Cloud Function logs for progress or errors).
        *   Go to the Google Cloud Console and navigate to the attacker-controlled GCS bucket you specified in the spreadsheet.
        *   Check if the generated video file (named based on `campaign`, `topic`, and `voice_id` from the spreadsheet row) is present in the attacker-controlled bucket.
        *   If the video file is found in the attacker's bucket, the data exfiltration vulnerability is confirmed.
        *   Optionally, check the original (victim's or test) GCS bucket specified in the Terraform variables. The video file might or might not be present there depending on the exact code execution flow, but the critical point is its presence in the attacker's bucket.
    4.  **Expected Result:** The generated video file should be found in the attacker-controlled GCS bucket, demonstrating successful data exfiltration due to the uncontrolled output bucket vulnerability. The "Status" column in the spreadsheet for the modified row should ideally indicate "Video OK," misleadingly suggesting successful operation from the victim's perspective.
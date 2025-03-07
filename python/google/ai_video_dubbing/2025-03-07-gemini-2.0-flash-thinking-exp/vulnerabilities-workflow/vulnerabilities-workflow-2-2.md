### Vulnerability List:

- Vulnerability Name: SSML Injection
- Description:
    1. An attacker gains unauthorized access to the Google Spreadsheet used to configure the video dubbing process. This could be due to compromised credentials, insider threat, or misconfigured sharing permissions on the spreadsheet.
    2. The attacker locates and modifies the "text" field within a row in the "config" sheet of the Google Spreadsheet. This field is intended to contain SSML (Speech Synthesis Markup Language) text for the text-to-speech conversion.
    3. The attacker injects malicious or unexpected SSML code into the "text" field. For example, the attacker might insert SSML tags that cause the text-to-speech engine to behave in unintended ways, such as introducing long pauses using `<break time="9999s"/>`, attempting to include audio from external sources using `<audio src="https://attacker.com/malicious.mp3">`, or manipulating voice parameters in unexpected ways.
    4. The `generate_tts_files` Cloud Function is triggered, either automatically by the Cloud Scheduler on its defined schedule or manually via "Force Run" in the Cloud Scheduler console.
    5. The `_read_config_from_google_sheet` function in `generate_tts_files/main.py` reads the configuration data from the Google Spreadsheet, including the modified "text" field containing the malicious SSML code.
    6. The `_generate_tts` function iterates through the rows of configuration data and calls the `_tts_api_call` function for each row to generate the text-to-speech audio file.
    7. The `_tts_api_call` function in `generate_tts_files/main.py` receives the configuration data for a row, including the attacker-modified "text" field. It directly uses the content of the "text" field to construct the `synthesis_input` for the Google Text-to-Speech API call without any sanitization or validation. The line `synthesis_input = texttospeech.SynthesisInput(ssml=line['text'])` is vulnerable.
    8. The Google Text-to-Speech API processes the `synthesis_input` which now contains the malicious SSML code.
    9. The Text-to-Speech API engine executes the injected SSML commands. Depending on the nature of the injected SSML, this can result in various outcomes, such as:
        - Unexpected audio content being generated, including silences, distortions, or attempts to play external audio if `<audio src="...">` tags are used.
        - Errors during audio synthesis if the injected SSML is invalid or exploits vulnerabilities in the TTS engine (though less likely to be exploitable for severe impact in this context).
        - Unintended behavior in the subsequent video generation process if the generated audio is corrupted or malformed due to the SSML injection.
- Impact:
    - Generation of unexpected or corrupted audio output, potentially disrupting the intended video dubbing process.
    - Introduction of unintended silences or noises into the generated audio.
    - Potential for the TTS service to attempt to access external resources if malicious `<audio src="...">` tags are injected, although the direct security impact of this in this context is limited to potentially unexpected audio and resource usage.
    - The overall quality and intended message of the dubbed video can be compromised.
- Vulnerability Rank: Medium
- Currently Implemented Mitigations:
    - None. The application directly processes the SSML text from the Google Spreadsheet without any sanitization or validation.
- Missing Mitigations:
    - Input Sanitization: Implement sanitization of the "text" field read from the Google Spreadsheet before passing it to the Text-to-Speech API. This should involve removing or escaping potentially harmful SSML tags and attributes. A whitelist approach, allowing only a safe subset of SSML tags and attributes, would be more secure than a blacklist.
    - Input Validation: Validate the structure and content of the "text" field to ensure it conforms to the expected SSML format and only contains allowed tags and attributes. This could include schema validation or parsing and verifying the SSML structure.
- Preconditions:
    - Attacker has write access to the Google Spreadsheet that is configured as the input for the AI Dubbing application.
    - The AI Dubbing application is actively running and configured to process the Google Spreadsheet.
- Source Code Analysis:
    1. File: `/code/src/cfs/generate_tts_files/main.py`
    2. Function: `_tts_api_call(line: Dict, file_name: str)`
    3. Vulnerable Line: `synthesis_input = texttospeech.SynthesisInput(ssml=line['text'])`
    4. **Code Flow Visualization:**
        ```
        Google Spreadsheet (Config Sheet) --> _read_config_from_google_sheet() --> lines (List[Dict])
        lines --> _generate_tts() --> for line in lines: ... _tts_api_call(line, file_name)
        _tts_api_call(line, file_name):
            synthesis_input = texttospeech.SynthesisInput(ssml=line['text'])  <-- Vulnerable point: No sanitization of line['text']
            client.synthesize_speech(input=synthesis_input, ...)
        ```
    5. **Step-by-step analysis:**
        - The `_tts_api_call` function is responsible for calling the Google Text-to-Speech API.
        - It takes a dictionary `line` as input, which represents a row from the Google Spreadsheet.
        - It directly accesses the 'text' key from the `line` dictionary: `line['text']`.
        - This `line['text']` value, which is directly taken from the Google Spreadsheet, is used to create the `SynthesisInput` object for the TTS API: `texttospeech.SynthesisInput(ssml=line['text'])`.
        - Critically, there is no code present to sanitize or validate the content of `line['text']` before it is used in the `SynthesisInput`.
        - Therefore, any SSML code present in the "text" field of the Google Spreadsheet will be passed directly to the Google TTS API for processing. This lack of sanitization is the root cause of the SSML Injection vulnerability.
- Security Test Case:
    1. **Setup:** Ensure the AI Dubbing application is set up and running, connected to a Google Spreadsheet that you have write access to. Identify a row in the "config" sheet to modify.
    2. **Inject Malicious SSML (Break Tag):**
        - In the Google Spreadsheet, locate the "text" field of the chosen row.
        - Replace the existing content of the "text" field with the following SSML code: `<speak><break time="15s"/></speak>`. This code injects a 15-second pause into the audio.
    3. **Trigger TTS Generation:**
        - Trigger the `generate_tts_files` Cloud Function. This can be done by waiting for the scheduled execution or by manually forcing a run of the "ai-dubbing-trigger" Cloud Scheduler job in the Google Cloud Console.
    4. **Verify Audio Output (Break Tag):**
        - After the Cloud Function execution completes, check the logs to ensure there were no errors.
        - Locate the generated TTS audio file in the configured output Google Cloud Storage bucket. The file path will be similar to `gs://{gcs_bucket}/output/{YYYYMMDD}/{campaign}-{topic}-{voice_id}.mp3`.
        - Download the generated audio file (e.g., using `gsutil cp`).
        - Play the downloaded audio file.
        - **Verification:** Listen to the audio file. You should observe a silence of approximately 15 seconds at the beginning of the audio, before the actual text-to-speech content begins. This confirms that the `<break time="15s"/>` SSML tag was successfully injected and processed by the TTS engine.
    5. **Inject Malicious SSML (Audio Tag - External Resource):**
        - In the same Google Spreadsheet and row, replace the "text" field content with: `<speak><audio src="https://upload.wikimedia.org/wikipedia/commons/9/9c/Speech_noise.ogg">Fallback Text</audio></speak>`. This code attempts to include audio from an external URL.
    6. **Trigger TTS Generation (Again):**
        - Trigger the `generate_tts_files` Cloud Function again as described in step 3.
    7. **Verify Audio Output (Audio Tag):**
        - After execution, check the Cloud Function logs for any errors or warnings related to external resource access or the `<audio>` tag.
        - Download and play the newly generated audio file from the GCS bucket.
        - **Verification:** Listen to the audio file.
            - **Successful Injection:** If the audio output is speech noise from the provided URL (or the "Fallback Text" if the external audio fails to load but the tag is processed), it indicates successful SSML injection.
            - **Partial Success/Error Indication:** Even if the external audio is blocked by the TTS service and you hear only standard TTS output or an error in logs, the fact that the system *attempted* to process the `<audio src="...">` tag from the spreadsheet demonstrates that malicious SSML is being passed to the TTS engine, confirming the vulnerability.

By successfully performing these test cases, you can demonstrate the SSML Injection vulnerability in the AI Dubbing application.
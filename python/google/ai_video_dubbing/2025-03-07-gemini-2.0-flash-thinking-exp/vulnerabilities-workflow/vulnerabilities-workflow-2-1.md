- Vulnerability Name: SSML Injection in Text-to-Speech Configuration
- Description:
    1. An attacker gains unauthorized write access to the Google Sheet used to configure the video dubbing process. This Google Sheet is defined by the `CONFIG_SPREADSHEET_ID` environment variable and is directly accessed by the `generate_tts_files` Cloud Function.
    2. The attacker locates the `text` column in the configuration sheet. This column contains the SSML text that will be converted to speech by the Google Text-to-Speech API.
    3. The attacker modifies the content of the `text` column in one or more rows, injecting malicious SSML payloads. For example, the attacker could inject SSML to play unexpected audio, include offensive language, or embed misleading information within the audio dubbing.
    4. The Cloud Scheduler triggers the `generate_tts_files` Cloud Function periodically, as defined by the `execution_schedule` variable in `variables.tf`. Alternatively, an attacker could manually trigger the Cloud Function if they have appropriate permissions.
    5. The `generate_tts_files` function reads the configuration from the Google Sheet, including the attacker-modified `text` field.
    6. The function iterates through each row and calls the `_tts_api_call` function.
    7. The `_tts_api_call` function directly uses the value from the `text` field as input to the Google Text-to-Speech API without any sanitization or validation. Specifically, it constructs the `synthesis_input` using `texttospeech.SynthesisInput(ssml=line['text'])`.
    8. The Google Text-to-Speech API processes the malicious SSML and generates an audio file based on it.
    9. The generated audio file, containing the attacker's injected audio, is stored in Google Cloud Storage.
    10. Subsequently, the `generate_video_file` Cloud Function uses this audio file to dub the video, embedding the malicious audio content into the final video output.
- Impact:
    - The attacker can inject arbitrary audio content into the dubbed videos.
    - This can lead to the dissemination of misinformation if the injected audio contradicts the video content or adds misleading narratives.
    - Offensive or inappropriate audio content can be injected, damaging the reputation of the video content creator or distributor.
    - The attacker could potentially insert audio advertisements or promotional material for their own purposes, hijacking the video content for unintended promotion.
    - Depending on the nature of the injected SSML, there might be potential for further exploitation if the SSML processing by downstream systems or viewers has vulnerabilities (though less likely in this specific context).
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - None. The provided code directly processes the `text` field from the Google Sheet without any input validation or sanitization.
- Missing Mitigations:
    - Input Sanitization: Implement sanitization of the `text` field from the Google Sheet to remove or neutralize potentially harmful SSML tags or attributes. A strict whitelist of allowed SSML tags and attributes should be enforced.
    - Input Validation: Validate the structure and content of the `text` field to ensure it conforms to expected SSML format and does not contain malicious or unexpected elements.
    - Access Control: Implement robust access control measures for the Google Sheet to restrict write access only to authorized users. Utilize Google Workspace's sharing and permission settings to manage access effectively. Consider using a dedicated service account with minimal necessary permissions to access the sheet programmatically, rather than relying on broad user access.
    - Content Security Policy (CSP) for Video Players: If the generated videos are embedded on web pages, consider implementing Content Security Policy headers to mitigate potential risks if malicious SSML could somehow lead to client-side execution vulnerabilities (though this is less relevant for audio injection itself, it's a general security best practice).
- Preconditions:
    - The attacker must gain write access to the Google Sheet configuration defined by `CONFIG_SPREADSHEET_ID`. This could be achieved through compromised Google accounts, insider threats, or misconfigured sharing permissions on the Google Sheet.
- Source Code Analysis:
    - File: `/code/src/cfs/generate_tts_files/main.py`
    - Function: `_tts_api_call(line: Dict, file_name: str)`
    ```python
    def _tts_api_call(line: Dict, file_name: str):
      """
      It call the TTS API with the parameters received in the line parameter

      Args:
        line: Dict object containing the fields to generate the tts audio file
      """

      # Instantiates a client
      client = texttospeech.TextToSpeechClient()
      # Set the text input to be synthesized
      synthesis_input = texttospeech.SynthesisInput(ssml=line['text']) # Vulnerable line: Directly uses 'text' from Google Sheet

      # Build the voice request, select the language code ("en-US") and the ssml
      # voice gender ("neutral")
      voice_id = line['voice_id'].split('##')[0]
      language_code = line['voice_id'][:5]
      voice = texttospeech.VoiceSelectionParams(language_code=language_code, name=voice_id)

      # Select the type of audio file you want returned
      audio_config = texttospeech.AudioConfig(
          audio_encoding=eval('texttospeech.AudioEncoding.' + line['audio_encoding'])
      )

      # Perform the text-to-speech request on the text input with the selected
      # voice parameters and audio file type
      response = client.synthesize_speech(
          input=synthesis_input, voice=voice, audio_config=audio_config
      )

      # ... (rest of the function)
    ```
    - The `_tts_api_call` function in `generate_tts_files/main.py` directly uses `line['text']` to create the `synthesis_input` for the Text-to-Speech API.
    - The `line` dictionary is populated from the Google Sheet in the `_read_config_from_google_sheet` function.
    - There is no sanitization or validation of the `line['text']` content before it is passed to the Text-to-Speech API.
    - This direct usage of unsanitized input from the Google Sheet allows an attacker who can modify the sheet to inject arbitrary SSML code.

- Security Test Case:
    1. Precondition: Ensure you have write access to the Google Sheet specified by the `CONFIG_SPREADSHEET_ID` environment variable used by the deployed Cloud Functions.
    2. Open the Google Sheet in a web browser.
    3. Locate the `text` column in the configuration sheet.
    4. Choose any row in the sheet. In the `text` column for that row, replace the existing SSML content with the following malicious SSML payload:
        ```xml
        <speak>
          <say-as interpret-as="spell-out">PWNED</say-as>
          <audio src="https://upload.wikimedia.org/wikipedia/commons/c/c4/ achievement.ogg">Pwned!</audio>
        </speak>
        ```
        This SSML payload will first spell out "PWNED" and then play an audio file from an external source.
    5. Wait for the Cloud Scheduler to trigger the `generate_tts_files` function (according to the schedule defined in `variables.tf`). Alternatively, you can manually trigger the `ai-dubbing-trigger` Cloud Scheduler job in the Google Cloud Console.
    6. After the `generate_tts_files` function executes, check the "status" column in the modified row of the Google Sheet. It should eventually change to "TTS OK" if the TTS generation was successful.
    7. Locate the generated TTS audio file in the Google Cloud Storage bucket specified in the configuration (`gcs_bucket` column in the sheet). The file path will be in the format `output/YYYYMMDD/{campaign}-{topic}-{voice_id}.mp3`.
    8. Download the generated audio file and listen to it. You should hear the audio output corresponding to the malicious SSML payload, including the "PWNED" spelling and the external audio clip.
    9. If the video generation process is automatically triggered after TTS generation (via Pub/Sub), wait for it to complete. Otherwise, manually trigger the `generate_video_file` Cloud Function, ensuring it processes the row you modified in the Google Sheet.
    10. After the `generate_video_file` function executes and the "status" in the Google Sheet updates to "Video OK", locate and download the generated video file from the GCS bucket.
    11. Play the generated video file. You should observe that the video now contains the malicious audio content injected through the SSML payload, demonstrating the SSML injection vulnerability.
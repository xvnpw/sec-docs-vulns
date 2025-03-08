### Vulnerability 1: WAV Header Injection in Live Transcriptions

- Description:
    1. An attacker establishes a websocket connection to the `/streaming-whisper/ws/{UNIQUE_MEETING_ID}` endpoint.
    2. Instead of sending raw PCM audio data as expected, the attacker crafts a malicious payload.
    3. This payload consists of a valid Skynet header (60 bytes, including participant ID and language) prepended to a standard WAV audio file (which inherently includes a WAV header).
    4. The Skynet server's audio processing pipeline, specifically the Faster Whisper integration, receives this combined payload.
    5. Due to the lack of validation for WAV headers in the input stream, the Faster Whisper library attempts to process the WAV header as if it were part of the raw audio data.
    6. This misinterpretation leads to incorrect audio decoding and transcription, potentially causing garbled or nonsensical transcriptions. In specific scenarios, this could lead to unexpected behavior within the application, although direct sensitive information disclosure is less likely.

- Impact:
    - Incorrect Live Transcriptions: The primary impact is the corruption of the live transcription service. Users relying on transcriptions will receive inaccurate and unreliable text output.
    - Potential for Unexpected Behavior: While not fully explored, misinterpreting binary data as audio could potentially lead to unexpected behavior within the Faster Whisper library, although this is less likely to be a severe security vulnerability and more of an operational issue.
    - Limited Information Disclosure (Indirect): In highly specific and theoretical scenarios, the garbled transcription *might* unintentionally reflect parts of the WAV header or internal data structures, leading to a very indirect and limited form of information disclosure. However, this is not the primary risk.

- Vulnerability Rank: Medium

- Currently implemented mitigations:
    - None. The application currently lacks any input validation to detect and reject audio streams containing WAV headers.

- Missing mitigations:
    - Input Validation: Implement a check at the websocket endpoint to inspect the incoming audio stream for a WAV header. If a WAV header is detected, the server should reject the connection or the audio chunk and log the event as a potential malicious activity.
    - Documentation Enhancement: While not a direct mitigation, clearly document the expected audio format (raw PCM, 16kHz, mono, no WAV header) in the `streaming_whisper_module.md` to guide developers and users on proper usage and potential issues.

- Preconditions:
    - `streaming_whisper` module must be enabled (`ENABLED_MODULES="streaming_whisper"`).
    - An attacker must be able to establish a websocket connection to the Skynet server's `/streaming-whisper/ws/{UNIQUE_MEETING_ID}` endpoint.
    - The attacker needs to have or create a WAV audio file to inject.

- Source code analysis:
    - `/code/skynet/modules/stt/streaming_whisper/app.py`: This file handles the websocket endpoint at `/ws/{meeting_id}`. It receives bytes via `websocket.receive_bytes()` and passes them to `ws_connection_manager.process(meeting_id, chunk, utils.now())`.
    - `/code/skynet/modules/stt/streaming_whisper/connection_manager.py`: The `ConnectionManager.process` method calls `self.connections[meeting_id].process(chunk, chunk_timestamp)`.
    - `/code/skynet/modules/stt/streaming_whisper/meeting_connection.py`: The `MeetingConnection.process` method creates a `Chunk` object from the received bytes and then calls `self.participants[a_chunk.participant_id].process(a_chunk, self.previous_transcription_tokens)`.
    - `/code/skynet/modules/stt/streaming_whisper/chunk.py`: The `Chunk` class's `__init__` method and `_extract` method are responsible for parsing the header:
        ```python
        class Chunk:
            def __init__(self, chunk: bytes, chunk_timestamp: int):
                self._extract(chunk)
                self.timestamp = chunk_timestamp
                self.duration = utils.convert_bytes_to_seconds(self.raw)
                self.size = len(self.raw)

            def _extract(self, chunk: bytes):
                header = chunk[0:60].decode('utf-8').strip('\x00')
                log.debug(f'Chunk header {header}')
                self.raw = chunk[60:]
                header_arr = header.split('|')
                self.participant_id = header_arr[0]
                self.language = utils.get_lang(header_arr[1])
        ```
        - The code extracts the first 60 bytes as a header and assumes the rest is raw audio data. There is **no validation** to check if the data after the header is indeed raw PCM and not a WAV file or other format.
    - `/code/skynet/modules/stt/streaming_whisper/utils/utils.py`: The `transcribe` function eventually passes the raw byte data to `faster-whisper` after a simple NumPy conversion in `load_audio`. `faster-whisper` is expected to process raw PCM and is not designed to handle WAV headers within the audio stream.

    ```mermaid
    graph LR
        A[WebSocket Client] --> B(Skynet App: /ws/{meeting_id} in app.py);
        B --> C(ConnectionManager.process in connection_manager.py);
        C --> D(MeetingConnection.process in meeting_connection.py);
        D --> E(Chunk.__init__ & _extract in chunk.py);
        E -- Raw Audio Bytes --> F(State.process in state.py);
        F --> G(utils.transcribe in utils.py);
        G --> H(faster-whisper library);
        H -- Transcription Result --> F;
        F -- TranscriptionResponse --> C;
        C -- JSON Response --> B;
        B --> A;
        style E fill:#f9f,stroke:#333,stroke-width:2px
        style H fill:#ccf,stroke:#333,stroke-width:2px
        style G fill:#ccf,stroke:#333,stroke-width:2px
        subgraph Audio Processing Flow
        E --> F --> G --> H
        end
    ```

- Security test case:
    1. **Setup:**
        - Ensure Skynet is running with the `streaming_whisper` module enabled.
        - Obtain a short WAV audio file (e.g., "test.wav", 16kHz, mono, PCM).
        - Determine the websocket URL for Live Transcriptions (e.g., `wss://<skynet-instance>:8000/streaming-whisper/ws/test_meeting?auth_token=<JWT_TOKEN>` or `ws://<skynet-instance>:8000/streaming-whisper/ws/test_meeting` if auth is bypassed).

    2. **Craft Malicious Payload:**
        - Open "test.wav" in binary read mode (`rb`).
        - Read the WAV file content into a byte variable, e.g., `wav_audio_data = open('test.wav', 'rb').read()`.
        - Create a valid Skynet header (60 bytes) with a participant ID (e.g., "attacker_id") and language (e.g., "en"), padded with null bytes if necessary: `header = b'attacker_id|en'.ljust(60, b'\0')`.
        - Combine the header and the WAV audio data: `malicious_payload = header + wav_audio_data`.

    3. **Send Malicious Payload via WebSocket:**
        - Establish a websocket connection to the Skynet server using a websocket client (e.g., wscat, browser-based websocket client, or Python's `websockets` library).
        - Send the `malicious_payload` as a binary message through the websocket: `ws.send(malicious_payload)`.
        - Keep sending chunks of `malicious_payload` if needed, mimicking a streaming audio scenario, or send the entire payload at once.

    4. **Send Valid Raw PCM Payload for Comparison:**
        - Extract the raw PCM audio data *without* the WAV header from "test.wav". You can use audio editing software or scripting for this. Let's assume you have this raw PCM data in `raw_pcm_data`.
        - Create a valid Skynet header for the raw PCM data: `valid_header = b'test_user|en'.ljust(60, b'\0')`.
        - Combine the valid header and raw PCM data: `valid_payload = valid_header + raw_pcm_data`.
        - Send the `valid_payload` as a binary message through the websocket: `ws.send(valid_payload)`.

    5. **Observe and Compare Transcriptions:**
        - Monitor the websocket messages received from the Skynet server for both payloads (malicious and valid).
        - Compare the transcriptions generated for the malicious payload (WAV header injected) and the valid payload (raw PCM).
        - **Expected Result:** The transcription for the malicious payload should be garbled, nonsensical, or significantly different and likely incorrect compared to the transcription of the valid raw PCM audio. This difference will demonstrate the vulnerability caused by the WAV header injection. The valid payload should produce a correct transcription of the audio content.
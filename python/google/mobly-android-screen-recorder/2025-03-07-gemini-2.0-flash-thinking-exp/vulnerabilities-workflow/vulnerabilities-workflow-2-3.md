### Vulnerability List

- **Vulnerability Name:** Unauthorised Screen Recording due to Missing Consent Enforcement

- **Description:**
    1. A malicious actor socially engineers a user (e.g., a developer or tester) into running a modified Mobly test script.
    2. This modified script includes the `mobly-android-screen-recorder` service.
    3. The service starts recording the Android device's screen when the test begins, as designed.
    4. However, the `mobly-android-screen-recorder` service itself does not have any mechanism to enforce explicit consent from the device user or the person running the test.
    5. The screen recording proceeds without any visual or programmatic indication on the Android device that recording is in progress (beyond the standard Android screen recording notification if triggered by other means, but not by this library itself).
    6. The recorded video is saved to the test output directory, accessible to whoever has access to the test execution environment.
    7. If the user is unaware of the screen recording, sensitive information displayed on the device screen during the test execution can be captured without their knowledge or consent.

- **Impact:**
    - **Privacy Violation:** Sensitive information displayed on the Android device screen, such as personal messages, emails, credentials, or application data, can be secretly recorded and accessed without the user's consent.
    - **Data Breach Risk:** Recorded videos could be exfiltrated from the test environment by the malicious actor, leading to a data breach.
    - **Legal and Ethical Implications:** Recording someone's screen without consent can have serious legal and ethical consequences, violating privacy laws and guidelines.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
    - **Documentation and Responsible Use Guidelines:** The `README.md` file includes a "Responsible Use" section and a "Disclaimer" that strongly emphasizes the need for explicit consent, legitimate purpose, data security, and transparency. It warns against misuse and highlights privacy concerns.
    - **Code of Conduct:** The project has a Code of Conduct that promotes ethical behavior and discourages inappropriate conduct.

- **Missing Mitigations:**
    - **Consent Mechanism within the Tool:** The library lacks any built-in mechanism to enforce or verify user consent before initiating screen recording. There is no prompt, notification, or programmatic check to ensure consent is obtained.
    - **Visual Indication of Recording:** The screen recording service does not provide any visual indication on the Android device's screen to inform the user that recording is in progress. A persistent notification or overlay icon could alert the user.
    - **Auditing and Logging:**  Lack of detailed logging of screen recording activities, including who initiated the recording and when, makes it difficult to audit usage and detect potential misuse.
    - **Access Control:** No access control mechanisms are implemented within the library to restrict who can initiate screen recordings.

- **Preconditions:**
    1. The attacker must be able to socially engineer a user into running a modified Mobly test script. This could involve sharing a seemingly legitimate test script or configuration that subtly includes the screen recording service.
    2. The user must have an Android device connected and configured for Mobly testing.
    3. The user must execute the modified Mobly test script on their testing environment.
    4. The `mobly-android-screen-recorder` library must be installed in the testing environment.

- **Source Code Analysis:**

    1. **Service Registration (`hello_world_test.py`, `README.md`):**
       - The `README.md` and example code (`hello_world_test.py`) clearly demonstrate how to register and start the `screen_recorder` service within a Mobly test script:
         ```python
         self.dut.services.register('screen_recorder', screen_recorder.ScreenRecorder)
         ```
       - This registration is sufficient to activate the screen recording service. There are no consent checks performed during registration or service startup.

    2. **Service Start (`screen_recorder.py` - `ScreenRecorder.start()`):**
       - The `start()` method in `screen_recorder.py` initiates the screen recording process:
         ```python
         def start(self) -> None:
             if self._is_alive:
                 return
             self._is_alive = True
             # ... setup and start streaming loop ...
             if not self._prepared:
                 self._setup()
             # ... executor submission ...
         ```
       -  The `start()` function is called programmatically within the test script. There is no user interaction or consent verification within this function or any function it calls.

    3. **Screen Recording Loop (`screen_recorder.py` - `ScreenRecorder._stream_loop()`):**
       - The `_stream_loop()` function continuously receives frames from the `scrcpy` server and saves them.
       - This loop runs in the background as long as the service is alive (`self._is_alive = True`), which is controlled by the `start()` and `stop()` methods called from the test script.
       - No consent checks are performed within the frame processing or recording loop.

    4. **No Consent Enforcement:**
       - Reviewing the entire `screen_recorder.py` code, there is no code related to:
         - Prompting for user consent.
         - Displaying notifications on the Android device about recording.
         - Implementing any form of consent verification.
       - The service is designed to be programmatically controlled and activated without any user-facing consent mechanism.

    **Visualization:**

    ```mermaid
    sequenceDiagram
        participant Malicious Actor
        participant User (Developer/Tester)
        participant Mobly Test Script (Modified)
        participant Android Device
        participant ScreenRecorder Service

        Malicious Actor->>User: Social Engineering (Share Modified Test Script)
        User->>Mobly Test Script (Modified): Executes Test Script
        Mobly Test Script (Modified)->>Android Device: Registers ScreenRecorder Service
        Mobly Test Script (Modified)->>ScreenRecorder Service: Start Recording (No Consent Check)
        ScreenRecorder Service->>Android Device: Starts scrcpy server (Background, No UI indication by this service)
        Android Device-->>ScreenRecorder Service: Streams Screen Frames (Secretly)
        ScreenRecorder Service->>Mobly Test Script (Modified): Saves Video to Output Directory
        Mobly Test Script (Modified) -->> User: Test Execution Completes (User Unaware of Recording)
        Malicious Actor<<--User: (Gains Access to Recorded Video from Output Directory)
    ```

- **Security Test Case:**

    1. **Setup:**
        - Install `mobly-android-screen-recorder` in a test environment.
        - Have an Android device connected and configured for Mobly testing.
        - Create a Mobly test configuration file (e.g., `test_config.yaml`).
        - Create a Python Mobly test script (e.g., `unauthorised_record_test.py`) with the following content:

        ```python
        from mobly import base_test
        from mobly import test_runner
        from mobly.controllers import android_device
        from mobly.controllers.android_device_lib.services import screen_recorder
        import time
        import os

        class UnauthorisedRecordTest(base_test.BaseTestClass):

          def setup_class(self):
            self.ads = self.register_controller(android_device)
            self.dut = self.ads[0]
            self.dut.load_snippet('mbs', android_device.MBS_PACKAGE)
            self.dut.services.register('screen_recorder', screen_recorder.ScreenRecorder)

          def test_unauthorised_recording(self):
            self.dut.mbs.makeToast('Running test, screen is being recorded!')
            time.sleep(5) # Simulate test activity, allowing screen to be recorded

          def teardown_test(self):
            self.dut.services.create_output_excerpts_all(self.current_test_info)

        if __name__ == '__main__':
          test_runner.main()
        ```

    2. **Execution:**
        - As a simulated malicious actor, prepare the `unauthorised_record_test.py` and `test_config.yaml` files.
        - Socially engineer a test user to execute this test script using Mobly:
          ```bash
          python unauthorised_record_test.py -c test_config.yaml
          ```
        - Observe the test execution on the Android device. **Note:** There will be no visual indication from the `mobly-android-screen-recorder` itself that screen recording is happening, only the toast message from the test script.

    3. **Verification:**
        - After the test execution, navigate to the test output directory (usually within the Mobly log path).
        - Locate the video file (e.g., `video_device_serial_device_model_timestamp.mp4`).
        - Open and review the video recording.
        - **Expected Result:** The video recording should contain the screen activity of the Android device during the test execution, including the "Running test, screen is being recorded!" toast message and any other activities performed on the device during the 5-second sleep period. This confirms that screen recording was successfully initiated and captured without any explicit consent prompt or user notification from the `mobly-android-screen-recorder` service itself, demonstrating the vulnerability.

This vulnerability highlights the importance of not only documenting responsible use but also implementing technical controls to mitigate the risk of misuse, especially for tools with privacy-sensitive capabilities like screen recording.
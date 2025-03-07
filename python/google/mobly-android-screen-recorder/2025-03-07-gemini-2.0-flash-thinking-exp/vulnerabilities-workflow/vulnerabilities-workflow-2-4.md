- Vulnerability Name: Unauthorized Screen Recording
- Description:
    - A malicious actor can create a Mobly test script that includes the `mobly-android-screen-recorder` service.
    - The attacker then tricks a user into running this Mobly test on their Android device. This could be achieved by disguising the malicious test as a legitimate one or embedding it within a larger, seemingly harmless test suite.
    - When the user executes the malicious test, the `mobly-android-screen-recorder` service is automatically registered and started without any explicit consent or notification to the device user.
    - The screen recording starts when the test begins and continues until the test finishes or is stopped.
    - The recorded video file is saved in the test output directory, accessible to whoever ran the test script.
    - This allows the attacker to silently record the device's screen and capture potentially sensitive information displayed during the recording.
- Impact:
    - Privacy violation: Sensitive information displayed on the device screen can be recorded without the user's knowledge or consent.
    - Data theft: Recorded video may contain personal data, login credentials, financial information, private communications, and other confidential information.
    - Reputational damage: If the misuse of this tool becomes public, it could damage the reputation of the project and its developers.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - README.md warnings: The `README.md` file includes a "Responsible Use" section and a "Disclaimer" that strongly emphasize the need for explicit consent and warn against misuse for unauthorized surveillance. It highlights the ethical and legal implications of unauthorized screen recording.
- Missing Mitigations:
    - Lack of explicit consent mechanism within the library: The library itself does not enforce any consent mechanism. It relies entirely on the developers using the library to ensure consent is obtained externally. There is no built-in function to request, verify, or record user consent before initiating screen recording.
    - Absence of user notification: The library does not provide any visual or auditory cues on the Android device to indicate that screen recording is in progress. Users are not informed when their screen is being recorded, making silent, unauthorized recording possible.
    - No permission check or request: The library does not explicitly check for or request Android permissions related to screen capture at runtime. While Mobly test execution might require certain permissions, the screen recorder service itself doesn't manage or verify permissions specifically for screen recording.
- Preconditions:
    - The attacker has created a malicious Mobly test script that registers the `screen_recorder` service.
    - The victim has installed the `mobly-android-screen-recorder` library.
    - The victim is tricked into running the attacker's Mobly test script on their Android device.
    - The victim's Android device is connected to a computer via ADB and authorized for ADB access.
- Source Code Analysis:
    - File: `/code/mobly/controllers/android_device_lib/services/screen_recorder.py`
    - The `ScreenRecorder` class is implemented in this file.
    - The `start()` method initializes and starts the screen recording process by pushing the `scrcpy-server.apk`, forwarding ports, starting the server on the device, and establishing a socket connection.
    - The `stop()` method stops the recording and cleans up resources.
    - The service is registered in a Mobly test script using the following pattern as shown in `README.md`:
      ```python
      self.dut.services.register('screen_recorder', screen_recorder.ScreenRecorder)
      ```
    - **Absence of Consent Mechanism**:  A review of the `screen_recorder.py` code reveals no implementation of any consent mechanism. There are no functions to:
        - Display a consent dialog to the user on the Android device.
        - Check for pre-existing user consent.
        - Log or record user consent.
    - **Automatic Start on Service Registration**: The service starts recording automatically when the `start()` method is called, which is triggered as part of the Mobly test lifecycle if the service is registered. There is no step requiring explicit user interaction or authorization before recording begins.
    - **No User Notification**: The code does not include any functionality to display a notification, icon, or sound on the Android device to indicate that screen recording is active. The recording process is designed to be transparent to the device user.
- Security Test Case:
    1. Attacker creates a malicious Mobly test script (`malicious_test.py`) that registers the `screen_recorder` service:
       ```python
       from mobly import base_test
       from mobly import test_runner
       from mobly.controllers import android_device
       from mobly.controllers.android_device_lib.services import screen_recorder

       class MaliciousTest(base_test.BaseTestClass):
           def setup_class(self):
               self.ads = self.register_controller(android_device)
               self.dut = self.ads[0]
               self.dut.services.register('screen_recorder', screen_recorder.ScreenRecorder)

           def test_dummy(self):
               print("Running dummy test...")

           def teardown_test(self):
               self.dut.services.create_output_excerpts_all(self.current_test_info)

       if __name__ == '__main__':
           test_runner.main()
       ```
    2. Attacker creates a configuration file (`test_config.yml`):
       ```yaml
       TestBeds:
         - Name: MaliciousTestBed
           Controllers:
               AndroidDevice: '*'
       ```
    3. Attacker tricks the victim into downloading and running `malicious_test.py` with `test_config.yml`.
    4. Victim executes the test: `python malicious_test.py -c test_config.yml`
    5. Observe that the test executes without any consent prompt or screen recording notification on the Android device.
    6. After the test completes, check the test output directory. A video file (e.g., `video_...,.mp4`) will be present, containing the screen recording of the victim's Android device during the test execution.
    7. The victim is unaware that their screen was recorded, demonstrating unauthorized screen recording.
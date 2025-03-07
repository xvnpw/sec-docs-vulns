### Vulnerability 1: Silent Screen Recording via Configuration Manipulation

* Description:
    An attacker can modify the Mobly test configuration or test script to silently enable screen recording on an Android device without the user's explicit consent. This is achieved by adding the screen recorder service registration to the test setup. When the user executes the test with the modified configuration, screen recording will be activated without any visible indication on the device, allowing for unauthorized surveillance.

    Steps to trigger the vulnerability:
    1. An attacker gains access to the Mobly test configuration files (e.g., `sample_config.yml`) or test scripts (e.g., `hello_world_test.py`).
    2. The attacker modifies the test script to include the screen recorder service registration within the `setup_class` method:
       ```python
       self.dut.services.register('screen_recorder', screen_recorder.ScreenRecorder)
       ```
    3. The attacker tricks a user into executing the modified test script, for example by sharing the modified configuration and script and instructing the user to run the test.
    4. The user, unaware of the added screen recording, executes the test.
    5. The `ScreenRecorder` service starts automatically when the test begins, recording the device screen in the background without any explicit consent or visible indication on the device.
    6. The recorded video file is saved in the test output directory.

* Impact:
    Privacy breach, unauthorized surveillance, potential exposure of sensitive information displayed on the Android device screen. This can lead to unauthorized access to personal or confidential data, violating user privacy and potentially leading to legal and ethical repercussions.

* Vulnerability Rank: High

* Currently Implemented Mitigations:
    - Disclaimer and Responsible Use guidelines in `README.md`. This documentation warns against misuse and emphasizes the need for explicit consent, but it is not a technical mitigation and relies on user awareness and adherence.

* Missing Mitigations:
    - **Visual indication on the Android device**: Implement a visible indicator on the Android device screen when screen recording is active. This could be an icon in the status bar, a persistent notification, or a toast message displayed at the start and end of recording. This would immediately alert the user that screen recording is in progress.
    - **Access control or permission mechanism**: Introduce a mechanism to control who can enable screen recording. This could involve a configuration setting that requires explicit user confirmation or a separate permission to activate the screen recorder service.
    - **Logging or auditing of screen recording activities**: Implement logging of screen recording start and stop events, including timestamps and the user or process that initiated the recording. This would provide an audit trail for screen recording activities.
    - **Clear warning message in test execution logs**: Display a prominent warning message in the Mobly test execution logs when the screen recorder service is activated. This would inform users reviewing the test logs that screen recording was enabled during the test run.

* Preconditions:
    - Attacker has the ability to modify the Mobly test configuration files or test scripts before they are executed. This could be achieved through insider access, compromised systems, or social engineering.
    - User executes the modified test configuration or script.
    - Mobly testing environment is set up and functional.
    - Target Android device is connected and configured for Mobly testing.

* Source Code Analysis:
    - File: `/code/mobly/controllers/android_device_lib/services/screen_recorder.py`
    - The `ScreenRecorder` class is implemented as a Mobly service.
    - The `start()` method initializes and starts the screen recording process when the service is registered and invoked by Mobly during test execution.
    - The `stop()` method terminates the recording.
    - The registration of the service is controlled entirely within the test script (e.g., in `setup_class` of a `BaseTestClass` as shown in `README.md`):
      ```python
      self.dut.services.register('screen_recorder', screen_recorder.ScreenRecorder)
      ```
    - There are no built-in checks within the `ScreenRecorder` service or the Mobly framework to verify user consent or provide device-side indication when recording is enabled.
    - The service is designed to be activated programmatically based on the test script configuration, making it susceptible to silent activation if the configuration is manipulated.
    - The output video file is generated and saved without any explicit user interaction or confirmation during the test execution.

* Security Test Case:
    1. **Setup:** Configure a Mobly testing environment with a connected Android device. Ensure the `mobly-android-screen-recorder` library is installed.
    2. **Baseline Test Script (No Recording):** Create a Mobly test script (e.g., `no_record_test.py`) based on the `hello_world_test.py` example from `README.md`, but **omit** the line that registers the `screen_recorder` service in the `setup_class` method.
       ```python
       from mobly import base_test
       from mobly import test_runner
       from mobly.controllers import android_device

       class NoRecordTest(base_test.BaseTestClass):
         def setup_class(self):
           self.ads = self.register_controller(android_device)
           self.dut = self.ads[0]
           self.dut.load_snippet('mbs', android_device.MBS_PACKAGE)

         def test_no_record(self):
           self.dut.mbs.makeToast('Hello World - No Record Test!')

         def teardown_test(self):
           self.dut.services.create_output_excerpts_all(self.current_test_info)

       if __name__ == '__main__':
         test_runner.main()
       ```
    3. **Run Baseline Test:** Execute the `no_record_test.py` with a sample configuration (e.g., `sample_config.yml`).
       ```bash
       python no_record_test.py -c sample_config.yml
       ```
    4. **Verify No Recording:** Check the test output directory. Confirm that **no video file** (e.g., `video_...mp4`) has been generated. Also, observe the Android device screen during the test; there should be **no indication of screen recording**.
    5. **Modified Test Script (With Recording):** Modify the test script to `record_test.py` by **adding** the screen recorder service registration in the `setup_class` method:
       ```python
       from mobly import base_test
       from mobly import test_runner
       from mobly.controllers import android_device
       from mobly.controllers.android_device_lib.services import screen_recorder

       class RecordTest(base_test.BaseTestClass):
         def setup_class(self):
           self.ads = self.register_controller(android_device)
           self.dut = self.ads[0]
           self.dut.load_snippet('mbs', android_device.MBS_PACKAGE)
           self.dut.services.register('screen_recorder', screen_recorder.ScreenRecorder) # Added line

         def test_record(self):
           self.dut.mbs.makeToast('Hello World - Record Test!')

         def teardown_test(self):
           self.dut.services.create_output_excerpts_all(self.current_test_info)

       if __name__ == '__main__':
         test_runner.main()
       ```
    6. **Run Modified Test:** Execute the `record_test.py` with the same sample configuration, without informing the user about the screen recording.
       ```bash
       python record_test.py -c sample_config.yml
       ```
    7. **Verify Recording Enabled Silently:** Check the test output directory. Confirm that a **video file** (e.g., `video_...mp4`) has been generated. This proves that screen recording was enabled.
    8. **Observe Device for Indication:** Observe the Android device screen during the execution of `record_test.py`. Verify that there is **no visible indication on the device** (no icon, no notification, no toast) that screen recording was active.

    **Expected Result:** The test case demonstrates that by modifying the test script to include the service registration, screen recording is silently activated and a video file is generated, without any explicit user consent or device-side indication. This confirms the vulnerability of silent screen recording via configuration manipulation.
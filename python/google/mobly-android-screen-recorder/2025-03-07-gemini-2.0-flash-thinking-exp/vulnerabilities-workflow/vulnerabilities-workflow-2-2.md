*   **Vulnerability Name:** Unauthorized Screen Recording via Test Configuration Modification

*   **Description:**
    1. A local attacker gains access to the system where Mobly tests are executed.
    2. The attacker modifies a Mobly test script (e.g., `hello_world_test.py`) or a test configuration file (e.g., `sample_config.yml`).
    3. The attacker adds code to the test script to register the `screen_recorder` service for the Android device under test. This can be done by adding the following lines to the `setup_class` method or similar setup section of the test script:
       ```python
       from mobly.controllers.android_device_lib.services.android_screen_recorder import screen_recorder
       self.dut.services.register('screen_recorder', screen_recorder.ScreenRecorder)
       ```
    4. The attacker runs the modified Mobly test.
    5. The `screen_recorder` service starts automatically when the test begins, recording the Android device's screen.
    6. The screen recording is saved as a video file in the test output directory on the local system.
    7. The attacker can then access the test output directory and exfiltrate the recorded video file, potentially containing sensitive information displayed on the Android device during the test.

*   **Impact:**
    *   **Confidentiality Breach:** Sensitive information displayed on the Android device screen during automated tests can be recorded without the knowledge or consent of device users or data owners. This information could include personal data, application secrets, financial details, or other confidential content depending on the nature of the tests being executed.
    *   **Privacy Violation:** Unauthorized recording of user screen activity is a severe privacy violation and can have legal and ethical implications.
    *   **Data Exfiltration:** Recorded video files can be easily exfiltrated by the attacker, leading to unauthorized access and potential misuse of sensitive data.

*   **Vulnerability Rank:** High

*   **Currently Implemented Mitigations:**
    *   **Documentation Warnings:** The `README.md` file includes "Responsible Use" guidelines and a "Privacy Warning" emphasizing the need for explicit consent and responsible use of the tool. It also states that misuse for unauthorized surveillance is strictly prohibited. However, these are only advisory and do not technically prevent the vulnerability.
        *   File: `/code/README.md`
        *   Section: "Responsible Use" and "Disclaimer"

*   **Missing Mitigations:**
    *   **Access Control for Service Registration:** Implement a mechanism to control or restrict the registration of the `screen_recorder` service. This could involve:
        *   **Configuration-based enabling:**  Introduce a configuration setting (e.g., in the Mobly test configuration file) that explicitly enables or disables the screen recording service. This would prevent arbitrary enabling through test script modification alone if the configuration file itself is protected.
        *   **Permission-based registration:** Implement a permission check before allowing service registration. This could be integrated with a user authentication or authorization system within the Mobly environment (if available).
    *   **Auditing and Logging:** Implement logging of screen recording service start and stop events, including the user or process that initiated the recording. This would provide an audit trail and help detect unauthorized usage.
    *   **Secure Storage of Recordings:** Ensure that test output directories, where recordings are stored, have appropriate access controls to prevent unauthorized access and exfiltration. This is a general system security measure but is crucial to mitigate the impact of this vulnerability.

*   **Preconditions:**
    1.  Local system access: The attacker must have local access to the system where Mobly tests are being executed. This could be a developer workstation, a test server, or any machine running Mobly test infrastructure.
    2.  Modifiable test configurations or scripts: The attacker must be able to modify Mobly test scripts (Python files) or test configuration files (YAML files) used to run the tests. This could be achieved through compromised accounts, insider access, or vulnerabilities in the system's access control mechanisms.
    3.  Mobly test environment setup: Mobly test environment must be set up and functional, including Android devices connected and configured for testing.

*   **Source Code Analysis:**
    1.  **Service Registration:** The vulnerability is rooted in the design of the `mobly-android-screen-recorder` service, where registration is performed directly within the Python test script using the `self.dut.services.register()` method.
        *   File: `/code/mobly/controllers/android_device_lib/services/screen_recorder.py` and example usage in `/code/README.md` (`hello_world_test.py`).
        *   Code snippet from `hello_world_test.py` (example):
            ```python
            self.dut.services.register('screen_recorder', screen_recorder.ScreenRecorder)
            ```
        *   This registration mechanism lacks any built-in access control or authorization. Any user who can modify the test script can add this line and enable screen recording.
    2.  **Default Output Path:** The recorded video files are saved in the default test output directory, which is typically accessible to users with local system access.
        *   File: `/code/mobly/controllers/android_device_lib/services/screen_recorder.py`
        *   Lines 164-165: `self.output_dir = configs.output_dir or device.log_path`
        *   Lines 604-611: `self._set_writer()` and `cv2.VideoWriter(os.path.join(self.output_dir, filename), ...)`
        *   This default behavior, combined with the lack of access control on service registration, makes it easy for an attacker to record and retrieve screen captures.
    3.  **No Consent Enforcement:** The code does not implement any mechanism to ensure or verify user consent before starting screen recording. It solely relies on the "Responsible Use" guidelines in the documentation.

*   **Security Test Case:**
    1.  **Pre-requisites:**
        *   Set up a Mobly test environment with an Android device connected and configured.
        *   Install `mobly-android-screen-recorder` library.
        *   Have a basic Mobly test script (like `hello_world_test.py` from the README) and configuration file (like `sample_config.yml`).
    2.  **Attacker Action:**
        *   As a local attacker, gain access to the system where the Mobly tests are stored.
        *   Modify the `setup_class` method in `hello_world_test.py` to register the `screen_recorder` service:
            ```python
            from mobly.controllers.android_device_lib.services.android_screen_recorder import screen_recorder

            def setup_class(self):
                self.ads = self.register_controller(android_device)
                self.dut = self.ads[0]
                self.dut.load_snippet('mbs', android_device.MBS_PACKAGE)
                self.dut.services.register('screen_recorder', screen_recorder.ScreenRecorder) # ADD THIS LINE
            ```
        *   Save the modified `hello_world_test.py` file.
    3.  **Run the Test:**
        *   Execute the modified test using the command: `python hello_world_test.py -c sample_config.yml`
    4.  **Verify Screen Recording:**
        *   After the test execution completes, navigate to the test output directory (typically under `test_output` in the project root).
        *   Locate the video file named `video,{device_serial},{device_model},{timestamp}.mp4`.
        *   Open the video file and verify that it contains a screen recording of the Android device during the test execution (in this example, it should show the "Hello World!" toast notification).
    5.  **Exfiltration (Optional):**
        *   As the attacker, copy the video file to a location under your control, simulating data exfiltration.

    **Expected Result:** The test case should successfully demonstrate that by modifying the test script, an attacker can enable screen recording without any explicit authorization or consent, and retrieve the recorded video file from the test output directory. This confirms the vulnerability.
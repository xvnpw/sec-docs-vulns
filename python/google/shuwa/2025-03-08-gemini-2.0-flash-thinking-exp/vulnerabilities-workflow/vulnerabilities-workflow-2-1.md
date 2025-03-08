- Vulnerability Name: Potential Stored Cross-Site Scripting (XSS) via Unsanitized Gloss Name in Web Output
- Description:
  1. An attacker uses the "Record" mode in the application's GUI.
  2. When prompted for "Sign name" in the `name_box`, the attacker enters a malicious payload as the sign name, for example: `<img src=x onerror=alert('XSS_in_gloss_name')>`.
  3. The attacker clicks "Record", performs a gesture, clicks "Stop", and then clicks "Save". This action saves a KNN database file. Critically, the filename of this database is derived from the unsanitized "Sign name" entered by the attacker, resulting in a file named (in this example) `<img src=x onerror=alert('XSS_in_gloss_name')>.txt` within the `knn_dir`. The malicious sign name also becomes a `knn_label` within the application's internal data structures.
  4. Later, when a user switches to "Play mode" and performs gesture recognition using the webcam, the system attempts to classify the gesture. If the gesture is classified as the sign associated with the malicious name (or even if any classification occurs and the label is displayed), the application will retrieve and use the stored malicious `knn_label`.
  5. The application then displays the classification result in the `console_box` of the GUI using the following code in `webcam_demo.py`: `self.console_box.insert('end', f"Nearest class: {res_txt}\n")`, where `res_txt` is the malicious gloss name (e.g., `<img src=x onerror=alert('XSS_in_gloss_name')>`).
  6. If the content of this `console_box`, specifically the `res_txt` value, is naively displayed on a webpage without proper sanitization (for instance, using `innerHTML` in a hypothetical web demo scenario), the HTML and JavaScript payload within the `res_txt` (e.g., `<img src=x onerror=alert('XSS_in_gloss_name')>`) will be executed in the user's browser. This execution of attacker-controlled scripts in the context of the user's web session constitutes a Cross-Site Scripting (XSS) vulnerability.
- Impact:
  Cross-Site Scripting (XSS). Successful exploitation of this vulnerability allows an attacker to inject and execute arbitrary JavaScript code in the context of a user's session if the application's console output is displayed on a webpage without sanitization. This can lead to various malicious activities, including:
    - Stealing sensitive user information, such as cookies and session tokens, which can be used to impersonate the user.
    - Redirecting users to attacker-controlled malicious websites, potentially for phishing or malware distribution.
    - Defacing the intended web page content, disrupting the user experience.
    - Performing unauthorized actions on behalf of the user, depending on the application's functionalities and the user's permissions.
- Vulnerability Rank: Medium
  This is ranked as a medium severity vulnerability because it is a Stored XSS, which can have significant impact. However, the exploitability in a typical web context is conditional. It depends on whether and how the Tkinter GUI's `console_box` output is exposed in a web environment. If the `console_box` is strictly confined to the desktop application and not used in any web-based interface, the risk to web users is mitigated. However, given the project description includes a "Web Demo", the potential for web exposure and thus the XSS risk is present and should be addressed.
- Currently Implemented Mitigations:
  None. Based on the provided source code, there are no explicit input sanitization or output encoding mechanisms implemented to prevent XSS. The application directly uses the user-provided sign name to create filenames and displays potentially user-influenced text in the console without any form of security processing.
- Missing Mitigations:
  - Input Sanitization: Implement robust input sanitization for the "Sign name" field in the "Record" mode. This should involve encoding or removing HTML special characters and JavaScript-related syntax before the sign name is used to create filenames or stored as labels.  A recommended approach is to allow only alphanumeric characters and spaces for sign names, or to HTML-encode any special characters if they are necessary for display but not for code execution.
  - Output Encoding: If the `console_box` content, especially the `res_txt` (classification result), is intended to be displayed in a web context, it is crucial to implement output encoding. This would involve HTML-encoding the `res_txt` before rendering it on the webpage. This ensures that any HTML tags or JavaScript code within `res_txt` are treated as plain text and not executed by the browser. Server-side or client-side templating engines with auto-escaping features can be used to achieve this.
- Preconditions:
  1. Access to the Shuwa Gesture Toolkit application GUI, specifically the "Record" mode and "Save" functionality. This is typically available to any user running the desktop application.
  2. A hypothetical scenario where the application's `console_box` output (or the classification results derived from the KNN database filenames) is displayed on a webpage without proper output sanitization. This precondition assumes a specific (and potentially insecure) implementation of a "web demo" component that is not explicitly detailed in the provided project files but is implied by the project description and README.
- Source Code Analysis:
  - File: `/code/webcam_demo.py`
    - `save_btn_cb` function:
      ```python
      gloss_name = self.name_box.get()
      ...
      self.translator_manager.save_knn_database(gloss_name, self.knn_records)
      ```
      This code snippet retrieves the sign name directly from the `name_box` using `self.name_box.get()` without any sanitization. This `gloss_name` is then passed to `self.translator_manager.save_knn_database`. Looking into `translator_manager.py`:
      ```python
      def save_knn_database(self, gloss_name, knn_records):
          output_path = Path(self.knn_dir, gloss_name + ".txt")
          ...
      ```
      The `gloss_name` is directly used to construct the `output_path` for saving the KNN database file. This means a malicious `gloss_name` will result in a malicious filename.
    - `record_btn_cb` function (in play mode):
      ```python
      res_txt = self.translator_manager.run_knn(feats)
      self.console_box.insert('end', f"Nearest class: {res_txt}\n")
      ```
      The classification result `res_txt`, which is derived from the `knn_labels` (and thus indirectly from the filenames which are based on user-provided `gloss_name`), is inserted into the `console_box` without any sanitization.
  - Visualization:
    [Conceptual Data Flow for XSS]
    ```
    User Input (Sign Name in GUI) --> [webcam_demo.py - name_box.get()] --> gloss_name --> [translator_manager.py - save_knn_database] --> Filename (unsanitized) --> KNN Database Files --> knn_labels (loaded into memory) --> [translator_manager.py - run_knn] --> res_txt (potentially malicious) --> [webcam_demo.py - console_box.insert] --> GUI Console Output --> [Hypothetical Web Demo] --> Webpage Display (unsanitized) --> XSS
    ```
- Security Test Case:
  1. **Environment Setup:** Set up the Shuwa Gesture Toolkit application on a test machine, ensuring you have write access to the `knn_dir` where KNN databases are saved.
  2. **Record Malicious Sign:**
     - Launch the `webcam_demo.py` application.
     - Switch to the "Record" tab in the GUI.
     - In the "Sign name" text box, enter the following XSS payload: `<img src=x onerror=alert('XSS_Test')>`.
     - Click the "Record" button, perform any hand gesture in front of the webcam for a few seconds, and then click "Stop".
     - Click the "Save" button. This saves a KNN database file named `<img src=x onerror=alert('XSS_Test')>.txt` in the `knn_dataset` directory (or configured `knn_dir`).
  3. **Trigger Play Mode and Observe (Hypothetical Web Scenario):**
     - Switch to the "Play mode" tab.
     - Perform a gesture in front of the webcam. It's not crucial that the gesture is correctly classified; the goal is to trigger the display of a classification result.
     - **Simulate Web Display:** Since the provided code is not a web application, you would need to simulate the scenario where the `console_box` output is displayed on a webpage.  For a basic test, you can manually extract the text content from the `console_box` after performing the gesture in "Play mode."  If you were to then take this text and naively insert it into an HTML page using `innerHTML` in a browser, you would expect the XSS payload to execute.  Alternatively, if you have a simplified web server that can read the classification result from the application (e.g., by reading the last line written to a log file or through some inter-process communication) and display it, you can test the XSS in a more realistic, albeit still simplified, web context.
  4. **Expected Outcome:** If the `console_box` output, containing the malicious sign name, is displayed on a webpage using `innerHTML` or similar unsanitized methods, an alert box with the message "XSS_Test" should appear in the browser. This confirms the Stored XSS vulnerability, demonstrating that malicious JavaScript code injected through the sign name can be executed when the classification result is displayed in a web context. If testing only within the Tkinter GUI, you will likely just see the raw text `<img src=x onerror=alert('XSS_Test')>` displayed in the console box, but the vulnerability is present if this output were to be used in a web context unsafely.
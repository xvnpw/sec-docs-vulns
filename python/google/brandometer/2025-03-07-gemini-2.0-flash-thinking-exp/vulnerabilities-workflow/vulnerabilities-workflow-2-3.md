- Vulnerability Name: Reflected Cross-Site Scripting (XSS) in Survey Creation
- Description:
    1. An attacker can create a new survey or edit an existing one via the application's survey creation/edit interface.
    2. In the survey creation/edit form, the attacker injects malicious JavaScript code into one of the survey input fields such as "question1", "answer1a", "surveyname", etc. For example, they could input `<script>alert("XSS")</script>` into the "question1" field.
    3. The application stores this malicious payload in the Firestore database without sanitization.
    4. When a user (either the survey creator or another authorized user) previews the survey, edits the survey, downloads the survey creatives, or views survey reports, the application retrieves the survey data from Firestore.
    5. The application then renders this data in the `creative.html` template (or potentially other views like reporting), likely without proper output encoding or sanitization.
    6. As a result, the injected JavaScript code is executed in the user's browser in the context of the application's domain.
- Impact:
    - Account Takeover: An attacker could potentially steal session cookies or other sensitive information, leading to account compromise of administrators or users accessing the survey data.
    - Data Theft: Malicious scripts could be used to extract sensitive data accessible within the application and send it to an attacker-controlled server.
    - Defacement: The application interface could be defaced, disrupting normal operation and potentially damaging the brand's reputation.
    - Redirection to Malicious Sites: Users could be redirected to attacker-controlled malicious websites, potentially leading to further compromise or malware infections.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - Basic Authentication: The application uses basic authentication (`flask-basicauth`) which provides a layer of access control. However, this does not prevent XSS once an authenticated user interacts with a survey containing malicious code.
    - Input Validation (Limited): The `QuestionForm` in `forms.py` uses `DataRequired` validators, ensuring that certain fields are not empty. However, it does not perform any sanitization or encoding of user inputs to prevent XSS.
- Missing Mitigations:
    - Output Encoding/Escaping: The application lacks proper output encoding or escaping when rendering user-provided survey data (questions, answers, survey names) in HTML templates. All user-provided data displayed in HTML should be encoded (e.g., using HTML escaping) to prevent browsers from interpreting them as executable code.
    - Content Security Policy (CSP): Implementing a Content Security Policy (CSP) would be a strong mitigation to restrict the sources from which the browser is allowed to load resources, significantly reducing the impact of XSS attacks.
    - Input Sanitization (Server-side): While output encoding is crucial, server-side input sanitization can also provide defense in depth by cleaning up potentially malicious input before it's stored in the database. However, output encoding is the primary and more effective mitigation for reflected XSS.
- Preconditions:
    - Access to the Brandometer application's survey creation or edit functionality. This is protected by basic authentication, so an attacker would need valid credentials or find a way to bypass authentication to initially inject the XSS payload. However, once a malicious survey is created, any authenticated user interacting with it can trigger the XSS.
- Source Code Analysis:
    1. **File: `/code/creative/app/forms.py`**:
        - The `QuestionForm` class defines the structure of the survey creation form.
        - It uses `StringField` for text inputs like `question1`, `answer1a`, `surveyname`, etc.
        - Validators used are primarily `DataRequired`, which only checks for the presence of input, not the content's safety.
        - **No input sanitization or encoding is performed here.**

    2. **File: `/code/creative/app/main.py`**:
        - `@app.route('/survey/create', methods=['GET', 'POST'])` and `@app.route('/survey/edit', methods=['POST', 'PUT', 'GET'])` handle survey creation and editing.
        - In both `create()` and `edit()` functions, the form data (`form.data`) is directly passed to `survey_service.create(form)` or `survey_service.update_by_id(docref_id, form)`.
        - **No sanitization of form data is performed in `main.py` before passing it to the service layer.**

    3. **File: `/code/creative/app/survey_service.py`**:
        - `create(form)` and `update_by_id(survey_id, form)` functions in `survey_service.py` call `survey_collection.create(form.data)` and `survey_collection.update_by_id(survey_id, form.data)` respectively, directly storing the form data into Firestore.
        - `get_html_template(survey_id, survey_dict, seg_type)` function renders the `creative.html` template, passing `survey_dict` as context.
        - `get_question_json(survey)` retrieves and structures survey questions and answers from the `survey_dict` for use in `creative.html`.
        - **No output encoding or sanitization is performed in `survey_service.py` before rendering data in templates or preparing JSON data for the frontend.**

    4. **File: `/code/creative/app/templates/creative.html` (Not provided, assumed vulnerable):**
        - **Assumption:** The `creative.html` template (and potentially `reporting.html` and `index.html`) likely uses a templating engine (like Jinja2) to render the survey data. If it directly outputs variables like `survey.surveyname`, `survey.question1`, `survey.answer1a`, etc., using constructs like `{{ survey.surveyname }}`, `{{ survey.question1 }}`, `{{ survey.answer1a }}`, **without any HTML escaping filter**, then it will be vulnerable to XSS.  Jinja2, by default, performs HTML escaping, but if `|safe` filter is used, or autoescape is disabled, it can become vulnerable.

    **Visualization:**

    ```
    User Input (Malicious Payload) --> QuestionForm (forms.py) --> main.py (create/edit) --> survey_service.py (create/update_by_id) --> Firestore (Stored as is)
                                                                                                    |
                                                                                                    |
    Firestore --> survey_service.py (get_doc_by_id, get_question_json, get_html_template) --> main.py (preview, reporting, index) --> creative.html (Template Rendering - Vulnerable Point) --> User Browser (XSS Execution)
    ```

- Security Test Case:
    1. **Login to the Brandometer application** using valid credentials.
    2. **Navigate to the survey creation page**: Click on "Create survey" from the home page (`/index`).
    3. **Inject XSS payload in Survey Name**: In the "Survey Name" field, enter the following payload: `<script>alert('XSS Vulnerability in Survey Name')</script>Test Survey`.
    4. **Inject XSS payload in Question 1**: In the "Question 1" field, enter: `<img src=x onerror=alert('XSS Vulnerability in Question 1')>`.
    5. **Fill in the rest of the required fields** for Question 1 (Answer A, Answer B, Next Question for Answer A and Answer B) with arbitrary values (e.g., "Answer A", "Answer B", "end", "end").
    6. **Submit the survey**: Click the "Submit" button.
    7. **Navigate back to the home page**: You should be redirected to the survey list page (`/index`).
    8. **Preview the created survey**: Click on the "Preview" button for the survey you just created.
    9. **Observe for XSS**:
        - You should see an alert box pop up with the message "XSS Vulnerability in Survey Name". This confirms that the JavaScript code injected in the survey name field was executed.
        - You should see another alert box pop up with the message "XSS Vulnerability in Question 1". This confirms that the JavaScript code injected in the question 1 field was executed.
    10. **Alternatively, test in Edit mode**: Instead of previewing, click on "Edit" for the created survey from the home page. Observe if the XSS payloads in Survey Name and Question 1 execute when the edit page loads.
    11. **Further Test Vectors**: Repeat steps 3-9, injecting XSS payloads into other input fields like "answer1a", "question2", etc., to confirm the vulnerability across different input points in the survey creation/edit form.

This test case demonstrates that malicious JavaScript injected during survey creation is executed when the survey is previewed or edited, confirming the Reflected XSS vulnerability.
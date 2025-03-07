### Vulnerability List

- Vulnerability Name: Unintended Parameter Submission in Form Handling
- Description:
    - The `_get_and_submit_form` function in `api.py` is designed to interact with HTML forms returned by non-public GitHub API endpoints.
    - This function automatically extracts all input fields with a 'name' attribute from the HTML form.
    - These extracted input fields are then included as parameters in a POST request to submit the form.
    - If a non-public GitHub API endpoint were to introduce unexpected input fields in its forms (e.g., for internal tracking, debugging, or even malicious purposes), this library would automatically extract and submit these parameters.
    - This could lead to unintended consequences if these unexpected parameters trigger different or harmful behavior on the server-side, potentially resulting in data manipulation, unintended actions, or security breaches.
    - An attacker could potentially exploit this by manipulating the non-public API responses (if they could control them, which is unlikely for external attackers but possible for insider threats or if GitHub's internal APIs are compromised) to include malicious parameters, which would then be submitted by applications using this library.
- Impact:
    - Medium. If GitHub's non-public APIs start using unexpected parameters in forms, applications using this library might inadvertently send these parameters.
    - This could potentially lead to unintended actions or data manipulation on GitHub, depending on how GitHub's non-public APIs process these unexpected parameters.
    - The severity is dependent on the specific unintended actions that could be triggered by these extra parameters on the server-side.
- Vulnerability Rank: Medium
- Currently implemented mitigations:
    - None. The code currently extracts and submits all named input fields without any filtering or validation.
- Missing mitigations:
    - The library should implement a mechanism to explicitly define and whitelist the expected form fields for each API interaction.
    - Only the whitelisted form fields should be extracted and submitted.
    - Any form fields received from the API response that are not on the whitelist should be ignored or logged as a warning.
    - This would ensure that the library only submits parameters that it is explicitly designed to handle, preventing unintended parameter submission.
- Preconditions:
    - The application using this library interacts with a non-public GitHub API endpoint that starts returning HTML forms with unexpected input fields.
    - These unexpected parameters, when submitted back to the GitHub API, cause unintended behavior or security issues.
- Source code analysis:
    - In `/code/github_nonpublic_api/api.py`, the function `_get_and_submit_form` is responsible for handling form submissions.
    - The code snippet below shows how form data is extracted:
    ```python
    def _get_and_submit_form(
        session, url: str, data_callback=None, form_matcher=lambda form: True
    ):
        # ... (Fetching URL and parsing HTML) ...
        doc = html5lib.parse(response.text, namespaceHTMLElements=False)
        forms = doc.findall(".//form")
        # ... (Form matching logic) ...
        submit_form = ... # Form is found based on matcher

        inputs = submit_form.findall(".//input")

        data = dict()
        for form_input in inputs:
            value = form_input.attrib.get("value")
            if value and "name" in form_input.attrib:
                data[form_input.attrib["name"]] = value
        # ... (Data callback and form submission) ...
    ```
    - The code iterates through all `<input>` elements within the identified form (`submit_form`).
    - For each `<input>` element, it checks if it has both a `value` and a `name` attribute.
    - If both attributes are present, the name-value pair is added to the `data` dictionary, which is later submitted in the POST request.
    - There is no validation or filtering of the `name` attribute. Any input field with a `name` will be included in the submitted data, regardless of whether it is expected or documented by this library.
- Security test case:
    - Step 1: Modify the test HTML file `tests/github_form.html` to include an unexpected hidden input field within one of the forms. For example, add the following line within the `<form id="form2">` in `tests/github_form.html`:
    ```html
    <input type="hidden" name="unexpected_param" value="unexpected_value">
    ```
    - Step 2: Modify the test function `test_get_and_submit_form_by_id` in `tests/test_api.py` to assert that the unexpected parameter is included in the submitted form data.
    ```python
    def test_get_and_submit_form_by_id_unexpected_param(self):
        self._seed_session_with_file(GITHUB_FORM_HTML) # GITHUB_FORM_HTML now contains the unexpected parameter

        api._get_and_submit_form(
            session=self.session, url='http://github.com',
            form_matcher=lambda form: form.attrib.get('id') == 'form2')

        self.session.post.assert_called_once_with(
            'http://github.com/form2', data=dict(key2='value2', unexpected_param='unexpected_value')) # Assert that unexpected_param is in the submitted data
    ```
    - Step 3: Run the test using `pytest tests/test_api.py::TestApi::test_get_and_submit_form_by_id_unexpected_param`.
    - Step 4: Verify that the test passes, indicating that the `unexpected_param` is indeed included in the data submitted by `_get_and_submit_form`. This demonstrates the vulnerability where unintended parameters from the form are submitted.
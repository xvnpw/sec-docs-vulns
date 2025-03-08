## Combined Vulnerability List

### Cross-Site Scripting (XSS) in Visualization Functions

- Description:
    1. An attacker can inject malicious JavaScript code through the reference or hypothesis text inputs.
    2. When JiWER's visualization functions, `visualize_alignment()` or `visualize_error_counts()`, are used to display the evaluation results in a web application without proper sanitization, this injected JavaScript code can be executed in the user's browser.
    3. Here's a step-by-step breakdown of how the vulnerability can be triggered:
        - An attacker crafts a malicious input string containing JavaScript code. This string can be intended for either the reference or hypothesis text. For example, the attacker might use a payload like `<img src=x onerror=alert('XSS')>` within the input text.
        - The application, using the JiWER library, processes the attacker-crafted input strings along with legitimate input to calculate metrics such as Word Error Rate (WER) or Character Error Rate (CER).
        - The application then calls either `jiwer.visualize_alignment()` or `jiwer.visualize_error_counts()` to generate a textual representation of the alignment and error statistics. These visualization functions, without proper sanitization, incorporate the raw reference and hypothesis strings into the output.
        - The web application embeds the output from JiWER's visualization functions directly into an HTML web page, intending to display the evaluation results to users. Crucially, the application fails to sanitize or encode this output before rendering it in the HTML context.
        - When a user accesses the web page, their web browser parses the HTML content, including the visualization output from JiWER. Because the malicious JavaScript code injected in step 1 was not sanitized, the browser executes it as part of the web page, leading to a Cross-Site Scripting (XSS) attack.

- Impact:
    - Successful exploitation of this XSS vulnerability allows an attacker to execute arbitrary JavaScript code within the context of a user's browser when they view the page displaying JiWER's visualization output. This can have severe consequences, including:
        - **Session Hijacking**: Attackers can steal session cookies, allowing them to impersonate the user and gain unauthorized access to the web application and its functionalities.
        - **Cookie Theft**: Sensitive information stored in cookies can be exfiltrated, potentially including authentication tokens or personal data.
        - **Redirection to Malicious Websites**: Users can be silently redirected to attacker-controlled websites, which may host phishing pages or malware.
        - **Web Page Defacement**: The attacker can alter the content of the web page, displaying misleading information or damaging the application's reputation.
        - **Malicious Actions on Behalf of the User**: The attacker can perform actions within the web application as if they were the victim user, such as making unauthorized transactions, accessing sensitive data, or modifying user settings.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    - None. A review of the provided source code reveals that there is no input sanitization or output encoding implemented within the `visualize_alignment()` and `visualize_error_counts()` functions in `src/jiwer/alignment.py`. The reference and hypothesis strings are directly incorporated into the output strings without any form of security processing to prevent XSS.

- Missing Mitigations:
    - Output Encoding: When constructing the visualization output strings, the reference and hypothesis strings should be properly encoded for HTML context. This ensures that any HTML or JavaScript code within these strings is treated as plain text and not executed by the browser. Suitable encoding functions should be applied to escape HTML special characters such as `<`, `>`, `&`, `"`, and `'`.
    - By implementing output encoding, the application can safely display visualizations derived from potentially untrusted input strings without risking XSS attacks.

- Preconditions:
    1. **Web Application Integration**: A web application must be in place that utilizes the JiWER library to evaluate Automatic Speech Recognition (ASR) performance and display the results to users.
    2. **Unsanitized User Input**: The web application must accept user-provided input for either the reference or hypothesis texts (or both) without performing adequate sanitization or validation on these inputs. This allows attackers to inject malicious code into the system.
    3. **Visualization Function Usage**: The web application must use either the `jiwer.visualize_alignment()` or `jiwer.visualize_error_counts()` functions to generate visualizations of the ASR evaluation results.
    4. **Unsanitized Visualization Output Display**: The web application must render the output from JiWER's visualization functions in a web page without applying any output sanitization or encoding. This direct embedding of potentially malicious strings into the HTML context is what enables the XSS vulnerability.
    5. **User Access**: A user must access the web page where the unsanitized visualization output is displayed in order for the XSS payload to be executed within their browser.

- Source Code Analysis:
    - **File:** `src/jiwer/alignment.py`
    - **Functions:** `visualize_alignment` and `visualize_error_counts`

    Both `visualize_alignment` and `visualize_error_counts` functions in `src/jiwer/alignment.py` are vulnerable because they directly embed user-controlled strings (reference and hypothesis texts) into the output visualization without any sanitization.

    **`visualize_alignment` function:**
    This function constructs a string output that includes lines starting with "REF:" and "HYP:", directly followed by words or characters from the reference and hypothesis inputs.

    ```python
    def visualize_alignment(
        output: Union[WordOutput, CharacterOutput],
        show_measures: bool = True,
        skip_correct: bool = True,
        line_width: Optional[int] = None,
    ) -> str:
        # ...
        final_str = ""
        for idx, (gt, hp, chunks) in enumerate(zip(references, hypothesis, alignment)):
            # ...
            final_str += f"=== SENTENCE {idx + 1} ===\n\n"
            final_str += _construct_comparison_string(
                gt, hp, chunks, include_space_seperator=not is_cer, line_width=line_width
            )
            final_str += "\n"
        # ...
        return final_str

    def _construct_comparison_string(
        reference: List[str],
        hypothesis: List[str],
        ops: List[AlignmentChunk],
        include_space_seperator: bool = False,
        line_width: Optional[int] = None,
    ) -> str:
        ref_str = "REF: "
        hyp_str = "HYP: "
        op_str = "     "
        agg_str = ""  # aggregate string for max_chars split

        for op in ops:
            # ...
            ref = reference[op.ref_start_idx : op.ref_end_idx]
            hyp = hypothesis[op.hyp_start_idx : op.hyp_end_idx]
            # ...
            for rf, hp, c in zip(ref, hyp, op_chars):
                # ...
                ref_str += f"{rf:>{str_len}}" # <--- Vulnerable point: rf is directly added
                hyp_str += f"{hp:>{str_len}}" # <--- Vulnerable point: hp is directly added
                # ...
        # ...
        return agg_str + f"{ref_str[:-1]}\n{hyp_str[:-1]}\n{op_str[:-1]}\n"
    ```
    As highlighted above, the variables `rf` (reference word/character) and `hp` (hypothesis word/character) are directly appended to the output strings `ref_str` and `hyp_str` without any HTML encoding. If these variables contain malicious JavaScript, it will be included in the output string.

    **`visualize_error_counts` function:**
    Similarly, `visualize_error_counts` also incorporates reference and hypothesis words into the output string without sanitization when displaying substitutions.

    ```python
    def visualize_error_counts(
        output: Union[WordOutput, CharacterOutput],
        show_substitutions: bool = True,
        show_insertions: bool = True,
        show_deletions: bool = True,
        top_k: Optional[int] = None,
    ):
        # ...
        def build_list(errors: dict):
            # ...
            build = ""
            for count, (k, v) in enumerate(
                sorted(errors.items(), key=lambda tpl: tpl[1], reverse=True)
            ):
                # ...
                if isinstance(k, tuple):
                    build += f"{k[0]: <{ln}} --> {k[1]:<{ln}} = {v}x\n" # <--- Vulnerable point: k[0] and k[1] are directly added
                else:
                    build += f"{k:<{ln}} = {v}x\n"
            return build
        # ...
        if show_substitutions:
            # ...
            output += build_list(s)
        # ...
        return output
    ```
    In `build_list`, when handling substitutions (`isinstance(k, tuple)` is true), `k[0]` (substituted word from reference) and `k[1]` (substitution word from hypothesis) are directly added to the output string, again without any encoding.

- Security Test Case:
    1. **Setup**: Assume you have a web application that uses the JiWER library and displays the output of `jiwer.visualize_alignment()` or `jiwer.visualize_error_counts()` on a web page. This application should allow you to input reference and hypothesis texts. For testing purposes, you can create a simple Python script using Flask or a similar framework to simulate this web application.
    2. **Craft Malicious Input**: In the input field for the **reference text**, enter the following XSS payload:
        ```html
        <img src=x onerror=alert('XSS Vulnerability in JiWER - visualize_alignment')>
        ```
        For the **hypothesis text**, you can enter any arbitrary string, for example:
        ```text
        test hypothesis
        ```
    3. **Execute Test**: Submit these inputs to your web application. The application should process these inputs using JiWER and display the visualization, likely using `jiwer.visualize_alignment()`.
    4. **Observe Alert**: Access the web page where the visualization is displayed in your browser. If the vulnerability is present, you should see a JavaScript alert box pop up with the message: "XSS Vulnerability in JiWER - visualize_alignment". This alert indicates that the injected JavaScript code from your reference text was successfully executed by the browser, confirming the XSS vulnerability.
    5. **Inspect HTML Source (Alternative)**: If you don't see an alert, or to further confirm the vulnerability, inspect the HTML source code of the web page in your browser (usually by right-clicking on the page and selecting "View Page Source" or similar). Look for the rendered output of `jiwer.visualize_alignment()`. You should find the exact `<img src=x onerror=alert('XSS Vulnerability in JiWER - visualize_alignment')>` tag from your input directly embedded in the HTML, without any HTML encoding applied. This lack of encoding is the root cause of the XSS vulnerability.

    **Repeat for `visualize_error_counts()` (Optional but Recommended)**:
    To test `visualize_error_counts()`, you would need to ensure your application calls this function and displays its output. The test steps are largely the same, but you might adjust the alert message to: "XSS Vulnerability in JiWER - visualize_error_counts" and verify that the XSS is also exploitable when using error count visualization with a similar malicious input.

    By following these steps, you can effectively demonstrate and confirm the presence of the Cross-Site Scripting vulnerability in JiWER's visualization functions within a web application context.
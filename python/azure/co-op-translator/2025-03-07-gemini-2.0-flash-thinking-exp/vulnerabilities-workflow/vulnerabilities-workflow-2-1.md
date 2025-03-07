- Vulnerability Name: Cross-Site Scripting (XSS) via Malicious Markdown Input
- Description:
    1. An attacker crafts a malicious Markdown file. This file contains embedded JavaScript code within HTML tags or as a data URI within an image link.
    2. The attacker submits this malicious Markdown file to be translated by the Co-op Translator, either through the command-line tool or by including it in a GitHub repository that uses the GitHub Actions integration.
    3. The Co-op Translator processes the Markdown file, translates the text content, and generates translated Markdown output files. Critically, the malicious JavaScript code embedded in the original Markdown is preserved in the translated output because the translator does not sanitize HTML or JavaScript within the Markdown content.
    4. A user views the translated documentation, for example, by browsing the translated README file in a web browser or a Markdown viewer that renders HTML and JavaScript.
    5. The malicious JavaScript code embedded in the translated Markdown is executed in the user's browser, potentially allowing the attacker to perform actions such as stealing cookies, redirecting the user, or defacing the page.
- Impact:
    - Successful exploitation can lead to Cross-Site Scripting (XSS).
    - An attacker could execute arbitrary JavaScript code in the victim's browser when they view the translated documentation.
    - This could result in session hijacking, cookie theft, redirection to malicious sites, or defacement of the documentation page.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - None. The project does not currently implement any explicit sanitization or escaping of Markdown content to prevent XSS.
- Missing Mitigations:
    - Markdown output sanitization: The translated Markdown content should be sanitized to remove or escape any potentially malicious HTML or JavaScript code before being written to the output files. This could be achieved by using a library designed for Markdown sanitization.
- Preconditions:
    - The attacker needs to be able to provide a malicious Markdown file to the Co-op Translator for processing. This could be achieved by:
        - Contributing to a project that uses Co-op Translator.
        - Providing a malicious file to a user running the command-line tool locally.
    - A user must then view the translated documentation in a context where JavaScript within Markdown is executed (e.g., a web browser or a vulnerable Markdown viewer).
- Source Code Analysis:
    - The code in `/src/co_op_translator/utils/llm/markdown_utils.py` and `/src/co_op_translator/core/llm/markdown_translator.py` focuses on parsing, chunking, and translating Markdown content and updating links.
    - Specifically, `src/co_op_translator/core/llm/markdown_translator.py` outlines the `translate_markdown` function, which:
        ```python
        async def translate_markdown(self, document: str, language_code: str, md_file_path: str | Path, markdown_only: bool = False) -> str:
            ...
            # Step 3: Generate translation prompts and translate each chunk
            prompts = [...]
            results = await self._run_prompts_sequentially(prompts) # Translation happens here
            translated_content = "\n".join(results)

            # Step 4: Restore the code blocks and inline code from placeholders
            translated_content = restore_code_blocks_and_inline_code(translated_content, placeholder_map) # Code blocks are restored verbatim

            # Step 5: Update links and add disclaimer
            updated_content = update_links(md_file_path, translated_content, language_code, self.root_dir, markdown_only=markdown_only) # Links are updated, but no sanitization

            ...
        ```
    - The `restore_code_blocks_and_inline_code` function in `/src/co_op_translator/utils/llm/markdown_utils.py`  restores code blocks and inline code verbatim from placeholders, meaning any malicious JavaScript injected within code blocks in the original Markdown will be directly included in the translated output.
    - The `update_links` function updates links but does not sanitize the overall Markdown structure or content.
    - There is no code present in the provided files that sanitizes or escapes Markdown content to prevent XSS vulnerabilities. The translation process focuses on translating text and maintaining Markdown structure but does not include security measures against malicious content.
- Security Test Case:
    1. Create a malicious Markdown file named `malicious.md` with the following content:
        ```markdown
        # Malicious Markdown Example

        This is a demonstration of a potential XSS vulnerability.

        <script>
        alert("XSS Vulnerability Detected!");
        </script>

        [Link to trigger XSS](javascript:alert('XSS from link!'))

        ![Image with XSS](data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTIGZyb20gaW1hZ2UhJyk7PC9zY3JpcHQ+)
        ```
    2. Save this `malicious.md` file in a directory that will be processed by Co-op Translator. For example, create a directory `test_xss` and place `malicious.md` inside it.
    3. Run the Co-op Translator command-line tool to translate this file to Korean:
        ```bash
        poetry run translate -l ko -r test_xss
        ```
    4. Navigate to the `test_xss/translations/ko` directory.
    5. Open the translated Markdown file `malicious.md` (or its translated version if the filename changed) in a web browser or a Markdown viewer that supports JavaScript execution (like VS Code Markdown preview or some online Markdown viewers).
    6. Observe if the alert box "XSS Vulnerability Detected!" appears. Also, check if clicking the "Link to trigger XSS" link or if the "Image with XSS" loads and triggers the alert "XSS from image!".
    7. If the alert boxes appear, it confirms that the XSS vulnerability is present because the embedded JavaScript code from the malicious Markdown file was executed by the browser when rendering the translated output.
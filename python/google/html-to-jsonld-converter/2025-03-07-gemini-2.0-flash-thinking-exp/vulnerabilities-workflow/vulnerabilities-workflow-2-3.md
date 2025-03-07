### Vulnerability List

- Vulnerability Name: HTML Injection in Preview HTML

- Description:
    1. An attacker provides a crafted HTML input, either through the `--html_file` or `--html_string` argument, that contains malicious HTML code within the text content of HTML tags that are parsed and converted to JSON-LD. For example, the attacker could inject HTML code within a `<p>` tag that is intended to be converted to the `s:description` field in the JSON-LD.
    2. The `HtmlConverter` processes the HTML input using `BeautifulSoup` and extracts relevant information based on the defined logic in `Processor.processor`. This extracted information, including the potentially malicious HTML from the crafted input, is then stored in the `sanitized_json` object.
    3. The `PreviewHtmlOfJsonLd` class is used to generate an HTML preview of the `sanitized_json`. This class iterates through the JSON-LD structure and uses string formatting to create HTML elements for headline, sub-headline, and description fields.
    4. Specifically, in the `preview` method of `PreviewHtmlOfJsonLd`, the values from the JSON-LD (like `showcaseBlock['s:headline']`, `item['s:headline']`, `item['s:description']`, `item['s:image']`) are directly embedded into HTML strings using `.format()`.
    5. Because the values from the JSON-LD are not HTML-encoded before being inserted into the HTML preview, any HTML code injected by the attacker in the initial HTML input will be directly rendered in the preview HTML output.
    6. When the `CommonUtility().store_html()` function saves this generated HTML preview to the output file (specified by `--output_html_file_path`), the malicious HTML is persisted.
    7. If a user opens the generated HTML preview file in a web browser, the injected HTML code will be executed, potentially leading to various client-side attacks, such as Cross-Site Scripting (XSS) if the injected code is JavaScript. In this context, while the application is designed for local use, the generated preview HTML could be shared or hosted elsewhere, increasing the risk. Even in local context, a merchant partner might use this preview file for validation and inadvertently execute malicious code.

- Impact:
    - When a user opens the generated HTML preview file, the injected HTML code is executed in their browser.
    - This could lead to:
        - **Information Disclosure**: The attacker could potentially access sensitive information accessible to the user's browser, such as cookies or local storage, if the preview HTML is opened in a context where such data exists.
        - **Client-Side Redirection**: The attacker could redirect the user to a malicious website.
        - **Defacement**: The attacker could modify the content of the preview HTML page as displayed in the user's browser.
        - **Drive-by Downloads**: In more complex scenarios, the attacker might be able to initiate drive-by downloads by injecting specific HTML or JavaScript.
        - **Reduced Data Integrity Perception**: While the JSON-LD itself might be structurally as expected (except for the injected content), the preview HTML, intended for validation, will be misleading and potentially confusing for the merchant partner, reducing trust in the conversion process.

- Vulnerability Rank: Medium

- Currently Implemented Mitigations:
    - **HTML Tag Blacklisting and Filtering:** The `HtmlSectionCleaner` class attempts to remove certain blacklisted tags (like `script`, `style`, `iframe`) and filter tags based on CSS classes defined in `FILTER_TAGS`. This provides a basic level of sanitization but is not comprehensive and can be bypassed. This is implemented in `/code/Utility/html_section_cleaner.py`.
    - **`JsonSanitizer`**: This sanitizer in `/code/Utility/sanitizer.py` removes empty fields and lists from the JSON-LD. It does not perform HTML sanitization on the string values within the JSON-LD.

- Missing Mitigations:
    - **HTML Encoding for Preview HTML Generation**: The most critical missing mitigation is HTML encoding of the values retrieved from the JSON-LD before inserting them into the preview HTML in `Utility/preview_html_of_json_ld.py`. Specifically, in the `__preview_headline`, `__preview_sub_headline`, `__preview_description`, and `__preview_image` methods, the `{text}` and `{src}` placeholders should be HTML-encoded to prevent interpretation of HTML characters within the text content. For example, using a library function to escape HTML entities would prevent injected HTML from being rendered as code.
    - **Robust HTML Sanitization of Input**:  Instead of relying on a blacklist and simple tag removal, a robust HTML sanitization library should be used on the input HTML before it is processed. This would involve parsing the HTML and whitelisting allowed tags and attributes, and encoding or removing disallowed content. Libraries like `bleach` in Python are designed for this purpose. This sanitization should happen early in the processing pipeline, ideally within the `HtmlConverter` class, before further processing by the `Processor` and before generating JSON-LD.

- Preconditions:
    - The attacker needs to be able to provide crafted HTML input to the converter, either via `--html_file` or `--html_string` arguments.
    - The user needs to generate and open the HTML preview file using the `--output_html_file_path` argument and open it in a web browser to trigger the vulnerability.

- Source Code Analysis:
    1. **`Utility/preview_html_of_json_ld.py`**:
        - The `PreviewHtmlOfJsonLd` class is responsible for creating the HTML preview.
        - Methods `__preview_headline`, `__preview_sub_headline`, `__preview_description`, and `__preview_image` construct HTML strings using `.format()`:

        ```python
        def __preview_headline(self, headline_text):
            return '<p style="text-align:center;font-family:Roboto;margin:12px' \
                   ';font-size:18px;font-weight:700;" >{text}</p>' \
                .format(text=headline_text) # [VULNERABLE]: headline_text is directly inserted without HTML encoding

        def __preview_sub_headline(self, sub_headline_text):
            return '<p style="text-align:center;font-family:Roboto;margin:12px' \
                   ';font-size:15px;font-weight:650;" >{text}</p>' \
                .format(text=sub_headline_text) # [VULNERABLE]: sub_headline_text is directly inserted without HTML encoding

        def __preview_description(self, description_text):
            return '<p style=\"text-align:center;font-family:Roboto;margin:12px' \
                   ';font-size:12px;font-weight:400;\">{text}</p>' \
                .format(text=description_text) # [VULNERABLE]: description_text is directly inserted without HTML encoding

        def __preview_image(self, image_text):
            return '<img style=\"display:block;width:100%;margin:12px;\" src=\"{' \
                   'src}\"/>'.format(src=image_text) # [VULNERABLE]: image_text (src) is directly inserted without HTML encoding

        def preview(self, json):
            html = []
            for showcaseBlock in json['g:showcaseBlock']:
                if 's:headline' in showcaseBlock and showcaseBlock['s:headline']:
                    html.append(self.__preview_headline(headline_text=
                                                        showcaseBlock[
                                                            's:headline'])) # Headline from JSON-LD
                # ... (rest of the code)
        ```
        - In the `preview` method, it iterates through the `json` (which is the sanitized JSON-LD) and extracts values like `s:headline`, `s:description`, and `s:image`. These values are then passed directly to the `__preview_*` methods and inserted into the HTML string using `.format()`. No HTML encoding is performed at this stage.

    2. **`Converter/html_converter.py`**:
        - The `HtmlConverter` processes the input HTML and generates the `sanitized_json`.
        - The `sanitize` method calls `JsonSanitizer`, which only removes empty fields and lists but does not sanitize HTML content within strings in the JSON-LD.
        - The `dump` method converts the `sanitized_json` to a JSON string.

    3. **`main.py`**:
        - The `main` function orchestrates the conversion process.
        - It calls `PreviewHtmlOfJsonLd().preview(json=converter.sanitized_json)` to generate the preview HTML, passing the `sanitized_json` directly to the preview generation.

    **Visualization:**

    ```
    [Crafted HTML Input] --> main.py --> HtmlConverter --> BeautifulSoup --> Processor --> JSON-LD (sanitized_json - No HTML encoding)
                                                                                    |
                                                                                    v
    sanitized_json --> PreviewHtmlOfJsonLd.preview() --> [VULNERABLE HTML Generation - No HTML Encoding] --> HTML Preview Output File
    ```

- Security Test Case:
    1. **Prepare a malicious HTML input string**:
        ```html
        <div id="prdDetail">
            <p>This is a product description with a headline: <h1>Malicious Headline <script>alert("XSS Vulnerability");</script></h1></p>
            <p>Description with injected HTML: <img src="malicious_image.jpg" onerror="alert('Image load failed, XSS via onerror')"></p>
        </div>
        ```
    2. **Run the `main.py` script** with the crafted HTML string as input, and request an HTML preview output:
        ```bash
        python main.py -s '<div id="prdDetail"><p>This is a product description with a headline: <h1>Malicious Headline <script>alert("XSS Vulnerability");</script></h1></p><p>Description with injected HTML: <img src="malicious_image.jpg" onerror="alert(\'Image load failed, XSS via onerror\')"></p></div>' -p output_preview.html
        ```
    3. **Open the generated `output_preview.html` file** in a web browser.
    4. **Observe the result**:
        - You should see an alert box pop up with the message "XSS Vulnerability" from the `<script>` tag in the headline.
        - You should also see an alert box pop up with the message "Image load failed, XSS via onerror" due to the `onerror` attribute in the `<img>` tag, although this might depend on whether the browser attempts to load `malicious_image.jpg`. Even without image load attempt, the HTML structure will be broken due to injected HTML.
    5. **Expected Outcome**: The JavaScript code injected in the HTML input should be executed when the `output_preview.html` is opened in a browser, demonstrating HTML injection vulnerability in the preview HTML generation.

This test case demonstrates that malicious HTML injected into the input can be executed when the generated preview HTML is opened, confirming the HTML injection vulnerability.
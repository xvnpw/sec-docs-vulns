* Vulnerability Name: HTML Injection in Preview HTML

* Description:
    The `PreviewHtmlOfJsonLd` class in `/code/Utility/preview_html_of_json_ld.py` generates an HTML preview based on the processed JSON-LD output. The functions `__preview_headline`, `__preview_sub_headline`, `__preview_description`, and `__preview_image` within this class directly embed text content from the JSON-LD structure into HTML output without proper sanitization or escaping. Specifically, the values from the JSON-LD keys `s:headline`, `s:description`, and `s:image` are inserted into HTML tags using string formatting (`.format()`). If a malicious user crafts HTML input that, after processing and sanitization (by `JsonSanitizer`), results in malicious HTML code within these JSON-LD fields, this code will be directly inserted into the preview HTML. This can lead to HTML injection when the preview HTML is rendered in a browser.

    Steps to trigger the vulnerability:
    1. Provide a crafted HTML input to the converter, either via `--html_file` or `--html_string` arguments in `main.py`.
    2. The crafted HTML should be designed to be parsed by `BeautifulSoup` and processed by `Processor` to generate JSON-LD output.
    3. The crafted HTML should aim to inject malicious HTML code into the `s:headline`, `s:description`, or `s:image` fields of the JSON-LD output. For example, injecting an `<img>` tag with `onerror` attribute or a `<script>` tag.
    4. Run `main.py` with the crafted HTML input.
    5. Observe the generated preview HTML file (specified by `--output_html_file_path` argument, default is `output/result.html`).
    6. Open the preview HTML file in a web browser.
    7. If the crafted HTML was successfully injected, malicious code will be executed in the context of the preview HTML page when it is loaded in the browser.

* Impact:
    When a user opens the generated preview HTML file in a web browser, any malicious HTML code injected through this vulnerability will be executed. This could lead to:
    - **Cross-Site Scripting (XSS):** An attacker could inject JavaScript code that executes in the user's browser when they view the preview HTML. This script could steal cookies, redirect the user to a malicious website, or perform other actions on behalf of the user within the context of the preview HTML page.
    - **Information Disclosure:**  An attacker might be able to craft HTML to extract information from the user's browser or local system, depending on browser capabilities and security policies.
    - **Defacement:** The attacker could alter the content of the preview HTML page, replacing it with misleading or malicious information.

* Vulnerability Rank: Medium

* Currently Implemented Mitigations:
    - The project uses `JsonSanitizer` in `/code/Utility/sanitizer.py` to remove empty fields and lists from the JSON-LD. However, this sanitizer does not sanitize the string values within the JSON-LD, which are used to generate the preview HTML.
    - `HtmlSectionCleaner` in `/code/Utility/html_section_cleaner.py` removes blacklisted HTML tags from the input HTML before JSON-LD conversion. The `BLACKLISTED_TAGS` in `Constants.py` include tags like `script`, `iframe`, etc., which helps to reduce the attack surface but doesn't prevent injection of HTML through allowed tags or attributes that are later reflected in the preview HTML.

* Missing Mitigations:
    - **Output Encoding/Escaping:** The most critical missing mitigation is proper output encoding or escaping when generating the preview HTML in `PreviewHtmlOfJsonLd`. Before embedding text from JSON-LD into HTML, these strings should be HTML-escaped to prevent the browser from interpreting them as HTML tags or attributes. For example, characters like `<`, `>`, `"`, `'`, and `&` should be replaced with their corresponding HTML entities (e.g., `<` becomes `&lt;`).
    - **Content Security Policy (CSP):** Implementing a Content Security Policy for the preview HTML could further mitigate the impact of HTML injection. A restrictive CSP can prevent the execution of inline scripts and restrict the sources from which resources can be loaded. However, this is a defense-in-depth measure and output escaping is the primary mitigation needed.

* Preconditions:
    - The attacker needs to be able to provide HTML input to the conversion tool, either as a file or as a string.
    - The attacker needs to craft the HTML input in such a way that after processing by the converter, malicious HTML code is included in the `s:headline`, `s:description`, or `s:image` fields of the resulting JSON-LD.
    - The user must open the generated preview HTML file in a web browser for the injection to be exploited.

* Source Code Analysis:
    1. **File: `/code/Utility/preview_html_of_json_ld.py`**
    2. **`preview(self, json)` function:** This function iterates through the `g:showcaseBlock` array in the input `json` and for each item, it checks for `s:headline`, `s:itemListElement`, `s:description`, and `s:image` keys.
    3. **`__preview_headline(self, headline_text)` function:**
       ```python
       def __preview_headline(self, headline_text):
           return '<p style="text-align:center;font-family:Roboto;margin:12px' \
                  ';font-size:18px;font-weight:700;" >{text}</p>' \
               .format(text=headline_text)
       ```
       - The `headline_text` (which comes from JSON `s:headline`) is directly inserted into the HTML `<p>` tag using `.format(text=headline_text)`. There is no HTML escaping performed on `headline_text`.
    4. **`__preview_sub_headline(self, sub_headline_text)` function:**
       ```python
       def __preview_sub_headline(self, sub_headline_text):
           return '<p style="text-align:center;font-family:Roboto;margin:12px' \
                  ';font-size:15px;font-weight:650;" >{text}</p>' \
               .format(text=sub_headline_text)
       ```
       - Similarly, `sub_headline_text` (from JSON `s:headline` within `s:itemListElement`) is directly embedded without escaping.
    5. **`__preview_description(self, description_text)` function:**
       ```python
       def __preview_description(self, description_text):
           return '<p style=\"text-align:center;font-family:Roboto;margin:12px' \
                  ';font-size:12px;font-weight:400;\">{text}</p>' \
               .format(text=description_text)
       ```
       - `description_text` (from JSON `s:description` within `s:itemListElement`) is also directly embedded.
    6. **`__preview_image(self, image_text)` function:**
       ```python
       def __preview_image(self, image_text):
           return '<img style=\"display:block;width:100%;margin:12px;\" src=\"{' \
                  'src}\"/>'.format(src=image_text)
       ```
       - `image_text` (from JSON `s:image` within `s:itemListElement`) is inserted into the `src` attribute of the `<img>` tag. Although this is an attribute, and direct HTML tag injection is not possible here, it could still be vulnerable if `image_text` is not a valid URL or if it's designed to trigger browser-specific vulnerabilities. However, the primary HTML injection vector is through the text content in other functions.

    **Visualization:**

    ```
    [HTML Input] --> [HtmlConverter] --> [Processor] --> [JSON-LD Output] --> [JsonSanitizer] --> [Sanitized JSON-LD] --> [PreviewHtmlOfJsonLd] --> [Preview HTML] --> [Browser]
                                                                                                      ^
                                                                                                      |
                                                                                                 HTML Injection Point (No Output Escaping)
    ```

* Security Test Case:
    1. **Crafted HTML Input (html_injection.html):**
       ```html
       <div id="prdDetail">
           <div>
               <h2 class="title">Headline Text</h2>
               <p class="description">Description Text</p>
               <ul>
                   <li>List Item 1</li>
                   <li>List Item 2</li>
               </ul>
               <div class="item">
                   <h3 class="sub-title">Sub Headline Text</h3>
                   <p class="description">Another Description</p>
                   <img src="image.jpg">
               </div>
               <div class="item">
                   <h3 class="sub-title">Sub Headline Text 2 <script>alert("XSS")</script></h3>
                   <p class="description">Description with <img src=x onerror=alert("XSS_IMG")></p>
               </div>
           </div>
       </div>
       ```
    2. **Run the converter:**
       ```bash
       python code/main.py -f html_injection.html -c prdDetail -p output_xss.html
       ```
    3. **Inspect `output_xss.html`:** Open `output/result.html` (or `output_xss.html` if `-p output_xss.html` was used) in a web browser.
    4. **Observe JavaScript Execution:** You should see two JavaScript alert boxes pop up: one with "XSS" and another with "XSS_IMG". This confirms that the `<script>` tag and the `onerror` attribute within the crafted HTML were injected and executed in the preview HTML, demonstrating the HTML injection vulnerability.
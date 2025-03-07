- Vulnerability Name: Cross-Site Scripting (XSS) vulnerability due to lack of HTML sanitization
- Description:
  1. An attacker crafts a malicious HTML payload containing JavaScript code, for example: `<img src="x" onerror="alert('XSS')">`.
  2. The attacker provides this malicious HTML string as input to the `translate_html_string` function of the BudouX library. This function is available in Python, JavaScript, and Java versions of the library.
  3. BudouX processes the HTML to insert word break hints but does not sanitize the input.
  4. BudouX outputs an HTML string that includes the malicious payload without any modification. For example, in Python:
     ```python
     import budoux
     parser = budoux.load_default_japanese_parser()
     malicious_html = '<img src="x" onerror="alert(\'XSS\')">'
     output_html = parser.translate_html_string(malicious_html)
     print(output_html)
     ```
     This will output: `<span style="word-break: keep-all; overflow-wrap: anywhere;"><img src="x" onerror="alert('XSS')"></span>`
  5. If this output HTML is then rendered in a user's web browser, the JavaScript code within the `onerror` attribute (in this example, `alert('XSS')`) will be executed.

- Impact:
  Successful exploitation of this vulnerability allows an attacker to execute arbitrary JavaScript code in the browser of a user who views content processed by BudouX with malicious HTML input. This can lead to various malicious activities, including:
  - Account takeover: Stealing session cookies or credentials to gain unauthorized access to the user's account.
  - Data theft: Accessing sensitive information displayed on the page or making requests to external services with the user's credentials.
  - Redirection to malicious websites: Redirecting the user to phishing sites or websites hosting malware.
  - Defacement: Altering the content of the webpage visible to the user.
  - Further attacks: Using the compromised webpage as a platform to launch attacks against other users or systems.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
  - None. The documentation explicitly states in multiple README files (`/code/README.md`, `/code/java/README.md`, `/code/javascript/README.md`) under the "Caveat" section that: "**BudouX doesn't sanitize any inputs.** Malicious HTML inputs yield malicious HTML outputs."

- Missing Mitigations:
  - Input sanitization: BudouX should sanitize HTML inputs before processing them. This could involve using a library specifically designed for HTML sanitization to remove or neutralize any potentially malicious HTML tags or attributes before passing the HTML to the phrase breaking logic and outputting the result.

- Preconditions:
  1. The application using BudouX must accept HTML input from an untrusted source, such as user-generated content or external data.
  2. The application must use BudouX's `translate_html_string` function (or equivalent in JavaScript/Java) to process this untrusted HTML input.
  3. The output HTML from BudouX must be rendered in a user's web browser without further sanitization or security measures.

- Source Code Analysis:
  - `/code/budoux/parser.py`:
    ```python
    def translate_html_string(self, html: str) -> str:
        """Translates the given HTML string with markups for semantic line breaks.
        ...
        """
        text_content = get_text(html) # Extracts text content from HTML, no sanitization
        chunks = self.parse(text_content) # Parses text content for line breaks
        return resolve(chunks, html) # Reconstructs HTML with word break hints, no sanitization
    ```
    The `translate_html_string` function in `budoux/parser.py` takes HTML input and passes it to `get_text` to extract text and then to `resolve` to reconstruct HTML. Neither of these functions, nor the `translate_html_string` function itself, implement any HTML sanitization.

  - `/code/budoux/html_processor.py`:
    ```python
    class TextContentExtractor(HTMLParser):
        """An HTML parser to extract text content.
        ...
        """
        output = ''

        def handle_data(self, data: str) -> None:
            self.output += data
    ```
    `TextContentExtractor` simply extracts text data from HTML tags using `HTMLParser` and accumulates it in `output`. No sanitization is performed here.

    ```python
    class HTMLChunkResolver(HTMLParser):
        """An HTML parser to resolve the given HTML string and semantic chunks.
        ...
        """
        output = ''
        ...
        def handle_starttag(self, tag: str, attrs: HTMLAttr) -> None:
            ...
            self.output += '<%s%s>' % (tag, encoded_attrs)

        def handle_endtag(self, tag: str) -> None:
            self.output += '</%s>' % (tag)

        def handle_data(self, data: str) -> None:
            ...
            self.output += char
            ...
    ```
    `HTMLChunkResolver` also extends `HTMLParser`. It reconstructs the HTML by handling start tags, end tags, and data, inserting word break hints (`\u200b`). It does not perform any sanitization; it simply passes through the tags and attributes from the input HTML to the output.

  - Visualization:

  ```mermaid
  graph LR
      InputHTML[Input HTML String] --> TextExtraction[TextContentExtractor.get_text()];
      TextExtraction --> Parse[Parser.parse()];
      Parse --> HTMLResolution[HTMLChunkResolver.resolve()];
      HTMLResolution --> OutputHTML[Output HTML String];
      subgraph budoux/parser.py
        translate_html_string
      end
      subgraph budoux/html_processor.py
        TextContentExtractor
        HTMLChunkResolver
        resolve
        get_text
      end
      style translate_html_string fill:#f9f,stroke:#333,stroke-width:2px
      style TextContentExtractor fill:#ccf,stroke:#333,stroke-width:1px
      style HTMLChunkResolver fill:#ccf,stroke:#333,stroke-width:1px
      style resolve fill:#ccf,stroke:#333,stroke-width:1px
      style get_text fill:#ccf,stroke:#333,stroke-width:1px
      style Parse fill:#f9f,stroke:#333,stroke-width:2px
      style HTMLResolution fill:#f9f,stroke:#333,stroke-width:2px
  ```
  The visualization shows the data flow. Input HTML goes through text extraction and parsing for line breaks, and then HTML is resolved by adding word break hints. There is no sanitization step in this process.

- Security Test Case:
  1. Prepare a test HTML file (e.g., `test_xss.html`) with the following content:
     ```html
     <!DOCTYPE html>
     <html>
     <head>
         <title>BudouX XSS Test</title>
     </head>
     <body>
         <div id="budoux_output"></div>
         <script type="module">
             import { loadDefaultJapaneseParser } from 'budoux';
             const parser = loadDefaultJapaneseParser();
             const maliciousHTML = '<img src="x" onerror="alert(\'XSS Vulnerability in BudouX!\')">';
             const outputHTML = parser.translateHTMLString(maliciousHTML);
             document.getElementById('budoux_output').innerHTML = outputHTML;
         </script>
     </body>
     </html>
     ```
  2. Open `test_xss.html` in a web browser.
  3. Observe the result. If a JavaScript alert box pops up with the message "XSS Vulnerability in BudouX!", it confirms the Cross-Site Scripting vulnerability. This is because the `onerror` event handler in the `<img>` tag is executed, demonstrating that malicious JavaScript can be injected and run through BudouX's HTML processing.
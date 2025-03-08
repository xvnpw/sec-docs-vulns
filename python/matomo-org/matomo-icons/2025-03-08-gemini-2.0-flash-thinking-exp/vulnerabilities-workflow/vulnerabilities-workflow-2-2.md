### Vulnerability List

- Vulnerability Name: Cross-Site Scripting (XSS) via Malicious SVG Icons

- Description:
    1. An attacker crafts a malicious SVG file containing embedded JavaScript code.
    2. The attacker submits a pull request to the `matomo-icons` repository, including the malicious SVG file in the `/src` directory, potentially under any icon category (e.g., `brand`, `browsers`, `devices`).
    3. If the pull request is merged by a maintainer without proper security review, the malicious SVG file is now part of the repository's source code.
    4. When the `convert.sh` script is executed (either manually by a maintainer or automatically via CI/CD), it processes all SVG files in the `/src` directory.
    5. The `convert.sh` script uses `inkscape` and `mogrify` to convert and optimize the icons. Critically, the script does not sanitize the SVG files to remove potentially malicious JavaScript code embedded within them.
    6. The converted icons, including the maliciously crafted SVG (now potentially converted to PNG if `mogrify` processing occurs after `inkscape`), are placed in the `/dist` directory.
    7. If a Matomo instance or any other system using these icons retrieves and renders icons from the `/dist` directory without proper sanitization, the malicious JavaScript code within the SVG (or potentially carried over to the PNG if conversion doesn't fully sanitize) will be executed in the user's browser.
    8. This results in a Cross-Site Scripting (XSS) vulnerability, as the attacker-controlled JavaScript code is executed within the context of the user's session in the application using these icons.

- Impact:
    Successful exploitation of this XSS vulnerability can have severe consequences:
    - **Session Hijacking:** Attackers can steal user session cookies, gaining unauthorized access to user accounts and sensitive data within the Matomo platform or any application using these icons.
    - **Defacement:** Attackers can modify the visual appearance of the application by injecting arbitrary HTML content, potentially damaging the reputation and trust in the platform.
    - **Redirection:** Users can be redirected to malicious websites, potentially leading to phishing attacks or malware infections.
    - **Data Theft:** Attackers can steal sensitive information displayed within the application by sending it to attacker-controlled servers.
    - **Malware Distribution:** Attackers can use the XSS vulnerability to distribute malware to users of the application.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    - None. The provided code does not include any explicit SVG sanitization or input validation to prevent malicious code injection in SVG files. The `convert.sh` script focuses on image conversion and optimization but lacks security considerations regarding malicious content.

- Missing Mitigations:
    - **SVG Sanitization:** Implement a robust SVG sanitization process within the `convert.sh` script or as a separate step before or after conversion. This process should parse SVG files and remove or neutralize any potentially malicious elements, especially JavaScript code embedded within `<script>` tags, `onload` attributes, or within SVG attributes like `xlink:href` that could be abused with `javascript:` URLs. Libraries like DOMPurify (for JavaScript) or similar server-side libraries could be integrated.
    - **Input Validation:** Implement checks to validate the content of uploaded or contributed SVG files before they are processed by the `convert.sh` script. This could include basic checks for `<script>` tags or `javascript:` URLs and more advanced parsing and sanitization.
    - **Content Security Policy (CSP):** While not a mitigation within this icon project itself, Matomo or any application using these icons should implement a strong Content Security Policy (CSP). CSP can significantly reduce the impact of XSS vulnerabilities by controlling the sources from which the browser is allowed to load resources, effectively preventing the execution of inline JavaScript or JavaScript loaded from untrusted sources.

- Preconditions:
    1. An attacker needs to be able to contribute to the `matomo-icons` project, typically by submitting a pull request on GitHub.
    2. A maintainer of the `matomo-icons` project merges the pull request containing the malicious SVG file without performing adequate security review and sanitization.
    3. The `convert.sh` script is executed, processing the malicious SVG file and generating output icons in the `/dist` directory.
    4. Matomo or another application uses these icons from the `/dist` directory and renders them in a web context without further sanitization of the icon content.

- Source Code Analysis:
    1. **`convert.sh` script:**
        - The script iterates through SVG files in the `src` directory using `src{/**/,/flags/}*.{svg,png,gif,jpg,ico}`.
        - For SVG files (`[[ $i == *.svg ]]`), it calls the `resizeSvg` function.
        - **`resizeSvg` function:**
            - It uses `inkscape` to convert the SVG: `inkscape -h "$size" "$inputfile" -o "$outputfile"` or `inkscape -h 1024 "$inputfile" -o "$outputfile"`. `inkscape` itself might have options for sanitization, but they are not used here.
            - It then uses `mogrify` to further process the output, including resizing and sharpening. `mogrify` is primarily for image manipulation and doesn't inherently sanitize SVG content for XSS.
            - **Crucially, neither `inkscape` nor `mogrify` commands in this script are used with any sanitization flags or configurations.**  They are used for conversion and optimization, not security.
        - **No Sanitization:** The script completely lacks any step to sanitize the SVG files before or after processing. It assumes that all input SVG files are safe, which is an incorrect assumption in a public contribution environment.

    2. **Absence of Input Validation:**
        - The script processes all files found in the `src` directory based on the glob pattern. There is no validation to check if the files are safe or if they contain malicious content.

    **Visualization:**

    ```
    Attacker creates malicious SVG -> Submits PR -> PR Merged (No Security Review) -> convert.sh processes SVG (No Sanitization) -> Malicious Icon in /dist -> Matomo/App uses icon (No Sanitization) -> XSS in User Browser
    ```

- Security Test Case:
    1. **Create a malicious SVG file:** Create a file named `malicious.svg` in the `/src/brand` directory (or any other relevant directory). The content of `malicious.svg` should be:
        ```xml
        <?xml version="1.0" encoding="UTF-8"?>
        <svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" viewBox="0 0 48 48">
          <script>alert('XSS Vulnerability!')</script>
          <rect width="48" height="48" fill="#4CAF50"/>
        </svg>
        ```
    2. **Run the conversion script:** Execute the `convert.sh` script from the project root: `./convert.sh`. This will process the `malicious.svg` file and generate `dist/brand/malicious.png` (or potentially `malicious.svg` depending on processing).
    3. **Verify the malicious code is present in the output:**
        - Open the generated file `dist/brand/malicious.png` (or `dist/brand/malicious.svg` if it remains an SVG) in a text editor.
        - Check if the `<script>alert('XSS Vulnerability!')</script>` tag (or a similar JavaScript payload) is still present in the output file. In the case of PNG conversion, the script might not be directly present in the PNG file itself, but if the SVG was not properly sanitized by `inkscape` before PNG conversion, there might still be ways to trigger XSS depending on how Matomo renders the icons (e.g., if it somehow caches or reuses parts of the original SVG). However, for SVG output it's more direct.
    4. **Simulate Matomo icon rendering (or test in Matomo directly):**
        - Create a simple HTML file to simulate how Matomo might use these icons.
        ```html
        <!DOCTYPE html>
        <html>
        <head>
          <title>SVG Icon Test</title>
        </head>
        <body>
          <h1>Testing SVG Icon</h1>
          <img src="dist/brand/malicious.png" alt="Malicious Icon"> <!-- Or malicious.svg if SVG output -->
        </body>
        </html>
        ```
        - Serve this HTML file using a local web server (e.g., using Python's `http.server` or `php -S localhost:8000`).
        - Access the HTML file in a web browser.
        - **Observe if the `alert('XSS Vulnerability!')` is executed.** If the alert box appears, it confirms the XSS vulnerability.

This test case demonstrates that malicious JavaScript code can be embedded in an SVG file, processed by the `convert.sh` script without sanitization, and potentially executed when the resulting icon is rendered in a web browser, confirming the XSS vulnerability.
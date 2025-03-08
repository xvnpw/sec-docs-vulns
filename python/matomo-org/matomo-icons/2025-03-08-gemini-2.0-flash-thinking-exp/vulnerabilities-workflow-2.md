## Vulnerability Report

The following high-severity vulnerability has been identified in the `matomo-icons` project.

### Vulnerability Name: Cross-Site Scripting (XSS) via Malicious SVG Icons

- Description:
    An attacker can inject malicious JavaScript code into SVG icon files and contribute them to the `matomo-icons` repository, typically through a pull request. If a maintainer merges this pull request without proper security review, the malicious SVG file becomes part of the repository's source code. The `convert.sh` script, responsible for processing icons, uses `inkscape` to convert and optimize SVG files. However, the script does not sanitize these SVG files to remove embedded JavaScript or other potentially malicious content before or during the conversion process. Consequently, if the Matomo application (or any other application using these icons) directly uses these generated icons from the `/dist` directory and renders them in a web context without proper sanitization, the embedded JavaScript code within the malicious SVG will be executed in the user's browser. This results in a Cross-Site Scripting (XSS) vulnerability. The attack flow is as follows:
    1.  An attacker crafts a malicious SVG file containing embedded JavaScript code, for example within `<script>` tags or event handlers like `onload`.
    2.  The attacker submits a pull request to the `matomo-icons` repository, including the malicious SVG file in the `/src` directory, potentially under any icon category (e.g., `brand`, `browsers`, `devices`).
    3.  If the pull request is merged by a maintainer without proper security review, the malicious SVG file is now part of the repository's source code.
    4.  When the `convert.sh` script is executed (either manually by a maintainer or automatically via CI/CD), it processes all SVG files in the `/src` directory.
    5.  The `convert.sh` script uses `inkscape` and `mogrify` to convert and optimize the icons. Critically, the script does not sanitize the SVG files to remove potentially malicious JavaScript code embedded within them.
    6.  The converted icons, including the maliciously crafted SVG (now potentially converted to PNG if `mogrify` processing occurs after `inkscape`), are placed in the `/dist` directory.
    7.  If a Matomo instance or any other system using these icons retrieves and renders icons from the `/dist` directory without proper sanitization, the malicious JavaScript code within the SVG (or potentially carried over to the PNG if conversion doesn't fully sanitize) will be executed in the user's browser.
    8.  This results in a Cross-Site Scripting (XSS) vulnerability, as the attacker-controlled JavaScript code is executed within the context of the user's session in the application using these icons.

- Impact:
    Successful exploitation of this XSS vulnerability can have severe consequences:
    *   Account Takeover: Attackers can steal user session cookies, gaining unauthorized access to user accounts and sensitive data within the Matomo platform or any application using these icons, potentially leading to complete account takeover.
    *   Data Theft: The attacker could access sensitive data within the Matomo application, depending on the user's permissions, potentially leading to exfiltration of personal or confidential information.
    *   Website Defacement: Attackers can modify the visual appearance of the application by injecting arbitrary HTML content, potentially damaging the reputation and trust in the platform.
    *   Redirection: Users can be redirected to malicious websites, potentially leading to phishing attacks or malware infections.
    *   Malware Distribution: Attackers can use the XSS vulnerability to distribute malware to users of the application, compromising their systems.
    *   Malicious Actions: The attacker could perform actions within Matomo on behalf of the logged-in user, such as modifying settings or accessing restricted features, potentially disrupting operations or causing further harm.

- Vulnerability Rank: High

- Currently implemented mitigations:
    None in the provided project files. The `convert.sh` script focuses on image conversion and optimization but does not include any SVG sanitization steps. There are no explicit sanitization or security measures in the scripts to prevent XSS vulnerabilities in SVG files.

- Missing mitigations:
    *   SVG Sanitization: The `convert.sh` script should incorporate a robust SVG sanitization step before or during the conversion process. This process should parse SVG files and remove or neutralize any potentially malicious elements, especially JavaScript code embedded within `<script>` tags, `onload` attributes, or within SVG attributes like `xlink:href` that could be abused with `javascript:` URLs. Libraries like DOMPurify (for JavaScript) or similar server-side libraries could be integrated.
    *   Input Validation: Implement checks to validate the content of uploaded or contributed SVG files before they are processed by the `convert.sh` script. This could include basic checks for `<script>` tags or `javascript:` URLs and more advanced parsing and sanitization. Implement strict input validation and review processes for contributed icons, especially SVG files. Manually or automatically inspect SVG files for embedded JavaScript or suspicious code before accepting them into the repository.
    *   Content Security Policy (CSP): While not a mitigation within this icon project itself, Matomo or any application using these icons should implement a strong Content Security Policy (CSP). CSP can significantly reduce the impact of XSS vulnerabilities by controlling the sources from which the browser is allowed to load resources, effectively preventing the execution of inline JavaScript or JavaScript loaded from untrusted sources. This would act as a defense-in-depth measure to mitigate the impact of XSS vulnerabilities, even if malicious SVG icons are served.

- Preconditions:
    *   An attacker needs to be able to contribute to the `matomo-icons` project, typically by submitting a pull request on GitHub.
    *   A maintainer of the `matomo-icons` project merges the pull request containing the malicious SVG file without performing adequate security review and sanitization.
    *   The `convert.sh` script is executed, processing the malicious SVG file and generating output icons in the `/dist` directory.
    *   Matomo or another application uses these icons from the `/dist` directory and renders them in a web context without further sanitization of the icon content.
    *   Matomo must be configured to serve the generated icons from the `dist` directory to users' browsers.
    *   Matomo must not have implemented sufficient SVG sanitization or CSP to prevent the execution of embedded JavaScript within SVG files.

- Source code analysis:
    1.  **`convert.sh` script:** The `resizeSvg` function is responsible for handling SVG files:
        ```bash
        function resizeSvg () {
            inputfile=$1
            outputfile=$2
            if echo "$outputfile" | grep "flags"
            then
                inkscape -h "$size" "$inputfile" -o "$outputfile"
            else
                inkscape -h 1024 "$inputfile" -o "$outputfile"
                mogrify \
                    -background none \
                    -bordercolor transparent -border 1x1 \
                    -trim \
                    -thumbnail "${size}"x"${size}"\> \
                    -unsharp 0x1 \
                    -gravity center \
                    -extent "${size}"x"${size}" \
                    "$outputfile"

            fi
            optimizeIcon "$outputfile"
        }
        ```
        This function uses `inkscape` to convert the input SVG file (`$inputfile`) to a PNG file (`$outputfile`). Critically, there is **no sanitization** performed on the SVG file before or during this conversion. `inkscape` itself may offer some default sanitization, but it's not guaranteed to be sufficient to prevent all XSS vectors, and no sanitization flags are used in the script. The subsequent `mogrify` commands are for image manipulation (trimming, resizing, sharpening) and do not address security concerns. The `optimizeIcon` function uses `pngquant` which is for PNG optimization and does not affect the SVG content itself.
    2.  **Absence of Sanitization:**  A review of all scripts (`convert.sh`, `analyseIco.py`, `referrers.py`, `sort.py`, `tests.py`, `tools/git-imgdiff.sh`) confirms that there is no code implemented to sanitize SVG files or remove potentially malicious content. The focus is solely on image processing, conversion, and testing for image properties (size, format, etc.), not security. The script processes all files found in the `src` directory based on the glob pattern. There is no validation to check if the files are safe or if they contain malicious content.
    3.  **Attack Vector & Contribution Workflow:** The `README.md` explicitly encourages contributions via pull requests: "An icon is missing, or you have a better one? Create a [new issue](https://github.com/matomo-org/matomo-icons/issues/new) or, even better, open a pull request." This contribution workflow is the primary attack vector, as it allows an attacker to submit malicious SVG files.
    **Visualization:**

    ```
    Attacker creates malicious SVG -> Submits PR -> PR Merged (No Security Review) -> convert.sh processes SVG (No Sanitization) -> Malicious Icon in /dist -> Matomo/App uses icon (No Sanitization) -> XSS in User Browser
    ```

- Security test case:
    1.  **Create a malicious SVG file:** Create a file named `malicious.svg` with the following content in `/code/src/brand/` (or any relevant subdirectory within `/src`):
        ```xml
        <?xml version="1.0" encoding="UTF-8"?>
        <svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" viewBox="0 0 48 48">
          <script>alert('XSS Vulnerability!')</script>
          <rect width="48" height="48" fill="#4CAF50"/>
        </svg>
        ```
    2.  **Run the conversion script:** Execute the `convert.sh` script from the `/code/` directory:
        ```bash
        ./convert.sh
        ```
    3.  **Locate the processed icon:** Find the processed icon in the `dist` directory. In this example, it would be `dist/brand/malicious.png` (or potentially `dist/brand/malicious.svg` depending on how Matomo serves icons and the script's full execution context).
    4.  **Verify the malicious code is present in the output:** Open the generated file `dist/brand/malicious.png` (or `dist/brand/malicious.svg` if it remains an SVG) in a text editor. Check if the `<script>alert('XSS Vulnerability!')</script>` tag (or a similar JavaScript payload) is still present in the output file.
    5.  **Simulate Matomo icon rendering (or test in Matomo directly):** Create a simple HTML file to simulate how Matomo might use these icons.
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
        Serve this HTML file using a local web server (e.g., using Python's `http.server` or `php -S localhost:8000`). Access the HTML file in a web browser.
    6.  **Verify XSS Execution:** Observe if the `alert('XSS Vulnerability!')` is executed. If the alert box appears, it confirms the XSS vulnerability, demonstrating that malicious JavaScript code can be embedded in an SVG file, processed by the `convert.sh` script without sanitization, and potentially executed when the resulting icon is rendered in a web browser.
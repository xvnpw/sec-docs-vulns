- Vulnerability name: Cross-Site Scripting (XSS) via Malicious SVG Icons

- Description:
    1. An attacker contributes a malicious SVG icon to the `src` directory of the `matomo-icons` repository, for example, via a pull request. This SVG file contains embedded JavaScript code.
    2. The maintainers merge the pull request, and the malicious SVG file is now part of the repository.
    3. The `convert.sh` script is executed to process the icons. This script uses `inkscape` to convert SVG files to PNG format.
    4. The `convert.sh` script does not sanitize the SVG files to remove embedded JavaScript code before or during the conversion process.
    5. If the Matomo application directly uses these SVG source files (or the converted PNGs which might still carry some XSS risk depending on Matomo's rendering and the exact nature of the SVG/PNG conversion and rendering process in browsers) to display icons in a web page, and if Matomo does not perform its own SVG sanitization, the embedded JavaScript code from the malicious SVG can be executed in a user's browser.
    6. This can occur when a Matomo user views a page where the malicious icon is displayed, such as in reports or settings pages.
    7. The attacker's JavaScript code will then run in the context of the user's Matomo session, potentially allowing the attacker to steal session cookies, perform actions on behalf of the user, or deface the Matomo interface.

- Impact:
    * Account Takeover: An attacker could potentially steal session cookies and hijack a user's Matomo account.
    * Data Theft: The attacker could access sensitive data within the Matomo application, depending on the user's permissions.
    * Website Defacement: The attacker could modify the content of Matomo pages, causing reputational damage.
    * Malicious Actions: The attacker could perform actions within Matomo on behalf of the logged-in user, such as modifying settings or accessing restricted features.

- Vulnerability rank: High

- Currently implemented mitigations:
    * None in the provided project files. The `convert.sh` script focuses on image conversion and optimization but does not include any SVG sanitization steps.

- Missing mitigations:
    * SVG Sanitization: The `convert.sh` script should incorporate an SVG sanitization step before or during the conversion process. This could involve using a dedicated SVG sanitization library or tool to remove potentially malicious elements, such as `<script>` tags, `javascript:` URLs in attributes, and other XSS vectors.
    * Input Validation: While not directly in this project, Matomo application should sanitize any SVG icons before displaying them to users, even if the icons are expected to be from a trusted source (like this icon repository).

- Preconditions:
    * An attacker needs to be able to contribute a malicious SVG file to the `matomo-icons` repository (e.g., via pull request and merge by maintainers).
    * The Matomo application must directly use the SVG icons from this repository (or the generated PNGs without further sanitization) and display them in a web context without proper sanitization.

- Source code analysis:
    1. **`convert.sh` script:** The `resizeSvg` function is responsible for handling SVG files:
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
        This function uses `inkscape` to convert the input SVG file (`$inputfile`) to a PNG file (`$outputfile`).  Critically, there is **no sanitization** performed on the SVG file before or during this conversion. `inkscape` itself may offer some default sanitization, but it's not guaranteed to be sufficient to prevent all XSS vectors. The subsequent `mogrify` commands are for image manipulation (trimming, resizing, sharpening) and do not address security concerns.
    2. **Absence of Sanitization:**  A review of all scripts (`convert.sh`, `analyseIco.py`, `referrers.py`, `sort.py`, `tests.py`, `tools/git-imgdiff.sh`) confirms that there is no code implemented to sanitize SVG files or remove potentially malicious content. The focus is solely on image processing, conversion, and testing for image properties (size, format, etc.), not security.
    3. **Attack Vector:** The `README.md` explicitly encourages contributions via pull requests: "An icon is missing, or you have a better one? Create a [new issue](https://github.com/matomo-org/matomo-icons/issues/new) or, even better, open a pull request." This contribution workflow is the primary attack vector, as it allows an attacker to submit malicious SVG files.

- Security test case:
    1. **Create a malicious SVG file:** Create a file named `malicious.svg` with the following content in `/code/src/brand/`:
        ```xml
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100">
          <script>alert("XSS Vulnerability");</script>
          <text x="10" y="50">Malicious SVG</text>
        </svg>
        ```
    2. **Run the conversion script:** Execute the `convert.sh` script from the `/code/` directory:
        ```bash
        ./convert.sh
        ```
    3. **Locate the converted PNG:** The script will create a PNG file from the SVG in the `dist/brand/` directory. In this case, it will be `dist/brand/malicious.png`.
    4. **Serve the PNG (and ideally also try serving the SVG directly if possible within Matomo's context for a more direct test):** To fully demonstrate the XSS, you would need to integrate this `dist/brand/malicious.png` (or ideally test with the source `src/brand/malicious.svg` if Matomo's icon handling allows for direct SVG usage) into a Matomo instance.
    5. **Access Matomo in a browser:** Navigate to a Matomo page where icons from this repository are displayed. If the `malicious.png` (or `malicious.svg`) is used and rendered by Matomo without sanitization, the JavaScript `alert("XSS Vulnerability");` will be executed in your browser when the page is loaded, proving the XSS vulnerability. *Note: As the script converts to PNG, direct execution of Javascript from the PNG is unlikely unless Matomo's icon rendering process has unexpected SVG-in-PNG handling. The vulnerability is more directly exploitable if Matomo were to use the unsanitized source SVGs directly.*  For a more robust test in this setup, you would need to analyze how Matomo uses these icons and if it's possible to serve the *source SVG* to Matomo instead of the PNG to more directly trigger the XSS. If Matomo only uses the PNGs, the XSS risk from *this specific conversion script output* is lower, but the *source SVGs are still unsanitized*, and the overall project lacks SVG sanitization, which is a vulnerability if those SVGs are used directly elsewhere without sanitization.
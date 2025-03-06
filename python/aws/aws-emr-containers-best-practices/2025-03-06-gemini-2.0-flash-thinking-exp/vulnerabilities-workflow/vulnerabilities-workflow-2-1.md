### Vulnerability List

- Vulnerability Name: Cross-Site Scripting (XSS) vulnerability in Markdown documentation

- Description:
  1. A threat actor forks the repository.
  2. The threat actor modifies a markdown file (e.g., `/code/content/index.md`) and injects malicious Javascript code within the markdown content. For example, they could add a script tag like `<script>alert("XSS Vulnerability");</script>` or `<img src="x" onerror="alert('XSS')">`.
  3. The threat actor creates a pull request with these malicious changes.
  4. If a repository administrator merges the pull request without proper review and sanitization, the malicious Javascript code becomes part of the website's source code after the documentation website is built and deployed using `mkdocs gh-deploy`.
  5. When users visit the published documentation website (e.g., via the "Live Docs" link in `/code/README.md`), their browsers execute the injected Javascript code.

- Impact:
  Successful XSS exploitation can lead to various impacts, including:
  - **Data theft:** The attacker can steal sensitive information like cookies, session tokens, or user data from the browsers of website visitors.
  - **Account hijacking:** The attacker can potentially hijack user accounts if authentication tokens are exposed or manipulated.
  - **Malware distribution:** The attacker can redirect users to malicious websites or inject malware into the documentation website.
  - **Defacement:** The attacker can modify the content of the documentation website, leading to misinformation or reputational damage.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
  - None. The project does not currently implement any automated sanitization or security checks for markdown content. The `CONTRIBUTING.md` file encourages contributors to focus on specific changes, but this is not a technical mitigation for XSS.

- Missing Mitigations:
  - **Content Security Policy (CSP):** Implementing a CSP header can restrict the sources from which the browser is allowed to load resources, significantly reducing the risk and impact of XSS attacks.
  - **Markdown Sanitization:** Integrating a markdown sanitization library into the MkDocs build process to automatically remove or neutralize potentially malicious HTML tags and Javascript code from the markdown content before website generation.
  - **Pull Request Review Process with Security Focus:** Establishing a rigorous pull request review process that includes security considerations, specifically looking for and sanitizing any potentially malicious content in markdown files. This should include manual inspection of all changes to markdown files for unexpected or suspicious code.

- Preconditions:
  - An attacker needs to be able to create a pull request to the repository.
  - A repository administrator needs to merge the pull request containing the malicious markdown content.
  - The documentation website needs to be rebuilt and deployed after merging the malicious pull request for the XSS vulnerability to become live.
  - Users need to visit the affected page on the published documentation website.

- Source Code Analysis:
  - The project uses MkDocs to build the website from markdown files, as indicated in `/code/README.md` and `mkdocs.yml`.
  - MkDocs, by default, renders markdown to HTML. Without specific sanitization configurations, it is vulnerable to XSS if malicious HTML or Javascript is included in the markdown source.
  - Examining the files, especially under `/code/content/`, reveals numerous markdown files (`.md`) that form the documentation content. Any of these files can be an injection point.
  - There is no code within the project files that suggests any form of markdown sanitization or CSP implementation. The focus is on documentation content and best practices for EMR on EKS, not website security.

- Security Test Case:
  1. Fork the repository to your personal GitHub account.
  2. Navigate to `/code/content/index.md` in your forked repository.
  3. Edit the `index.md` file and add the following malicious Javascript code at the end of the file:
     ```markdown
     <script>alert("XSS Vulnerability");</script>
     ```
  4. Commit the changes to your forked repository.
  5. Create a pull request from your forked repository to the main repository's `main` branch.
  6. Wait for the pull request to be merged by a repository administrator (for testing purposes, if you have admin rights, you can merge it yourself).
  7. After the pull request is merged, manually trigger the website deployment process by running `mkdocs gh-deploy` locally if you have the environment set up, or wait for the automated deployment process if configured for the repository.
  8. Once the website is deployed, access the live documentation website, specifically the index page (or the page you modified).
  9. Verify if an alert box with the message "XSS Vulnerability" appears in your browser. If the alert box appears, the XSS vulnerability is confirmed.
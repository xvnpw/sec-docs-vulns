### Vulnerability List

#### Vulnerability Name: Path Traversal in Output Filename Generation
* Description:
    * The Corpus Crawler application allows users to specify the output directory and language for the crawled corpus via command-line arguments.
    * The application uses the language parameter to construct the output filename without proper sanitization.
    * An attacker can craft a malicious language string containing path traversal characters (e.g., `../`, `..\\`) and pass it as the `--language` argument.
    * When the crawler processes a website and attempts to save the crawled content, the application uses the attacker-controlled language string to construct the output filename.
    * Due to the lack of sanitization, the path traversal characters are interpreted by the operating system, allowing the attacker to control the output file path.
    * This can lead to writing crawled content to arbitrary locations on the user's file system, potentially overwriting sensitive files or writing data to unexpected locations.
* Impact:
    * High: An attacker can write arbitrary content to arbitrary files on the user's system. This can lead to:
        * Overwriting system files, potentially causing system instability or denial of service.
        * Overwriting user data, leading to data loss or corruption.
        * Writing malicious scripts (e.g., to startup folders) for potential further compromise.
* Vulnerability Rank: High
* Currently Implemented Mitigations:
    * None. The code does not perform any sanitization or validation of the language parameter before constructing the output filename.
* Missing Mitigations:
    * Input Sanitization: The application should sanitize the `language` parameter to remove or escape any path traversal characters before using it to construct the output filename.
    * Path Validation: The application should validate the constructed output path to ensure it remains within the intended output directory.
    * Principle of Least Privilege: The application should run with minimal permissions necessary to perform its function, limiting the impact of a successful path traversal exploit.
* Preconditions:
    * The user must execute the Corpus Crawler application.
    * The user must specify a malicious language parameter via the `--language` command-line argument.
* Source Code Analysis:
    * File: `/code/Lib/corpuscrawler/util.py`
    * Function: `Crawler.get_output(self, language=None)`
    * Line: `outpath = os.path.join(self.output_dir, language + '.txt')`
    * Visualization:
        ```
        [User Input: language] --> [String Concatenation: language + '.txt'] --> [os.path.join] --> [outpath]
        ```
    * Step-by-step analysis:
        * The `get_output` function takes an optional `language` argument. If not provided, it defaults to `self.language`.
        * The `outpath` is constructed using `os.path.join`, which is designed to handle path components but does not prevent path traversal if malicious components are already present in the input `language` string.
        * The `language` variable, derived from user-controlled input, is directly used in `os.path.join` without any sanitization.
        * This allows an attacker to inject path traversal sequences like `../` within the language string, leading to writing files outside the intended output directory.
* Security Test Case:
    1. Assume the Corpus Crawler is installed and runnable.
    2. Open a terminal and navigate to the Corpus Crawler's directory.
    3. Execute the crawler with a malicious language parameter and output directory:
        ```bash
        ./corpuscrawler --language="../evil_corpus" --output="./corpus" --language=yo
        ```
    4. After the crawler finishes, check the parent directory (`./`) for a file named `evil_corpus.txt`.
    5. If the file `evil_corpus.txt` is created in the parent directory, the path traversal vulnerability is confirmed.
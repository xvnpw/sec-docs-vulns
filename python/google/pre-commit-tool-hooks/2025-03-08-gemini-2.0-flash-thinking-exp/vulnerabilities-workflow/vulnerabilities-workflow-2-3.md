- vulnerability name: Path Traversal in `check-links` hook
- description:
    - A developer adds a malicious markdown file to their local repository.
    - This malicious markdown file contains a crafted link with a path traversal payload, such as `[malicious link](/../../../../evil.md)`.
    - The developer attempts to commit the changes, triggering the `check-links` pre-commit hook.
    - The `check-links` hook parses the malicious markdown file and extracts the crafted link.
    - The hook constructs the destination path for the link by joining the repository root path with the path from the link. Due to insufficient validation, the path traversal payload is not neutralized.
    - The hook checks if the constructed destination path exists using `dest_path.is_file()`.
    - If the attacker crafts the path to point to an existing file on the developer's machine, the `is_file()` check will succeed, even if the file is outside the repository.
    - This path traversal allows the pre-commit hook to access and potentially read files outside the intended repository directory during link validation.
- impact: An attacker can craft a malicious markdown file that, when processed by the `check-links` pre-commit hook on a developer's machine, can lead to unauthorized file access. While the hook itself might not directly expose the file content, it demonstrates a path traversal vulnerability that could be further exploited or used as a stepping stone for more severe attacks if the hook were to perform other operations on the accessed file.
- vulnerability rank: medium
- currently implemented mitigations: None. The code constructs the path without sanitization.
- missing mitigations: Input validation and sanitization for the link paths. The `check-links` hook should validate and sanitize the destination paths in links to prevent path traversal attacks. Specifically, it should ensure that the resolved path stays within the repository directory.
- preconditions:
    - A developer has installed the `pre-commit-tool-hooks` and configured the `check-links` hook in their local repository.
    - The developer attempts to commit changes that include a malicious markdown file with a path traversal link.
- source code analysis: In `pre_commit_hooks/check_links.py`, the `_check_links` function constructs the destination path using `repo_root.joinpath(dest_url.path.lstrip("/"))` for absolute paths and `absolute_path.parent.joinpath(url_path)` for relative paths. It does not perform any validation to ensure that the resolved path stays within the repository directory.
    ```python
    def _check_links(
        link_cache: LinkCache, repo_root: Path, path: str, anchors_only: bool
    ) -> bool:
        ...
        for link in links:
            dest_url = parse.urlsplit(link.destination)
            ...
            elif dest_url.path:
                if not anchors_only:
                    url_path = Path(dest_url.path)
                    if url_path.is_absolute():
                        # Absolute paths are actually relative to the repo root.
                        dest_path = repo_root.joinpath(dest_url.path.lstrip("/")) # Potential path traversal
                    else:
                        # Relative paths are relative to the current file's dir.
                        dest_path = absolute_path.parent.joinpath(url_path)
                    ...
                    if not dest_path.is_file(): # Checks if file exists, but after path traversal
                        _print_error(
                            path, link, "Link points at a non-existent file."
                        )
                        has_errors = True
                        continue
                    ...
    ```
- security test case:
    - Create a new directory to simulate a git repository.
    - Initialize a git repository in this directory using `git init`.
    - Create a `.pre-commit-config.yaml` file with the following content to enable the `check-links` hook:
    ```yaml
    repos:
    -   repo: https://github.com/google/pre-commit-tool-hooks
        rev: main # or any specific rev
        hooks:
        -   id: check-links
    ```
    - Install the pre-commit hooks using `pre-commit install`.
    - Create a malicious markdown file named `malicious.md` with the following content:
    ```markdown
    [malicious link](/../../../../tmp/test_file)
    ```
    Assume that file `/tmp/test_file` exists on the system. Create it using `touch /tmp/test_file`.
    - Add and commit the `malicious.md` file using `git add malicious.md` and `git commit -m "Add malicious markdown file"`.
    - Observe that the pre-commit hook `check-links` executes without errors, indicating that it successfully accessed `/tmp/test_file` due to path traversal.
    - To verify the vulnerability, modify the `check_links.py` script to print the `dest_path` before the `dest_path.is_file()` check.
    ```python
                    if not dest_path.is_file():
                        print(f"dest_path: {dest_path}") # Add this line for debugging
                        _print_error(
                            path, link, "Link points at a non-existent file."
                        )
                        has_errors = True
                        continue
    ```
    - Re-run the commit with the modified `check_links.py`. Observe in the output the `dest_path` being resolved to a path outside the repository, such as `/tmp/test_file`, confirming the path traversal vulnerability.
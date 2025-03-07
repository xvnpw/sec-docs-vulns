### Vulnerability List

- Vulnerability Name: Command Injection via `baseurl` in Hugo Builds
- Description:
    - An attacker can inject arbitrary commands into the build container by providing a malicious `baseurl` build argument when the site generator is set to `hugo`.
    - Step 1: The attacker crafts a malicious JSON payload for the build parameters, setting the `generator` to `hugo` and including a command injection payload within the `baseurl` parameter. For example, the `baseurl` could be set to `\"; touch /tmp/pwned; \"`.
    - Step 2: The attacker initiates a site build using this malicious JSON payload, either by providing it as a JSON string via the `-p` or `--params` flag, or as a JSON file via the `-f` or `--file` flag when running `main.py`.
    - Step 3: The `main.py` script parses the parameters and calls the `build()` function in `build.py` with these parameters.
    - Step 4: Inside `build()`, the code checks if the `generator` is `hugo`. If so, it calls the `build_hugo()` function.
    - Step 5: Within `build_hugo()`, the `baseurl` parameter, without proper sanitization, is incorporated into the `hugo_args` string using an f-string: `hugo_args += f' --baseURL {base_url}'`.
    - Step 6: This `hugo_args` string, now containing the injected command, is executed by the `run()` function in `src/runner/__init__.py` using `shell=True` because `node=True` is passed in the call.
    - Step 7: The shell interprets the injected command within `baseurl`, executes it, and in this example, creates a file named `pwned` in the `/tmp/` directory of the build container.
- Impact:
    - Critical. Successful command injection allows the attacker to execute arbitrary commands within the build container. This grants them full control over the container environment.
    - Potential impacts include:
        - Data exfiltration: Sensitive data within the build container or accessible AWS resources could be stolen.
        - Infrastructure compromise: The attacker could potentially pivot from the build container to compromise other parts of the cloud.gov Pages infrastructure.
        - Denial of Service: The attacker could disrupt the build process or the entire service.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations:
    - None. There is no input sanitization for the `baseurl` parameter before it is used in the Hugo command execution within the `build_hugo` function. While some parameters like `branch`, `owner`, and `repository` are quoted using `shlex.quote()` in `main.py`, `baseurl` is not.
- Missing Mitigations:
    - Input sanitization for the `baseurl` parameter is missing. Shell metacharacters within `baseurl` should be escaped or removed before constructing the Hugo command.
    - Alternatively, the code could avoid using `shell=True` when executing Hugo commands. Using the list form of arguments for `subprocess.Popen` would prevent shell interpretation of metacharacters.
- Preconditions:
    - The `generator` build argument must be set to `hugo`.
    - The attacker must be able to control the `baseurl` build argument. This is possible by crafting a malicious JSON payload for the `-p` or `-f` options when running the `main.py` script.
- Source Code Analysis:
    - File: `/code/src/main.py`
        ```python
        if __name__ == "__main__":
            # ...
            build(**kwargs)
        ```
        - The `main` function in `main.py` parses arguments and calls the `build` function in `build.py`. The `baseurl` parameter from user input is passed directly to the `build` function as part of `kwargs`.
    - File: `/code/src/build.py`
        ```python
        def build(
            # ...
            baseurl,
            generator,
            # ...
        ):
            # ...
            if generator == 'hugo':
                run_step(
                    build_hugo,
                    'There was a problem running Hugo, see the above logs for details.',
                    branch, owner, repository, site_prefix, baseurl, decrypted_uevs,
                )
            # ...

        def build_hugo(branch, owner, repository, site_prefix,
                   base_url='', user_env_vars=[]):
            # ...
            hugo_args = f'--source {CLONE_DIR_PATH} --destination {SITE_BUILD_DIR_PATH}'
            if base_url:
                hugo_args += f' --baseURL {base_url}'

            env = build_env(branch, owner, repository, site_prefix, base_url, user_env_vars)
            run(logger, f'{HUGO_BIN_PATH} {hugo_args}', cwd=CLONE_DIR_PATH, env=env, node=True)
        ```
        - The `build` function calls `build_hugo` when the generator is `hugo`.
        - In `build_hugo`, the `baseurl` parameter is directly embedded into the `hugo_args` string using an f-string without any sanitization.
        - The `run` function is called with `node=True`, which leads to `shell=True` execution.
    - File: `/code/src/runner/__init__.py`
        ```python
        def run(logger, command, cwd=None, env=None, shell=False, check=True, node=False, ruby=False, skip_log=False):  # noqa: E501
            # ...
            if ruby:
                command = f'source {RVM_PATH} && {command}'
                shell = True

            if node:
                command = f'source {NVM_PATH} && {command}'
                shell = True
            # ...
            p = subprocess.Popen(  # nosec
                command,
                cwd=cwd,
                env=env,
                shell=shell,
                executable=executable,
                stderr=subprocess.STDOUT,
                stdout=subprocess.PIPE,
                bufsize=1,
                encoding='utf-8',
                text=True,
                preexec_fn=setuser
            )
            # ...
        ```
        - The `run` function executes commands using `subprocess.Popen` with `shell=True` if `node=True` or `ruby=True`. This allows shell command injection if the `command` string is not properly sanitized.
- Security Test Case:
    - Step 1: Create a file named `exploit.json` in the `.local` directory (or any `/tmp/local` mounted directory if running with docker-compose) with the following JSON content:
        ```json
        {
          "aws_access_key_id": "dummy",
          "aws_secret_access_key": "dummy",
          "aws_default_region": "us-gov-west-1",
          "bucket": "dummy",
          "status_callback": "http://localhost:8989/status",
          "generator": "hugo",
          "owner": "cloud-gov",
          "repository": "pages-build-container",
          "branch": "main",
          "site_prefix": "test-site",
          "baseurl": "\"; touch /tmp/pwned; \""
        }
        ```
    - Step 2: Run the build container using docker-compose with the malicious JSON file as input:
        ```bash
        docker-compose run --rm app python main.py -f /tmp/local/exploit.json
        ```
    - Step 3: After the build container finishes (it might fail, but that's expected), access the shell of the running `app` container to verify command execution:
        ```bash
        docker-compose run --rm app bash
        ```
    - Step 4: Inside the container's shell, check if the file `/tmp/pwned` exists:
        ```bash
        ls /tmp/pwned
        ```
        - If a file named `pwned` is listed in `/tmp/`, it confirms that the command injection vulnerability via the `baseurl` parameter in Hugo builds is present.
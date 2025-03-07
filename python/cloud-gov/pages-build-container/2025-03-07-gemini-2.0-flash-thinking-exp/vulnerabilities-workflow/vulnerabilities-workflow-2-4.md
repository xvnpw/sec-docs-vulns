### Vulnerability 1: Hugo BaseURL Command Injection

* Description:
    1. A malicious actor can manipulate the `baseurl` parameter in the build arguments.
    2. The `main.py` script decrypts and passes these parameters to the `build` function in `build.py`.
    3. The `build` function then calls `build_hugo` in `steps/build.py`, passing the `baseurl` parameter.
    4. In `build_hugo`, the `baseurl` is directly embedded into the `hugo` command string without proper sanitization or quoting.
    5. When the `hugo` command is executed using `runner.run`, a command injection vulnerability occurs because the malicious `baseurl` can inject arbitrary commands into the `hugo` execution.

* Impact:
    - **Critical**
    - Successful command injection allows arbitrary command execution on the build container.
    - An attacker can gain full control of the build container, potentially leading to data exfiltration, further attacks on the infrastructure, or denial of service.

* Vulnerability Rank: Critical

* Currently implemented mitigations:
    - None. The `baseurl` parameter is taken directly from the decrypted parameters and used in the command execution without any sanitization or quoting in `build_hugo` function in `/code/src/steps/build.py`.

* Missing mitigations:
    - Sanitize or quote the `baseurl` parameter before embedding it into the `hugo` command in the `build_hugo` function in `/code/src/steps/build.py`. Use `shlex.quote` to properly escape the `baseurl` parameter before command execution.

* Preconditions:
    - The target site must be configured to use the `hugo` generator.
    - An attacker needs to be able to modify the `baseurl` parameter in the build arguments. This can be achieved by compromising the GitHub repository of the target site and modifying the site's configuration file (e.g., `federalist.json` or `pages.json`) to trigger a new build with malicious `baseurl`.

* Source code analysis:
    - File: `/code/src/main.py`
        ```python
        if __name__ == "__main__":
            # ...
            if args.params:
                params = json.loads(args.params)
                params = decrypt_params(params)
            else:
                params = json.load(args.file)

            params = {k.lower(): v for (k, v) in params.items()}

            build_arguments = inspect.getfullargspec(build)[0]
            # ...
            kwargs = {k: v for (k, v) in params.items() if k in build_arguments}
            # ...
            kwargs['branch'] = shlex.quote(kwargs['branch'])
            kwargs['owner'] = shlex.quote(kwargs['owner'])
            kwargs['repository'] = shlex.quote(kwargs['repository'])
            # baseurl is NOT quoted here
            build(**kwargs)
        ```
    - File: `/code/src/build.py`
        ```python
        from steps import (
            build_hugo, # ...
        )
        def build(
            # ...
            baseurl, # ...
            generator, # ...
        ):
            # ...
            elif generator == 'hugo':
                run_step(
                    build_hugo,
                    'There was a problem running Hugo, see the above logs for details.',
                    branch, owner, repository, site_prefix, baseurl, decrypted_uevs,
                )
        ```
    - File: `/code/src/steps/build.py`
        ```python
        def build_hugo(branch, owner, repository, site_prefix,
                   base_url='', user_env_vars=[]):
            '''
            Builds the cloned site with Hugo
            '''
            logger = get_logger('build-hugo')
            # ...
            hugo_args = f'--source {CLONE_DIR_PATH} --destination {SITE_BUILD_DIR_PATH}'
            if base_url:
                # Command Injection Vulnerability: base_url is directly embedded without quoting
                hugo_args += f' --baseURL {base_url}'

            env = build_env(branch, owner, repository, site_prefix, base_url, user_env_vars)
            run(logger, f'{HUGO_BIN_PATH} {hugo_args}', cwd=CLONE_DIR_PATH, env=env, node=True)
        ```
        Visualization:
        ```mermaid
        graph LR
            A[main.py: params] --> B(build(**kwargs))
            B --> C[build.py: build_hugo(baseurl)]
            C --> D[steps/build.py: hugo_args += f' --baseURL {base_url}']
            D --> E[steps/build.py: run(f'{HUGO_BIN_PATH} {hugo_args}')]
            E --> F[Command Injection]
        ```

* Security test case:
    1. Set up a local development environment using `docker-compose`.
    2. Create a malicious build parameter JSON file (e.g., `.local/my-build.json`) with a crafted `baseurl` to execute a command. For example:
        ```json
        {
          "aws_access_key_id": "dummy",
          "aws_secret_access_key": "dummy",
          "aws_default_region": "us-gov-west-1",
          "bucket": "dummy",
          "status_callback": "http://localhost:8989/status",
          "generator": "hugo",
          "owner": "test",
          "repository": "test-site",
          "branch": "main",
          "site_prefix": "test-site",
          "baseurl": "\"; touch /tmp/pwned; #",
          "user_environment_variables": []
        }
        ```
        The malicious `baseurl` is `\"; touch /tmp/pwned; #`. This is designed to inject the command `touch /tmp/pwned`. The `#` comments out the rest of the intended `baseurl` value, preventing Hugo from misinterpreting it.
    3. Run the build container with the malicious parameters:
        ```sh
        docker-compose run --rm app python main.py -f /tmp/local/my-build.json
        ```
    4. After the build process completes (either successfully or with an error due to Hugo failing because of the modified baseURL), execute the following command inside the running `app` container to check if the file `/tmp/pwned` was created:
        ```sh
        docker-compose run --rm app bash
        ls /tmp/pwned
        ```
    5. If the file `/tmp/pwned` exists, it confirms that the command injection was successful, and arbitrary commands could be executed via the `baseurl` parameter.
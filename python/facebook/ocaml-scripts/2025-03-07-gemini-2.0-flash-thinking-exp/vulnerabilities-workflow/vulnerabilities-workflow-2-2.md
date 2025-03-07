### Vulnerability List

* Vulnerability Name: **Malicious Package Installation via JSON Configuration**
* Description:
    1. An attacker crafts a malicious JSON configuration file.
    2. This malicious JSON file contains an array of `packages` with names of backdoored opam packages or packages from malicious opam repositories.
    3. The attacker entices a user to run `dromedary.py` with the malicious JSON file as input using the command: `python3 dromedary.py -o BUCK_PATH MALICIOUS_JSON_CONFIG`.
    4. `dromedary.py` parses the JSON configuration file, extracts the package list, and uses `opam install` command to install these packages in a newly created opam switch.
    5. If the malicious packages exist in the configured opam repositories, `opam install` will download and install them.
    6. During the installation process of these malicious packages, any malicious install scripts embedded within them will be executed with the user's privileges.
* Impact: Arbitrary code execution on the user's machine, potentially leading to full system compromise. This can be used for supply chain attacks by backdooring development environments.
* Vulnerability Rank: **Critical**
* Currently Implemented Mitigations: None. The project provides no input validation or sanitization for the JSON configuration file or the package names. The `README.md` contains a general disclaimer that the scripts are a work in progress.
* Missing Mitigations:
    * **JSON Schema Validation**: Implement validation of the JSON configuration file against a predefined schema to ensure the structure and data types are as expected.
    * **Package Name Validation**: Implement a mechanism to validate package names against a whitelist of trusted packages or known repositories. This is complex for opam due to its dynamic nature, but warnings about installing packages from untrusted sources are crucial.
    * **Input Sanitization**: Sanitize package names before passing them to the `opam install` command to prevent potential command injection vulnerabilities (although `opam` itself should handle basic cases, sanitization is still a good practice).
    * **User Warnings**: Display clear warnings to the user when `dromedary.py` is run with a JSON configuration file, emphasizing the security risks of using untrusted configurations and installing packages from potentially unknown sources.
* Preconditions:
    * The attacker needs to create a malicious JSON configuration file.
    * The attacker needs to convince a user to download and execute `dromedary.py` with this malicious JSON file.
    * The malicious packages specified in the JSON must be available in opam repositories configured on the user's system, or the attacker needs to trick the user into adding a malicious opam repository.
* Source Code Analysis:
    1. In `dromedary.py`, the `read_json(config_file)` function reads the JSON file specified by the user.
    ```python
    def read_json(path: str) -> Dict[str, Any]:
        try:
            with open(path, "rt", encoding="utf-8") as file:
                switch_config = json.load(file) # Line where JSON is parsed
        except FileNotFoundError as exc:
            # ... error handling ...
        except json.decoder.JSONDecodeError as exc:
            # ... error handling ...
        except Exception as exc:
            # ... error handling ...

        return switch_config
    ```
    2. The `validate_config` function performs minimal validation, primarily checking for the presence of "packages" and "compiler" keys and setting default values:
    ```python
    def validate_config(switch_config: Dict[str, Any], json_path: str) -> SwitchConfig:
        # ... (code to get switch_packages, switch_name, switch_compiler from switch_config) ...

        switch_packages = switch_config.get("packages")
        if switch_packages is None: # Check if "packages" key exists
            # ... error handling ...

        # ... (rest of validation logic, mostly setting defaults) ...

        return SwitchConfig(
            name=switch_name, compiler=switch_compiler, packages=switch_packages
        )
    ```
    3. The `install_packages` function directly uses the `packages` list from the validated configuration and executes `opam install` with these packages:
    ```python
    def install_packages(packages: List[str], cmd_env: Dict[str, str]) -> None:
        """Install the packages given in `switch_config["packages"]`.

        Uses the Opam environment `cmd_env`.
        """
        print(f"Installing packages '{packages}'")
        inst_args = OPAM_INSTALL_COMMAND # OPAM_INSTALL_COMMAND = [OPAM_EXE, "install", "--yes"]
        inst_args.extend(packages) # Packages from JSON are directly added here
        run_cmd_output(inst_args, cmd_env=cmd_env) # Command execution
    ```
    There is no validation or sanitization of the `packages` list between reading the JSON and executing the `opam install` command.
* Security Test Case:
    1. Create a file named `malicious_config.json` with the following content. Replace `malicious-package-name` with a placeholder for a malicious package name. In a real test, you would need to set up a local opam repository serving a package with this name and malicious install scripts. For demonstration, we assume a package named `pcre-malicious` exists in a reachable opam repository and contains malicious install scripts.
    ```json
    {
        "name": "./malicious_switch",
        "compiler": "ocaml-base-compiler",
        "packages": [
            "ocamlfind",
            "pcre-malicious"
        ]
    }
    ```
    2. Run `dromedary.py` with the malicious configuration file, specifying an output BUCK file path:
    ```bash
    python3 dromedary.py -o malicious_buck_file malicious_config.json
    ```
    3. Observe the output of `dromedary.py`. It should indicate that an opam switch named `./malicious_switch` is being created, and packages `['ocamlfind', 'pcre-malicious']` are being installed.
    4. If a package named `pcre-malicious` (or your chosen malicious package name) exists and contains malicious install scripts, these scripts will be executed during the `opam install` step. The exact malicious behavior depends on the content of the `pcre-malicious` package's install scripts. To verify code execution, the malicious install script could, for example, create a file in the user's temporary directory or print a specific message.
    5. After running the test, check for the expected malicious behavior to confirm the vulnerability. For example, check if the file created by the malicious install script exists or if the expected message was printed.

---

* Vulnerability Name: **Malicious BUCK File Generation Leading to Build-Time Code Execution**
* Description:
    1. Building upon the previous vulnerability, an attacker can further compromise the build process. After enticing a user to use a malicious JSON (as described above), the generated BUCK file can be indirectly compromised.
    2. If a malicious opam package, installed via the malicious JSON, is crafted to manipulate its metadata (e.g., by placing malicious binaries or libraries in locations where `ocamlfind` or the build process expects legitimate files), `meta2json.py` will extract this manipulated metadata.
    3. `meta2json.py` generates an intermediate JSON file containing package information, including paths to libraries, executables, and C libraries. This JSON file will now contain paths to the attacker's malicious files due to the manipulated metadata from the malicious package.
    4. `rules.py` processes this compromised JSON file to generate a BUCK file.
    5. The generated BUCK file will contain `prebuilt_ocaml_library` and other rules that reference the malicious files (libraries, executables) because `rules.py` blindly trusts the paths provided in the JSON.
    6. When a developer builds a target using this generated BUCK file with Buck, Buck will use the malicious libraries or executables during the build process, leading to code execution on the developer's machine during the build.
* Impact: Arbitrary code execution on the developer's machine during the build process. This can lead to compromised builds, exfiltration of secrets, or further propagation of the attack within the development environment or to end users if malicious artifacts are included in releases.
* Vulnerability Rank: **High**
* Currently Implemented Mitigations: None. The scripts assume that the opam switch and package information are trustworthy.
* Missing Mitigations:
    * **Data Validation in `rules.py`**: Implement validation in `rules.py` to check the paths extracted from the JSON file before generating BUCK rules. This could include verifying that paths are within expected opam switch directories or checking file types and signatures (though this is complex).
    * **Principle of Least Privilege for Build Processes**: Encourage users to run Buck build processes with minimal privileges to limit the impact of potential build-time code execution.
    * **Input Sanitization and Validation for JSON Data**: While `meta2json.py` collects data, `rules.py` should not blindly trust this data. Validate critical paths and data used to generate build rules.
    * **User Warnings**:  Warn users about the risks associated with generating BUCK files from potentially untrusted opam switches or JSON configurations.
* Preconditions:
    * The preconditions for "Malicious Package Installation via JSON Configuration" must be met first, meaning a malicious package must be installed in the opam switch.
    * The malicious package must be capable of manipulating metadata in a way that affects the JSON output of `meta2json.py` (e.g., by replacing legitimate files or altering `ocamlfind` output).
    * The user must then run `dromedary.py` (or `meta2json.py` and `rules.py` separately) to generate a BUCK file from this compromised opam switch.
    * Finally, the user must build a target using the generated BUCK file with Buck.
* Source Code Analysis:
    1. `meta2json.py` extracts information using `ocamlfind` commands and functions like `package_directory`, `archive`, `plugin`, etc. For example, `package_directory` calls `ocamlfind_query` which executes `ocamlfind query -format "%d" libname`. If a malicious package influences the output of `ocamlfind`, the JSON will contain malicious paths.
    ```python
    def ocamlfind(cmd):
        query = ["ocamlfind"] + cmd
        process = Popen(query, stdout=PIPE) # Line where ocamlfind is executed
        (output, err) = process.communicate()
        exit_code = process.wait()
        if exit_code != 0:
            print("Invalid cmd: {}".format(str(cmd)), file=sys.stderr)
            return ""
        return output.decode("UTF-8").strip()

    def package_directory(libname):
        query = ["-format", "%d", libname]
        return ocamlfind_query(query)
    ```
    2. `rules.py` reads the JSON file and uses the paths directly to create BUCK rules, for example in `prebuilt_ocaml_library`:
    ```python
    def prebuilt_ocaml_library(
        # ... function parameters ...
        include_dir: str = None,
        native_lib: str = None,
        bytecode_lib: str = None,
        native_c_libs: List[str] = (),
        bytecode_c_libs: List[str] = (),
        deps: List[str] = (),
    ) -> None:
        # ... (setting default values and visibility) ...

        include_dir = self.add_prefix(include_dir) # Path from JSON used directly
        native_c_libs = self.map_prefix(native_c_libs) # Paths from JSON used directly
        bytecode_c_libs = self.map_prefix(bytecode_c_libs) # Paths from JSON used directly
        bytecode_lib = self.add_prefix(bytecode_lib) # Path from JSON used directly
        native_lib = self.add_prefix(native_lib) # Path from JSON used directly
        deps = [":{}".format(dep) for dep in deps]

        with open(self.output_file, "a") as fp:
            self._open(fp, 0, "prebuilt_ocaml_library")
            # ... (writing BUCK rules using the paths) ...
    ```
    `rules.py` uses the paths for `include_dir`, `native_lib`, `bytecode_lib`, `native_c_libs`, and `bytecode_c_libs` directly from the JSON without any validation, making it vulnerable if the JSON contains malicious paths.
* Security Test Case:
    1. This test case is more complex and builds upon the previous one.  For a practical demonstration, you would need to:
        a. Create a malicious opam package (e.g., `pcre-metadata-manipulator`). This package, upon installation, needs to be able to manipulate opam metadata or file system in a way that when `meta2json.py` is run, it picks up malicious paths. This is a non-trivial task and depends on the internal workings of opam and how packages can influence metadata. A simplified approach for demonstration is to *simulate* this metadata manipulation.
        b. Instead of creating a real malicious package, you could manually modify the JSON output of `meta2json.py` after running it on a switch containing a benign package.  For example, after running `python3 meta2json.py -o temp_data.json`, manually edit `temp_data.json` to replace the path to a legitimate library (e.g., in `native_lib` or `bytecode_lib` field of a package entry) with a path to a malicious executable or library you control (e.g., `/tmp/malicious_lib.so`).
        c. Create a simple malicious library or executable at the path you specified in the modified JSON (e.g., create `/tmp/malicious_lib.so` that executes some harmful code when loaded or executed).
    2. Run `dromedary.py` (or `rules.py` directly if you manually created `temp_data.json`):
    ```bash
    # If using dromedary.py, you might need to adapt it to use your modified JSON
    # For direct rules.py test, use:
    python3 rules.py -i temp_data.json -o MALICIOUS_BUCK -s /path/to/your/opam/switch -r opam
    ```
    3. Create a simple Buck build file (e.g., `BUCK`) that depends on one of the OCaml libraries defined in your `MALICIOUS_BUCK` file. For example, if you modified the `pcre` library entry in `temp_data.json`, create a BUCK file that depends on `:pcre`.
    4. Build the target using Buck:
    ```bash
    buck2 build //:your_target
    ```
    5. Observe if the malicious code from `/tmp/malicious_lib.so` (or your chosen malicious path) is executed during the Buck build process. The exact manifestation depends on what your malicious code does and how it's triggered when Buck uses the modified BUCK rules.  For example, if `/tmp/malicious_lib.so` is a shared library and you replaced a legitimate native library path with it, Buck might attempt to load it, and the malicious code within the library could execute.
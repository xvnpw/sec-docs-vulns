### Vulnerability List

*   #### Vulnerability Name: Command Injection in Osmjs Call

    *   **Description:**
        The `run.py` script executes the `osmjs` command using `subprocess.call` with `shell=True`. The command string is constructed using user-provided database connection parameters (`args.db_host`, `args.db_port`, `args.db_user`, `args.db_name`). Specifically, these arguments are incorporated into the `psql` command within the `osmjs` call. If a malicious user provides crafted input for these arguments, they can inject arbitrary shell commands that will be executed by the system.

        Steps to trigger the vulnerability:
        1.  The attacker crafts malicious input for one or more of the following command-line arguments: `-H` (db_host), `-p` (db_port), `-U` (db_user), `-d` (db_name).
        2.  The attacker executes the `run.py` script with the crafted arguments.
        3.  The script constructs the `osmjs` command string, embedding the malicious input.
        4.  `subprocess.call` with `shell=True` executes the command string, including the injected commands.

    *   **Impact:**
        Successful command injection can lead to arbitrary code execution on the server hosting the application. An attacker could gain full control of the server, read sensitive data, modify files, install malware, or pivot to other systems on the network. In this specific scenario, the attacker could gain control over the database server and potentially other connected systems if the application server has broader network access.

    *   **Vulnerability Rank:** critical

    *   **Currently Implemented Mitigations:**
        None. The script directly uses user-provided arguments in a shell command without any sanitization or validation.

    *   **Missing Mitigations:**
        *   **Input Sanitization/Validation:** Validate and sanitize all user-provided command-line arguments, especially those used in shell commands. For database connection parameters, restrict characters to alphanumeric and specific symbols if necessary.
        *   **Use `subprocess.call` with list format:** Avoid using `shell=True`. Instead, pass the command and its arguments as a list to `subprocess.call`. This prevents shell interpretation of metacharacters and reduces the risk of command injection.
        *   **Principle of Least Privilege:** Run the script and the PostgreSQL database server with the minimum necessary privileges to limit the impact of a successful attack.

    *   **Preconditions:**
        *   The attacker must have the ability to execute the `run.py` script with arbitrary command-line arguments. This is typically the case for users who can run the script directly or control input to a system that executes the script.

    *   **Source Code Analysis:**
        1.  The script takes database connection parameters as command-line arguments: `-H`, `-p`, `-U`, `-d`.
            ```python
            ap.add_argument('-H', dest='db_host', default='localhost',
                            help='PostgreSQL host.')
            ap.add_argument('-p', dest='db_port', default='5432',
                            help='PostgreSQL port.')
            ap.add_argument('-U', dest='db_user', default='postgres',
                            help='PostgreSQL user name.')
            ap.add_argument('-d', dest='db_name', default='osm',
                            help='PostgreSQL database.')
            ```
        2.  These arguments are directly incorporated into the `osmjs` command string using string formatting:
            ```python
            subprocess.call(['osmjs -l sparsetable -r -j process-boundaries.js {0} | psql -h {1} -p {2} -U {3} -d {4} > /dev/null'.format(
                outfile,
                args.db_host,
                args.db_port,
                args.db_user,
                args.db_name)],
            shell=True)
            ```
        3.  `shell=True` in `subprocess.call` allows shell command injection. If any of `args.db_host`, `args.db_port`, `args.db_user`, or `args.db_name` contain shell metacharacters, they will be interpreted by the shell, leading to command injection.
        4.  For example, if an attacker provides `-d "osm; touch /tmp/pwned"` as a command-line argument, the constructed command becomes:
            ```bash
            osmjs -l sparsetable -r -j process-boundaries.js osm_admin_2-4.osm.pbf | psql -h localhost -p 5432 -U postgres -d "osm; touch /tmp/pwned" > /dev/null
            ```
        5.  Due to `shell=True`, the shell will execute `osmjs ... | psql ... -d osm` and then execute the command `touch /tmp/pwned`.

    *   **Security Test Case:**
        1.  Set up a testing environment with PostgreSQL and PostGIS.
        2.  Prepare an OSM PBF file (e.g., a small extract).
        3.  Execute the `run.py` script with a malicious `-d` argument to inject a command. For example:
            ```bash
            python run.py -d "testdb; touch /tmp/pwned" data.osm.pbf
            ```
        4.  After running the script, check if the file `/tmp/pwned` exists on the system.
        5.  If `/tmp/pwned` exists, it confirms that the command injection was successful.

*   #### Vulnerability Name: Command Injection in Osmosis Call

    *   **Description:**
        Similar to the Osmjs command injection, the `run.py` script executes the `osmosis` command using `subprocess.call` with `shell=True`. The command string includes the user-provided input file path (`args.osm_input`). If a malicious user provides a crafted input for `args.osm_input`, they could inject arbitrary shell commands that will be executed by the system during the `osmosis` call.

        Steps to trigger the vulnerability:
        1.  The attacker crafts a malicious input for the `planet.osm.pbf` argument ( `args.osm_input`).
        2.  The attacker executes the `run.py` script with the crafted argument.
        3.  The script constructs the `osmosis` command string, embedding the malicious input.
        4.  `subprocess.call` with `shell=True` executes the command string, including the injected commands.

    *   **Impact:**
        Successful command injection in the `osmosis` call also leads to arbitrary code execution on the server, with the same potential impacts as described for the Osmjs command injection.

    *   **Vulnerability Rank:** critical

    *   **Currently Implemented Mitigations:**
        None. The script directly uses user-provided `args.osm_input` in a shell command without any sanitization or validation.

    *   **Missing Mitigations:**
        *   **Input Sanitization/Validation:** Validate and sanitize the `args.osm_input` argument. Check if the provided path is a valid file path and does not contain any malicious characters.
        *   **Use `subprocess.call` with list format:** Avoid using `shell=True`. Pass the command and its arguments as a list to `subprocess.call`.
        *   **Principle of Least Privilege:** Run the script with the minimum necessary privileges.

    *   **Preconditions:**
        *   The attacker must have the ability to execute the `run.py` script and provide a malicious file path as a command-line argument.

    *   **Source Code Analysis:**
        1.  The script takes the input OSM PBF file path as a command-line argument: `args.osm_input`.
            ```python
            ap.add_argument(dest='osm_input', metavar='planet.osm.pbf',
                            help='An OpenStreetMap PBF file to process.')
            ```
        2.  This argument is directly incorporated into the `osmosis` command string using string formatting:
            ```python
            subprocess.call(['''osmosis \
                --read-pbf {0} \
                --tf accept-relations admin_level={1} \
                ...'''.format(
                    args.osm_input,
                    admin_levels,
                    outfile)],
                shell=True)
            ```
        3.  `shell=True` in `subprocess.call` allows shell command injection. If `args.osm_input` contains shell metacharacters, they will be interpreted by the shell.
        4.  For example, if an attacker provides `planet.osm.pbf; touch /tmp/pwned` as `args.osm_input`, the constructed command becomes:
            ```bash
            osmosis --read-pbf planet.osm.pbf; touch /tmp/pwned --tf accept-relations admin_level=2,3,4 --tf accept-relations boundary=administrative --used-way --used-node --write-pbf osm_admin_2-4.osm.pbf
            ```
        5.  Due to `shell=True`, the shell will execute `osmosis --read-pbf planet.osm.pbf` and then execute the command `touch /tmp/pwned`.

    *   **Security Test Case:**
        1.  Set up a testing environment. Osmosis is required for this test case.
        2.  Execute the `run.py` script with a malicious `osm_input` argument to inject a command. For example:
            ```bash
            python run.py planet.osm.pbf"; touch /tmp/pwned; echo "
            ```
        3.  After running the script, check if the file `/tmp/pwned` exists on the system.
        4.  If `/tmp/pwned` exists, it confirms that the command injection was successful.
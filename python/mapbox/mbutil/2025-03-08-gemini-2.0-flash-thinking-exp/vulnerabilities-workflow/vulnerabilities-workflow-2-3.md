- Vulnerability Name: Path Traversal in `mbtiles_to_disk` output directory

- Description:
  1. The `mb-util` tool allows exporting MBTiles files to a directory using the `mbtiles_to_disk` function.
  2. The output directory is provided as a command-line argument and is used directly in file path construction within the `mbtiles_to_disk` function.
  3. An attacker can provide a malicious output directory path, such as `output/../../../evil_dir`, containing path traversal sequences (`..`).
  4. When `mbtiles_to_disk` processes the MBTiles file, it creates directories and files based on tile coordinates within the attacker-controlled output directory path.
  5. Due to the lack of path sanitization, the path traversal sequences are not removed, leading to files being written outside the intended output directory and potentially overwriting or creating files in arbitrary locations on the file system.

- Impact:
  - **High:** An attacker can write files to arbitrary locations on the file system where the user running `mb-util` has write permissions. This could lead to:
    - **Data manipulation:** Overwriting critical system files or application configuration files, leading to application malfunction or security breaches.
    - **Code execution:** Writing malicious scripts (e.g., in web server document roots or cron job directories) that could be executed by the system, leading to remote code execution.
    - **Information disclosure:** In certain scenarios, an attacker might be able to create symbolic links to sensitive files, although direct information disclosure is less likely with file writing.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
  - None. The code directly uses the user-provided `directory_path` without any sanitization or validation.

- Missing Mitigations:
  - **Input sanitization:** The `directory_path` should be sanitized to remove path traversal sequences (e.g., `..`) or restrict the output directory to a safe location.
  - **Path normalization:** Use `os.path.abspath` and `os.path.normpath` to normalize the output path and resolve any symbolic links or relative path components before creating directories and files.
  - **Output directory validation:** Validate that the resolved output directory is within an expected or allowed path, although in this case, the user is intended to specify the output directory.  At minimum, prevent path traversal to locations outside the intended user-specified output base directory.

- Preconditions:
  - The attacker needs to be able to execute the `mb-util` command with arbitrary arguments, specifically controlling the output directory path. This is typically the case for command-line utilities.
  - The user running `mb-util` must have write permissions to the locations targeted by the path traversal.

- Source Code Analysis:
  - The vulnerability is located in the `mbtiles_to_disk` function in `/code/mbutil/util.py`.
  - The relevant code snippet is within the tile exporting loop:

    ```python
    def mbtiles_to_disk(mbtiles_file, directory_path, **kwargs):
        # ...
        os.mkdir("%s" % directory_path) # Vulnerable mkdir
        # ...
        base_path = directory_path # Vulnerable base_path
        if not os.path.isdir(base_path):
            os.makedirs(base_path) # Redundant and still vulnerable
        # ...
        while t:
            # ...
            if kwargs.get('scheme') == 'xyz':
                y = flip_y(z,y)
                if not silent:
                    logger.debug('flipping')
                tile_dir = os.path.join(base_path, str(z), str(x)) # Vulnerable path join
            # ...
            else:
                tile_dir = os.path.join(base_path, str(z), str(x)) # Vulnerable path join
            if not os.path.isdir(tile_dir):
                os.makedirs(tile_dir) # Vulnerable makedirs
            if kwargs.get('scheme') == 'wms':
                tile = os.path.join(tile_dir,'%03d.%s' % (int(y) % 1000, kwargs.get('format', 'png'))) # Vulnerable path join
            else:
                tile = os.path.join(tile_dir,'%s.%s' % (y, kwargs.get('format', 'png'))) # Vulnerable path join
            f = open(tile, 'wb') # Vulnerable file open
            f.write(t[3])
            f.close()
            # ...
    ```

  - **Visualization:**

    ```
    mbtiles_to_disk (mbtiles_file, directory_path, ...)
    │
    ├── os.mkdir(directory_path)  <-- Creates initial output directory (Vulnerable)
    │
    └── base_path = directory_path <-- User-controlled path is directly assigned
        │
        ├── tile_dir = os.path.join(base_path, str(z), str(x)) <-- Path traversal via base_path
        │   │
        │   └── os.makedirs(tile_dir) <-- Creates tile subdirectories (Vulnerable)
        │   │
        │   └── tile = os.path.join(tile_dir, ...) <-- Path traversal continues
        │       │
        │       └── f = open(tile, 'wb') <-- File creation/overwrite at attacker-controlled path (Vulnerable)
        │
        └── ... (loop continues for all tiles)
    ```

  - The `directory_path` argument, directly taken from user input, is used as the base for all subsequent file and directory operations.  The code uses `os.path.join` which, while designed for platform-independent path construction, does not inherently prevent path traversal if the base path itself contains traversal sequences. `os.makedirs` and `open` then operate within this potentially malicious base path.

- Security Test Case:
  1. **Prepare a test MBTiles file:** Create a simple MBTiles file (e.g., `test.mbtiles`) using `mb-util` or download the `test/data/one_tile.mbtiles` from the repository. This file doesn't need to contain any specific content for this test, as the vulnerability is in path handling, not tile processing.
  2. **Choose a target directory:** Select a directory where you want to demonstrate the path traversal. For example, `/tmp/evil_dir`. Ensure this directory does *not* exist before running the test.
  3. **Execute `mb-util` with a path traversal payload:** Run the following command in your terminal, replacing `/path/to/mbutil/mb-util` with the actual path to the `mb-util` script:
     ```bash
     /path/to/mbutil/mb-util test.mbtiles output/../../../tmp/evil_dir
     ```
     Here, `output/../../../tmp/evil_dir` is the malicious output directory path. It attempts to go up three directories from `output` and then enter `/tmp/evil_dir`.
  4. **Verify successful execution:** The `mb-util` command should execute without errors.
  5. **Check for file creation in the target directory:** Verify if the files and directories were created in `/tmp/evil_dir`. You should find directories like `0/0` and a file `0.png` (or similar based on the MBTiles content) within `/tmp/evil_dir`.
  6. **Expected Result:** If the vulnerability is present, the tile files and directories will be created under `/tmp/evil_dir`, demonstrating that the path traversal was successful and files were written outside the intended `output` subdirectory. If the vulnerability is mitigated, the files should either be written to a sanitized path or the operation should be prevented with an error.
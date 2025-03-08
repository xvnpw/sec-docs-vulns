- Vulnerability name: Path Traversal during MBTiles export

- Description:
    1. A malicious MBTiles file is crafted with tile paths containing directory traversal sequences (e.g., "../", "..\\").
    2. The attacker provides this malicious MBTiles file as input to the `mb-util` utility, using the `mbtiles_to_disk` command to export tiles to a directory.
    3. During the export process, the `mbtiles_to_disk` function reads tile paths (zoom level, tile column, tile row) from the MBTiles file and constructs output file paths by joining the output directory path with the tile paths.
    4. Due to insufficient sanitization of tile paths extracted from the MBTiles file, directory traversal sequences are not removed.
    5. When the utility attempts to create directories and files based on these crafted paths using functions like `os.makedirs` and `open`, it writes files to locations outside the intended output directory, potentially overwriting critical system files or placing malicious files in arbitrary locations.

- Impact:
    - File system manipulation: Attackers can write files to arbitrary locations on the server's file system where the `mb-util` utility is executed.
    - File overwrite: Critical system files or application files could be overwritten, leading to application malfunction or system instability.
    - Arbitrary code execution (potential): In some scenarios, if an attacker can overwrite executable files or configuration files, this could potentially lead to arbitrary code execution on the server.
    - Data exfiltration (potential): Although less direct, an attacker might be able to create symbolic links or hard links to sensitive files and then retrieve them through subsequent operations, depending on system configurations and permissions.

- Vulnerability rank: High

- Currently implemented mitigations:
    - None: The code does not implement any sanitization or validation of tile paths extracted from the MBTiles file before using them in file system operations.

- Missing mitigations:
    - Input sanitization: The application should sanitize the tile paths (zoom level, tile column, tile row) read from the MBTiles file. This should include removing directory traversal sequences like "../" and "..\\" before constructing file paths.
    - Path validation: Before creating directories or files, the application should validate that the constructed output path is within the intended output directory. This can be achieved by canonicalizing both the output directory path and the constructed file path and ensuring that the constructed file path is a subdirectory of the output directory path.
    - Principle of least privilege: Running the `mb-util` utility with minimal necessary privileges can limit the impact of a successful path traversal attack.

- Preconditions:
    - The attacker needs to be able to provide a maliciously crafted MBTiles file as input to the `mb-util` utility.
    - The `mb-util` utility must be used in export mode (`mbtiles_to_disk`).
    - The user running the `mb-util` utility must have write permissions in the directories targeted by the path traversal sequences if they are outside of the intended output directory, and must have write permissions to the targeted files if overwriting existing files.

- Source code analysis:
    1. The vulnerability is in the `mbtiles_to_disk` function within `/code/mbutil/util.py`.
    2. The function reads tile data from an MBTiles file and exports it to a directory structure on disk.
    3. The code iterates through tiles fetched from the database using the SQL query: `select zoom_level, tile_column, tile_row, tile_data from tiles;`
    4. For each tile, it extracts `z`, `x`, and `y` coordinates, which are directly derived from `zoom_level`, `tile_column`, and `tile_row` columns in the `tiles` table of the MBTiles file.
    5. It constructs the directory path using `os.path.join(base_path, str(z), str(x))` where `base_path` is the user-provided output directory.
    6. It constructs the tile file path using `os.path.join(tile_dir,'%s.%s' % (y, kwargs.get('format', 'png')))` or similar variations depending on the scheme.
    7. The code uses `os.makedirs(tile_dir, exist_ok=True)` to create the directory structure and `f = open(tile, 'wb')` to open the file for writing tile data.
    8. **Vulnerability:** The code does not validate or sanitize the `z`, `x`, and `y` values obtained from the MBTiles file. If a malicious MBTiles file contains values like `tile_column = "../evil"` or `tile_row = "../../important"`, these values are directly used in `os.path.join`, leading to path traversal.

    ```python
    def mbtiles_to_disk(mbtiles_file, directory_path, **kwargs):
        # ...
        base_path = directory_path
        # ...
        tiles = con.execute('select zoom_level, tile_column, tile_row, tile_data from tiles;')
        t = tiles.fetchone()
        while t:
            z = t[0] # zoom_level from database
            x = t[1] # tile_column from database
            y = t[2] # tile_row from database
            # ...
            tile_dir = os.path.join(base_path, str(z), str(x)) # vulnerable path construction
            if not os.path.isdir(tile_dir):
                os.makedirs(tile_dir) # directory creation based on potentially malicious path
            tile = os.path.join(tile_dir,'%s.%s' % (y, kwargs.get('format', 'png'))) # vulnerable path construction
            f = open(tile, 'wb') # file creation based on potentially malicious path
            f.write(t[3])
            f.close()
            # ...
    ```

- Security test case:
    1. Create a malicious MBTiles file (e.g., `malicious.mbtiles`) using an SQLite editor or programmatically.
    2. In the `tiles` table of `malicious.mbtiles`, insert a row with:
        - `zoom_level = 0`
        - `tile_column = "../evil_dir"`
        - `tile_row = "file"`
        - `tile_data = <some tile data>`
    3. Open a terminal and navigate to a test directory.
    4. Execute the `mb-util` command to export the malicious MBTiles file: `mb-util malicious.mbtiles output_test_dir`
    5. After execution, check the file system in the parent directory of `output_test_dir`.
    6. Verify if a directory named `evil_dir` has been created in the parent directory, and if a file named `file.png` (or the default image format) exists within `evil_dir`.
    7. If the directory `evil_dir` and the file `file.png` are created outside of the `output_test_dir` directory, the path traversal vulnerability is confirmed.

    **Example malicious.mbtiles creation using sqlite command line:**

    ```bash
    sqlite3 malicious.mbtiles "CREATE TABLE tiles (zoom_level INTEGER, tile_column INTEGER, tile_row INTEGER, tile_data BLOB);"
    sqlite3 malicious.mbtiles "INSERT INTO tiles (zoom_level, tile_column, tile_row, tile_data) VALUES (0, '../evil_dir', 'file', 'test data');"
    ```

    **Expected result:** After running `mb-util malicious.mbtiles output_test_dir`, a directory `evil_dir` should be created in the parent directory of `output_test_dir`, and inside `evil_dir`, a file `file.png` (or the default image format) should be present, containing "test data" as its content. This confirms that the path traversal vulnerability exists, as files are written outside the intended `output_test_dir`.
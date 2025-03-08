### Vulnerability List

- Path Traversal in `open_zarr` function

#### Description
An attacker could exploit a path traversal vulnerability in the `open_zarr(path)` function. By providing a maliciously crafted path containing directory traversal sequences (e.g., `../`), an attacker could potentially bypass intended directory restrictions and access files or directories outside the designated Zarr storage location. This is possible because the `open_zarr` function uses `os.path.join` to construct paths to individual arrays within the Zarr store without proper sanitization of the base path. If a Zarr store is structured in a specific way, with variable names that, when combined with a malicious base path, traverse outside the intended directory, it could lead to unauthorized file access.

**Step-by-step trigger:**
1. An attacker crafts a malicious path string that includes directory traversal sequences, for example, `'../sensitive_zarr_root'`.
2. The attacker provides this malicious path to the `open_zarr` function as the `path` argument.
3. The `open_zarr` function internally uses `xarray.open_zarr` to read the Zarr metadata, which might reveal the names of variables (keys) within the Zarr store.
4. For each variable key `k` obtained from the Zarr metadata, the `open_zarr` function constructs a path using `os.path.join(path, k)`. If the initial `path` was malicious (e.g., `'../sensitive_zarr_root'`) and a key `k` is, for instance, `'data_array'`, the resulting path becomes `'../sensitive_zarr_root/data_array'`.
5. TensorStore is then used to open the array at this constructed path. If the traversal sequences in the initial `path` are not properly sanitized, TensorStore might access locations outside the intended Zarr root directory.

#### Impact
Successful exploitation of this path traversal vulnerability could allow an attacker to:
- **Read sensitive files**: Access and read files located outside the intended Zarr storage directory, potentially including configuration files, data files, or other sensitive information.
- **Enumerate directory structure**: By attempting to access various paths, an attacker might be able to map out the directory structure of the server or system where the code is running, gaining further knowledge for potential attacks.

#### Vulnerability Rank
High

#### Currently Implemented Mitigations
None. The code directly uses `os.path.join` with the user-provided path without any sanitization or validation to prevent directory traversal.

#### Missing Mitigations
- **Path Sanitization**: Implement input sanitization on the `path` argument in the `open_zarr` function to remove or neutralize directory traversal sequences (e.g., `../`, `./`).
- **Path Validation**: Validate the resolved path to ensure it remains within the intended Zarr storage directory. This could involve resolving the absolute path of the intended root directory and checking if the accessed path stays within this root.
- **Principle of Least Privilege**: Ensure that the process running `xarray-tensorstore` operates with the minimum necessary permissions to access only the intended Zarr storage locations and prevent access to other parts of the file system.

#### Preconditions
- The attacker must be able to provide an arbitrary path string to the `open_zarr` function. This is typically the case when the path is derived from user input or external configuration.
- The underlying operating system and file system permissions must allow traversal to the targeted files or directories if the path traversal is successful.
- The Zarr store structure (variable names) may influence the exploitability, but a malicious path alone might be sufficient if the application expects to access files relative to the provided path.

#### Source Code Analysis
```python
def open_zarr(
    path: str,
    *,
    context: tensorstore.Context | None = None,
    mask_and_scale: bool = True,
    write: bool = False,
) -> xarray.Dataset:
  ...
  ds = xarray.open_zarr(path, chunks=None, mask_and_scale=mask_and_scale) # Line 206
  ...
  specs = {k: _zarr_spec_from_path(os.path.join(path, k)) for k in ds} # Line 209
  ...
  array_futures = {
      k: tensorstore.open(spec, read=True, write=write, context=context) # Line 212
      for k, spec in specs.items()
  }
  ...
```

**Line 206:** `xarray.open_zarr(path, ...)`: This line uses xarray's built-in Zarr opening functionality. While xarray itself might have some internal path handling, the vulnerability is in how `xarray-tensorstore` constructs paths for TensorStore.

**Line 209:** `specs = {k: _zarr_spec_from_path(os.path.join(path, k)) for k in ds}`: This is the critical line.
- `path`: This is the user-provided path, which can be manipulated to include traversal sequences like `../`.
- `k`: This is the variable name (key) from the xarray Dataset `ds`, obtained from the Zarr metadata. The attacker might have some control over the structure of the Zarr store and thus the keys `k`.
- `os.path.join(path, k)`: This function naively joins the user-provided `path` with the variable key `k`. If `path` is malicious, `os.path.join` will simply concatenate or resolve the path according to standard path joining rules, without preventing traversal.

**Line 212:** `array_futures = {k: tensorstore.open(spec, ...)`: TensorStore opens arrays based on the `spec` generated by `_zarr_spec_from_path`, which incorporates the potentially malicious path constructed in the previous step.

**Visualization:**

Imagine the intended Zarr root is `/safe/zarr_storage`.
An attacker provides `path = '../sensitive_files'` to `open_zarr`.
Let's say the Zarr store contains a variable named `config.json` (so `k = 'config.json'`).
`os.path.join('../sensitive_files', 'config.json')` results in `'../sensitive_files/config.json'`.
If the code is running in `/safe/zarr_storage/app/`, then the resolved path becomes `/safe/sensitive_files/config.json`, potentially accessing files outside of `/safe/zarr_storage`.

#### Security Test Case
**Pre-requisites:**
- Python environment with `xarray-tensorstore` installed.
- Write access to `/tmp` directory to create temporary files and directories.

**Steps:**
1. **Setup Sensitive File:** Create a sensitive file outside the intended Zarr storage location.
   ```bash
   echo "This is a sensitive file" > /tmp/sensitive.txt
   ```

2. **Create Malicious Zarr Store:** Create a Zarr store with a variable name designed for path traversal.
   ```python
   import xarray as xr
   import numpy as np
   import zarr
   import os

   zarr_root = '/tmp/malicious_zarr_root'
   sensitive_file_var_name = '../../sensitive.txt' # Traversal path

   if not os.path.exists(zarr_root):
       os.makedirs(zarr_root)

   # Create a simple dataset
   ds = xr.Dataset(
       {sensitive_file_var_name: (('x',), np.arange(5))}, # Variable with traversal name
       coords={'x': np.arange(5)}
   )
   ds.to_zarr(os.path.join(zarr_root, 'malicious.zarr'))
   ```

3. **Attempt Path Traversal using `open_zarr`:** Use `open_zarr` with a path that, combined with the malicious variable name, should attempt to access the sensitive file.
   ```python
   import xarray_tensorstore
   import os

   malicious_zarr_path = '/tmp/malicious_zarr_root/malicious.zarr'

   # Attempt to open the Zarr store with a base path that should allow traversal
   try:
       ds_malicious = xarray_tensorstore.open_zarr(malicious_zarr_path)

       # Access the variable with the malicious name, which should try to read '../../sensitive.txt'
       malicious_var = ds_malicious[sensitive_file_var_name]

       # Try to compute or access data - this might trigger the file access
       data = malicious_var.compute()
       print("Successfully accessed data from potentially traversed path.") # Vulnerability exists if this line is reached without error.
       print(data)

   except Exception as e:
       print(f"Error during access (Expected if mitigation exists or access is blocked): {e}")

   # Verification: Check if access to sensitive file was possible (manual step)
   # If the code above runs without a file access error and prints "Successfully accessed data...",
   # it indicates a potential vulnerability. In a real scenario, you'd check if the content
   # of `/tmp/sensitive.txt` was somehow exposed or accessible via this process.
   ```

**Expected Result:**
If the path traversal vulnerability exists, the test case should either:
- Successfully read data without raising a "file not found" or permission error, indicating that it might have accessed a location outside the intended Zarr root (though in this test case, it's still within `/tmp`, but conceptually, it demonstrates traversal).
- Raise an error related to file access outside the intended boundaries, if some form of system-level path traversal protection is in place (less likely to be a mitigation within `xarray-tensorstore` itself).

If mitigations are implemented, the test case should ideally raise an error indicating that the path is invalid or contains disallowed traversal sequences, or access should be restricted to within the intended Zarr root.

**Note:** This test case is designed to demonstrate the *potential* for path traversal. Real-world exploitation might depend on file system permissions, the structure of the Zarr store, and the context in which `xarray-tensorstore` is used. A robust security test would involve more rigorous checks and potentially attempt to access files in more sensitive locations (within the constraints of ethical testing).
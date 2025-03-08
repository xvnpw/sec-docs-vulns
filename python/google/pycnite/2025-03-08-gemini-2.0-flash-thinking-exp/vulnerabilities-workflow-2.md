## Vulnerability Report

This report outlines critical and high severity vulnerabilities identified in the `pycnite` library related to parsing marshalled Python bytecode (`.pyc` files). These vulnerabilities can be exploited by a malicious actor providing a crafted `.pyc` file to an application that uses `pycnite`.

### 1. Integer Overflow in Marshal Reader String Size Handling

*   **Vulnerability Name:** Integer Overflow in Marshal Reader String Size Handling
*   **Description:** The `MarshalReader` in `marshal.py` uses `_read_long()` to read the size of strings, unicode objects, bytes objects, and other variable-length data structures from marshalled data. The `_read_long()` function reads a 32-bit signed integer. If a malicious `.pyc` file provides a string size close to the maximum value of a signed 32-bit integer (2<sup>31</sup> - 1), and subsequent operations on this size, like memory allocation, are performed without proper overflow checks, it can lead to an integer overflow. This overflow can wrap around to a small value, potentially leading to a heap buffer overflow when reading the string data using `_read(n)`.
*   **Impact:** Heap buffer overflow, potentially leading to arbitrary code execution. An attacker could craft a malicious `.pyc` file with a large string size that, when parsed by `pycnite`, causes a buffer overflow, overwriting adjacent memory regions. This can be exploited to achieve arbitrary code execution on the system running an application that uses `pycnite` to parse untrusted `.pyc` files.
*   **Vulnerability Rank:** Critical
*   **Currently Implemented Mitigations:** None. The code does not explicitly check for integer overflows when reading the size of data structures in `marshal.py`.
*   **Missing Mitigations:** Input validation to check for excessively large size values read from the marshalled data, before using them in memory allocation or read operations. Specifically, after reading the size using `_read_long()` in functions like `load_string`, `load_unicode`, `load_ascii`, and others, there should be a check to ensure the size is within reasonable limits and doesn't lead to integer overflows in subsequent calculations.
*   **Preconditions:**
    *   The application must use `pycnite` to parse a `.pyc` file provided by an attacker.
    *   The malicious `.pyc` file must be crafted to include a string or similar data structure with a size value that triggers an integer overflow when processed by `MarshalReader`.
*   **Source Code Analysis:**
    1.  **File: `/code/pycnite/marshal.py`**: Examine the `MarshalReader` class, specifically the `_read_long()` and `_read_sized()` methods, and the `load_*` methods that use them (e.g., `load_string`, `load_unicode`, `load_ascii`).
    2.  **Function: `_read_long()`**: This function reads 4 bytes and interprets them as a signed 32-bit integer. It does not perform any checks for potential overflow when this value is used later.

        ```python
        def _read_long(self):
            """Read a signed 32 bit word."""
            b = self._read(4)
            x = b[0] | b[1] << 8 | b[2] << 16 | b[3] << 24
            if b[3] & 0x80 and x > 0:
                # sign extension
                x = -((1 << 32) - x)
                return int(x)
            else:
                return x
        ```
    3.  **Function: `_read_sized()`**: This function calls `_read_long()` to get the size and then uses this size in `_read(n)`. If `n` is a large value close to `INT_MAX` and there's an overflow in calculations involving `n` later, it could become small, but `_read(n)` will still attempt to read a large amount of data based on the original intended size, leading to a buffer overflow if the allocated buffer is smaller than the intended size due to the integer wrap-around.

        ```python
        def _read_sized(self):
            """Read a size and a variable number of bytes."""
            n = self._read_long()
            return self._read(n)
        ```
    4.  **Vulnerable `load_*` functions**: Functions like `load_string`, `load_unicode`, `load_ascii`, `load_interned` in `MarshalReader` use `_read_sized()`. If the size read by `_read_long()` is maliciously crafted to cause an integer overflow in subsequent operations within these functions or in the caller functions, a heap buffer overflow can occur during the `_read(n)` call.

    5.  **Visualization**:

        ```
        Malicious .pyc file --> pyc.load/loads/load_file --> marshal.loads --> MarshalReader
                                                                    |
                                                                    |--> _read_long() reads large size (e.g., INT_MAX - small_value)
                                                                    |
                                                                    |--> _read_sized() gets size from _read_long()
                                                                    |
                                                                    |--> Potential Integer Overflow (e.g., size + offset wraps to small value)
                                                                    |
                                                                    |--> _read(n) with potentially overflowed size 'n' --> Heap Buffer Overflow
        ```

*   **Security Test Case:**
    1.  **Craft a malicious `.pyc` file**: Create a Python source file, say `overflow.py`, with simple content (e.g., `x = 1`).
    2.  **Compile it to `.pyc` for a target Python version (e.g., 3.9)** using the standard `compile()` function.
    3.  **Modify the `.pyc` file**: Open the `.pyc` file in binary mode. Locate the size field for a string or similar data structure within the marshalled code object (this requires understanding the marshal format, e.g., constants pool). Replace this size field with a value close to `2**31 - 1` (e.g., `0x7FFFFFFF`). You might need to adjust the subsequent bytes to maintain `.pyc` file structure if checksums or size fields are present after the modified size. A tool or script would be needed to reliably craft such a `.pyc` file.
    4.  **Run `pycnite.load_file()` on the modified `.pyc` file**: Write a test script that uses `pycnite.load_file()` or `pycnite.loads()` to parse the crafted `.pyc` file.
    5.  **Observe the outcome**: Execute the test script. If the integer overflow vulnerability is present, it might lead to a crash due to a heap buffer overflow, or potentially, if carefully crafted, overwrite memory without immediate crashing, which is a more severe security issue. Use memory debugging tools (like AddressSanitizer, if available) to confirm heap buffer overflow. If successful, this demonstrates the vulnerability.

### 2. Uncontrolled Memory Allocation in String/Bytes Loading

*   **Vulnerability Name:** Uncontrolled Memory Allocation in String/Bytes Loading
*   **Description:**
    1.  The `marshal.loads` function in `pycnite/marshal.py` is used to deserialize data from a `.pyc` file.
    2.  When loading string or bytes objects, the `_read_sized` method is called.
    3.  `_read_sized` first reads a 4-byte integer representing the size of the string/bytes object using `_read_long`.
    4.  It then attempts to read exactly `n` bytes from the input stream, where `n` is the size read in the previous step.
    5.  If a malicious `.pyc` file provides a very large integer as the size, `_read_sized` will attempt to allocate a large amount of memory to read the string/bytes data.
    6.  This can lead to excessive memory consumption and potentially a crash if the system runs out of memory when processing a crafted `.pyc` file.

*   **Impact:** Memory exhaustion leading to potential crash of the application. A crafted `.pyc` file can cause the application using `pycnite` to allocate excessive memory, resulting in a crash and impacting availability.
*   **Vulnerability Rank:** High
*   **Currently Implemented Mitigations:** None. The code directly reads the size and attempts to allocate memory without any size validation or limits.
*   **Missing Mitigations:**
    *   Implement size limits for strings/bytes being read from the `.pyc` file.
    *   Add checks to ensure the size is within reasonable bounds before attempting to allocate memory.
    *   Consider using a more memory-safe approach for reading potentially large strings/bytes, such as reading in chunks.
*   **Preconditions:**
    *   An attacker needs to be able to provide a malicious `.pyc` file to an application that uses `pycnite` to parse it. This could be through file upload, network transfer, or any other mechanism where the application processes `.pyc` files from external sources.
*   **Source Code Analysis:**
    *   **File:** `/code/pycnite/marshal.py`
    *   **Method:** `MarshalReader._read_sized()`

    ```python
    def _read_sized(self):
        """Read a size and a variable number of bytes."""
        n = self._read_long() # [POINT OF VULNERABILITY] - Reads a 4-byte size
        return self._read(n)  # [POINT OF VULNERABILITY] - Attempts to read 'n' bytes
    ```

    *   The `_read_long()` method reads a 4-byte signed integer. This integer is directly used as the size `n` in `_read(n)`.
    *   The `_read(n)` method then attempts to read `n` bytes. If `n` is excessively large, this will lead to a large memory allocation.
    *   There are no checks in `_read_sized` or `_read_long` to validate the size `n` against any maximum allowed value.

    ```python
    def load_string(self):
        s = self._read_sized() # Calls _read_sized to get string data
        return bytes(s)
    ```
    ```python
    def load_unicode(self):
        s = self._read_sized() # Calls _read_sized to get unicode data
        return s.decode("utf8", "backslashreplace")
    ```
    *   `load_string` and `load_unicode` are examples of methods that use `_read_sized` to load string and unicode data from the marshalled stream. A malicious `.pyc` can trigger this path and cause excessive memory allocation.

*   **Security Test Case:**
    1.  **Craft a malicious `.pyc` file:** Create a Python source file (e.g., `malicious.py`) and compile it into a `.pyc` file using a standard Python compiler.
    2.  **Modify the `.pyc` file:** Open the `.pyc` file in binary mode. Locate the marshalled string or bytes data within the `.pyc` file's content. Replace the size prefix of a string or bytes object with a very large 4-byte integer (e.g., `0xffffffff` for -1 or `0xffffff7f` for a large positive number close to maximum signed 32-bit integer).  You can use a hex editor or a script to modify the bytes.
    3.  **Prepare a test application:** Write a simple Python script that uses `pycnite` to load the crafted `.pyc` file using `pyc.load_file` or `pyc.loads`.
    4.  **Run the test application:** Execute the test application with the modified `.pyc` file.
    5.  **Observe the behavior:** Monitor the memory usage of the test application. If the vulnerability is present, you should observe a significant increase in memory consumption, potentially leading to a crash or system slowdown due to memory exhaustion.
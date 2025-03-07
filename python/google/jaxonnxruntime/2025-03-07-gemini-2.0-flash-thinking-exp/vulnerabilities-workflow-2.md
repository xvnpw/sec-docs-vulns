## Combined List of Critical and High Severity Vulnerabilities in jaxonnxruntime

This document outlines critical and high severity vulnerabilities identified in the jaxonnxruntime project. These vulnerabilities could potentially allow an attacker to compromise the system by exploiting weaknesses in ONNX model processing.

### 1. Integer Overflow in Shape Calculation for Slice Operator

- **Vulnerability Name:** Integer Overflow in Shape Calculation for Slice Operator
- **Description:**
    1. A malicious ONNX model is crafted with a Slice operator.
    2. This Slice operator is configured with extremely large or specially crafted `starts`, `ends`, or `steps` attributes, or input tensors for these values in versions supporting dynamic inputs.
    3. When `jaxonnxruntime` parses and executes this model, specifically the `onnx_slice` function in `/code/jaxonnxruntime/onnx_ops/slice.py`, the slice indices calculations might lead to an integer overflow due to the potentially large values.
    4. This integer overflow could result in incorrect memory access during the slice operation, potentially leading to out-of-bounds read or write, and potentially arbitrary code execution.
- **Impact:**
    Arbitrary code execution. An attacker could potentially gain full control of the system by crafting a malicious ONNX model that exploits this integer overflow to execute arbitrary code.
- **Vulnerability Rank:** Critical
- **Currently Implemented Mitigations:**
    No specific mitigations are implemented in the provided code to prevent integer overflows in shape calculations for the Slice operator. The code in `/code/jaxonnxruntime/onnx_ops/slice.py` directly uses the provided attributes or input values for slicing without any explicit checks for integer overflows.
- **Missing Mitigations:**
    - Input validation: Implement checks to validate the `starts`, `ends`, and `steps` attributes/inputs of the Slice operator to ensure they are within reasonable bounds and will not cause integer overflows during calculations.
    - Safe integer arithmetic: Use safe integer arithmetic operations that detect and handle overflows, or use libraries that provide overflow-safe integer types.
    - Fuzzing: Implement fuzzing techniques specifically targeting the Slice operator with various large and boundary values for `starts`, `ends`, and `steps` to identify potential overflow issues.
- **Preconditions:**
    1. The attacker needs to provide a maliciously crafted ONNX model to the `jaxonnxruntime` library.
    2. The ONNX model must contain a Slice operator.
    3. The Slice operator must have attributes or inputs that, when used in slice index calculations, can cause an integer overflow.
- **Source Code Analysis:**
    1. File: `/code/jaxonnxruntime/onnx_ops/slice.py`
    2. Function: `onnx_slice`
    3. Code snippet:
    ```python
    @functools.partial(jax.jit, static_argnames=('starts', 'ends', 'axes', 'steps'))
    def onnx_slice(*input_args, starts, ends, axes, steps):
      """The impl for https://github.com/onnx/onnx/blob/v1.12.0/docs/Operators.md#Slice."""
      x = input_args[0]
      if axes is None:
        axes = tuple(range(len(starts)))
      if steps is None:
        steps = [1] * len(starts)
      slices = tuple(
          slice(start, end, step) for start, end, step in zip(starts, ends, steps)
      )
      sub_indx = [slice(None)] * len(x.shape)
      for i, axis in enumerate(axes):
        sub_indx[axis] = slices[i]
      return x[tuple(sub_indx)]
    ```
    4. Vulnerability point: The `onnx_slice` function uses `starts`, `ends`, and `steps` directly to create slice objects without validating their numerical ranges. If these values are excessively large, the calculation of slice indices within JAX could potentially lead to integer overflows. For example, if `start` and `step` are very large positive numbers and `end` is a very large negative number, the calculation within `slice()` might overflow. This can lead to unexpected behavior in memory access during the slicing operation, potentially causing a security vulnerability.
- **Security Test Case:**
    1. Create a malicious ONNX model (`malicious_slice_model.onnx`) with a Slice operator.
    2. Set the Slice operator's `starts`, `ends`, and `steps` attributes or inputs to values that are likely to cause an integer overflow during slice index calculation. For example, set `starts` and `steps` to the maximum integer value and `ends` to a large negative integer value.
    3. Load the malicious ONNX model using `onnx.load('malicious_slice_model.onnx')`.
    4. Prepare input data for the model, ensuring the input shape is compatible with the Slice operator.
    5. Run the model using `jaxonnxruntime.backend.run_model(model, input_data)`.
    6. Observe the behavior of `jaxonnxruntime`. If the vulnerability is triggered, it might result in a crash, incorrect output, or potentially arbitrary code execution.
    7. Example malicious ONNX model (pseudocode - needs to be created as a valid ONNX model):
        ```python
        import onnx
        import onnx.helper as helper
        import numpy as np

        node = helper.make_node(
            'Slice',
            inputs=['input', 'starts', 'ends', 'axes', 'steps'],
            outputs=['output']
        )

        graph = helper.make_graph(
            [node],
            'malicious_slice_graph',
            [helper.make_tensor_value_info('input', onnx.TensorProto.FLOAT, [10, 10, 10]),
             helper.make_tensor_value_info('starts', onnx.TensorProto.INT64, [1]),
             helper.make_tensor_value_info('ends', onnx.TensorProto.INT64, [1]),
             helper.make_tensor_value_info('axes', onnx.TensorProto.INT64, [1]),
             helper.make_tensor_value_info('steps', onnx.TensorProto.INT64, [1])],
            [helper.make_tensor_value_info('output', onnx.TensorProto.FLOAT, [10, 10, 10])],
        )

        model = helper.make_model(graph, producer_name='jaxonnxruntime')

        # Set large values for starts, ends, steps as initializers
        starts_init = helper.make_tensor('starts', onnx.TensorProto.INT64, [1], [2**63-1]) # Max int64
        ends_init = helper.make_tensor('ends', onnx.TensorProto.INT64, [1], [-2**63]) # Min int64
        axes_init = helper.make_tensor('axes', onnx.TensorProto.INT64, [1], [0])
        steps_init = helper.make_tensor('steps', onnx.TensorProto.INT64, [1], [2**63-1]) # Max int64

        model.graph.initializer.extend([starts_init, ends_init, axes_init, steps_init])

        onnx.save(model, 'malicious_slice_model.onnx')
        ```
    8. Execute the test case and verify if an integer overflow occurs, leading to unexpected behavior or a crash.

### 2. Potential Type Confusion in Cast Operator leading to Arbitrary Code Execution

- **Vulnerability Name:** Potential Type Confusion in Cast Operator leading to Arbitrary Code Execution
- **Description:**
    1. An attacker crafts a malicious ONNX model containing a `Cast` operator.
    2. This `Cast` operator is designed to convert a tensor from a carefully selected `from_type` to a `to_type`.
    3. The attacker manipulates the `from_type` and `to_type` attributes in the ONNX model, potentially causing a type confusion during the `onnx_cast` operation in `jaxonnxruntime/onnx_ops/cast.py`.
    4. Specifically, the vulnerability lies in the line `y = x.view(from_type).astype(to_type)`. If `from_type` and `to_type` are maliciously chosen, the `view` operation might reinterpret memory in an unsafe way, and the subsequent `astype` operation could trigger unexpected behavior due to type confusion.
    5. This type confusion could potentially be exploited to read from or write to unintended memory locations, leading to arbitrary code execution.
- **Impact:**
    Critical: Successful exploitation can lead to arbitrary code execution on the machine running the JAX ONNX Runtime. This allows the attacker to completely compromise the system, potentially stealing sensitive data, installing malware, or disrupting operations.
- **Vulnerability Rank:** Critical
- **Currently Implemented Mitigations:**
    - The `onnx_cast` function includes a `try-except` block to catch potential errors during casting, but this might not be sufficient to prevent all type confusion vulnerabilities, especially if the memory corruption occurs before the exception is raised or if the exception is too broad.
    - Source code: `/code/jaxonnxruntime/onnx_ops/cast.py`
- **Missing Mitigations:**
    - Input Validation: Implement robust validation for the `from_type` and `to_type` attributes of the `Cast` operator to ensure they are within expected and safe ranges. This should include checks for potentially dangerous type conversions.
    - Type Safety Enforcement:  Strengthen type checking within the `onnx_cast` implementation to prevent unexpected type reinterpretations during the `view` and `astype` operations. Explore safer alternatives to `view` if it's the source of potential vulnerabilities.
    - Security Review: Conduct a thorough security review of the `onnx_cast` operator and related code paths, focusing on type handling and memory safety.
- **Preconditions:**
    - The attacker needs to be able to supply a maliciously crafted ONNX model to the JAX ONNX Runtime. This could be through a web service, application, or any other interface that processes user-provided ONNX models.
- **Source Code Analysis:**
    1. File: `/code/jaxonnxruntime/onnx_ops/cast.py`
    2. Function: `onnx_cast`
    3. Vulnerable Code:
    ```python
    y = x.view(from_type).astype(to_type)
    ```
    4. Step-by-step Exploit Scenario:
        - The attacker crafts an ONNX model with a `Cast` node.
        - The `Cast` node's attributes specify a malicious `from_type` (e.g., a smaller data type like `FLOAT16`) and `to_type` (e.g., a larger data type like `FLOAT64`).
        - When `onnx_cast` is executed:
            - `x.view(from_type)`:  The input tensor `x`'s data is reinterpreted as `from_type`. If `from_type` is smaller than the original type and the size is not properly checked, this could lead to out-of-bounds read during the view operation.
            - `.astype(to_type)`: The reinterpreted data is then cast to `to_type`. If `to_type` is larger than `from_type`, this could lead to buffer overflows during the type conversion, as the code might allocate insufficient memory based on the malicious `from_type`.
        - By carefully crafting the input tensor and the `from_type`/`to_type` parameters, an attacker might be able to trigger memory corruption, potentially leading to arbitrary code execution.
- **Security Test Case:**
    1. Objective: Prove that a maliciously crafted ONNX model with a `Cast` operator can trigger unexpected behavior due to potential type confusion.
    2. Test Setup:
        - Create a Python script to generate a malicious ONNX model.
        - This model should contain a `Cast` operator with specific `from_type` and `to_type` attributes designed to trigger type confusion.
        - The input tensor to the `Cast` operator should also be crafted to maximize the exploit potential.
    3. Steps:
        - Model Creation: Use the ONNX Python API to create a model with a `Cast` node. Set the `to` attribute of the `Cast` node to `onnx.TensorProto.FLOAT64` and attempt to implicitly control or influence the `from_type` (e.g., by providing input data that might be misinterpreted as a smaller type).
        - Input Preparation: Create a NumPy input array with a specific data pattern and type that aligns with the crafted `from_type` in the ONNX model.
        - Execution: Load the malicious ONNX model using `onnx.load()`.
        - Backend Preparation: Prepare the ONNX model for execution using `jaxonnxruntime.backend.Backend.prepare()`.
        - Run Model: Execute the prepared model with the crafted input using `backend_rep.run()`.
        - Verification: Observe the behavior of the JAX ONNX Runtime. Check for:
            - Crashes or unexpected errors during execution.
            - Memory corruption or out-of-bounds access (if detectable).
            - Incorrect output values that deviate significantly from expected behavior, indicating type confusion.
    4. Expected Outcome:
        - If the vulnerability is valid, the test case should demonstrate abnormal program behavior, such as crashes, errors, or incorrect outputs, indicating a successful type confusion exploit. In a more advanced scenario, it might be possible to demonstrate arbitrary code execution.

### 3. Uncontrolled Shape/Dimension Parameter in ONNX Operator Implementation

- **Vulnerability Name:** Uncontrolled Shape/Dimension Parameter in ONNX Operator Implementation
- **Description:** The `op_code_generator.py` script automatically generates template code for new ONNX operators. This template, particularly in the `onnx_{op_name_lower}` function, uses `*input_args` without specific type or shape validation. If a newly implemented operator relies on shape information from the ONNX model (e.g., for reshaping, slicing, or indexing operations) and does not validate the shape parameters, a maliciously crafted ONNX model could provide unexpected or malicious shape values. This could lead to out-of-bounds access, buffer overflows, or other memory corruption issues when the generated JAX code is executed.
- **Impact:** Arbitrary Code Execution. By crafting a malicious ONNX model with manipulated shape parameters, an attacker could potentially cause the JAX runtime to access memory outside of the intended buffers, leading to crashes, information disclosure, or potentially arbitrary code execution if memory corruption vulnerabilities are exploited.
- **Vulnerability Rank:** Critical
- **Currently Implemented Mitigations:** None. The generated code template includes a `TODO` comment to add implementation, but does not guide developers to include input validation.
- **Missing Mitigations:**
    - Input validation within each ONNX operator implementation, especially for shape-related parameters.
    - Clear guidelines and documentation for developers on secure operator implementation, emphasizing input validation and sanitization in `contributing.md` and `docs/adding_a_new_op.rst`.
    - Static analysis tools or linters to automatically detect missing input validations in operator implementations.
- **Preconditions:**
    - An attacker needs to create a malicious ONNX model.
    - The malicious model must target a newly implemented ONNX operator or an existing operator that lacks proper input validation for shape parameters.
    - The user must convert and run this malicious ONNX model using `jaxonnxruntime`.
- **Source Code Analysis:**
    - **File:** `/code/tools/op_code_generator.py`
    - **Function:** `main(args)`
    - **Template Code:**
      ```python
      template_tail = """
      @functools.partial(jax.jit, static_argnames=())
      def onnx_{op_name_lower}(*input_args):
        \"\"\"https://github.com/onnx/onnx/blob/v1.12.0/docs/Operators.md#{op_name} for more details.\"\"\"
        # TODO({username}): add the implementation here.
        return input_args
      """
      ```
    - **Analysis:** The `op_code_generator.py` tool creates a template Python file for implementing new ONNX operators. The generated `onnx_{op_name_lower}` function takes `*input_args` without any specific type or shape checking. The `TODO` comment encourages developers to add implementation logic, but lacks guidance on security best practices such as input validation. If a developer implements an operator using this template and relies on shape information from the ONNX model without validation, it becomes vulnerable to malicious shape parameters. For example, if an operator uses a shape parameter from `input_args` to index into an array, a large or negative value in the malicious model could lead to out-of-bounds access when the JAX code is executed.
- **Security Test Case:**
    1. Setup:
        - Assume an attacker can create a malicious ONNX model.
        - Assume a developer has implemented a new ONNX operator, for instance, `MyCustomOp`, using the template generated by `op_code_generator.py`, and this operator uses a shape parameter from the ONNX model to perform slicing without input validation.
    2. Craft Malicious ONNX Model:
        - The attacker crafts an ONNX model that includes the `MyCustomOp` operator.
        - Within this model, the attacker manipulates the shape parameter associated with `MyCustomOp` to an extreme value (e.g., a very large number or a negative number).
    3. User Conversion and Execution:
        - The user is tricked into using `jaxonnxruntime` to convert and run this malicious ONNX model.
        - The conversion process proceeds as usual as there's no validation during ONNX parsing itself.
    4. Exploit Trigger:
        - When `jaxonnxruntime` executes the converted model, it calls the `onnx_mycustomop` function.
        - Due to the lack of input validation in `onnx_mycustomop`, the malicious shape parameter is used directly in slicing or indexing operations.
    5. Verify Vulnerability:
        - Observe the execution. If the manipulated shape parameter causes a crash (e.g., `IndexError`, `Segmentation Fault`) or unexpected behavior (e.g., incorrect output due to out-of-bounds memory access), it indicates a successful exploit.
    6. Expected Outcome: The test should demonstrate that by providing a maliciously crafted ONNX model with manipulated shape parameters, it's possible to trigger a vulnerability in the JAX execution due to missing input validation in the custom operator implementation. The vulnerability could range from crashing the application to potential arbitrary code execution depending on the specific operator and the nature of memory corruption.

### 4. Potential Arbitrary File Overwrite via Zip Extraction

- **Vulnerability Name:** Potential Arbitrary File Overwrite via Zip Extraction
- **Description:** The `extract` function in `/code/jaxonnxruntime/experimental/export/exportable_utils.py` and `/code/jaxonnxruntime/core/onnx_utils_test.py` extracts zip files without proper path sanitization. If a malicious zip file is crafted to contain filenames with path traversal characters (e.g., `../../`), the extracted files could be written outside the intended extraction directory, potentially overwriting system files or other sensitive data. While this function might be used internally or in test cases, if it's ever exposed to processing user-provided zip files (e.g., ONNX models distributed as zip archives), it could become a vulnerability.
- **Impact:** Arbitrary File Overwrite. An attacker could overwrite arbitrary files on the system where the `jaxonnxruntime` library is used, leading to potential system compromise, data corruption, or denial of service.
- **Vulnerability Rank:** High
- **Currently Implemented Mitigations:** None. The `extract` function directly uses `zipfile.ZipFile.extractall` without any path sanitization or checks.
- **Missing Mitigations:**
    - Path sanitization within the `extract` function to validate and sanitize filenames before extraction, ensuring they remain within the intended extraction directory.
    - Principle of least privilege: ensure the process running the extraction has minimal permissions to reduce the impact of a successful file overwrite.
    - Documentation warning against using `extract` with untrusted zip files.
- **Preconditions:**
    - An attacker needs to create a malicious zip file containing filenames with path traversal sequences.
    - The `extract` function must be used to extract this malicious zip file. This could occur if:
        - Users are instructed to extract ONNX models from zip files using this function.
        - The function is used internally to process user-provided ONNX models packaged as zip files.
- **Source Code Analysis:**
    - **File:** `/code/jaxonnxruntime/experimental/export/exportable_utils.py` and `/code/jaxonnxruntime/core/onnx_utils_test.py` (and likely other locations where `extract` is used).
    - **Function:** `extract(filename, folder=None)`
    - **Code Snippet:**
      ```python
      def extract(filename, folder=None):
          base_dir = os.path.dirname(filename)
          _, ext = os.path.splitext(filename)
          assert ext in ('.zip', '.tar', '.gz'), 'Only support zip/tar files.'
          if ext == '.zip':
              fp = zipfile.ZipFile(filename, 'r')
          else:
              fp = tarfile.open(filename, 'r')
          if folder is None:
              folder = base_dir
          fp.extractall(folder) # Vulnerable line
      ```
    - **Analysis:** The `extractall(folder)` method of `zipfile.ZipFile` is vulnerable to path traversal attacks. If a zip file contains entries with filenames like `../../sensitive_file.txt`, `extractall` will attempt to write this file to the directory `folder/../../sensitive_file.txt`, which resolves to a location outside of the intended `folder`. This allows an attacker to potentially overwrite arbitrary files.
- **Security Test Case:**
    1. Setup:
        - Create a temporary directory for testing.
    2. Craft Malicious Zip File:
        - Create a zip file (`malicious.zip`) containing a file with a path traversal filename, e.g., `../../pwned.txt`. The content of `pwned.txt` can be arbitrary (e.g., "You have been PWNED!").
    3. Extraction using Vulnerable Function:
        - Use the `extract` function from `jaxonnxruntime` to extract `malicious.zip` into the temporary directory.
    4. Verify File Overwrite:
        - After extraction, check if the file `pwned.txt` has been created outside the temporary directory (e.g., in the parent directory or system root, depending on the path traversal).
        - Verify the content of the overwritten file (if successful) to ensure it matches the content from the malicious zip file.
    5. Expected Outcome: The test should demonstrate that `pwned.txt` is created outside the intended temporary directory, proving the arbitrary file overwrite vulnerability. If a sensitive system file was targeted instead of `pwned.txt`, it could lead to a more severe impact.
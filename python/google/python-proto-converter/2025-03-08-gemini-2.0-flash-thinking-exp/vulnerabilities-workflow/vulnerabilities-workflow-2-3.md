- Vulnerability name: Potential Data Loss in Float to Integer Conversion

- Description:
  1. An application uses the `python-proto-converter` library to convert protobuf messages from one type to another.
  2. The protobuf message conversion involves converting a field with a float data type in the source proto to a field with an integer data type in the destination proto.
  3. A custom conversion function is implemented using the `@converter.convert_field` decorator to handle this type conversion.
  4. Inside the custom conversion function, the float value from the source proto is directly cast to an integer using `int()`.
  5. The `int()` function in Python truncates the decimal part of the float value, resulting in a loss of precision.
  6. If the application logic relies on the full precision of the original float value, this data loss can lead to incorrect behavior or security vulnerabilities.
  7. For example, if the float field represents a price, converting it to an integer could lead to incorrect price calculations, potentially allowing users to pay less than the intended amount or causing financial discrepancies in the application.

- Impact:
  - Data integrity issues due to loss of precision during type conversion.
  - Potential for financial inaccuracies if the converted fields represent monetary values or prices.
  - Exploitable application logic flaws in systems that rely on the precision of the float values after conversion to integer.
  - Inaccurate calculations or decision-making in downstream systems that consume the converted protobuf messages.

- Vulnerability rank: Medium

- Currently implemented mitigations:
  - None. The library provides the functionality to define custom conversion functions, but it does not include any built-in mitigations or warnings against potential data loss during type conversions like float to integer. The provided examples in `README.md` and `converter_example.py` actually demonstrate this potentially vulnerable conversion without highlighting the risk of data loss.

- Missing mitigations:
  - **Documentation Enhancement**: The documentation should explicitly warn users about the potential risks of data loss when converting between different data types, especially when converting float to integer. It should advise users to carefully consider the implications of such conversions and suggest alternative approaches if data precision is critical.
  - **Guidance on Conversion Methods**: The documentation could provide guidance on safer or more appropriate methods for handling float to integer conversions when precision is important, such as rounding to the nearest integer or using decimal types if available in the target protobuf definition.
  - **Optional Warnings or Checks**: The library could potentially offer an optional mechanism (e.g., a flag or setting in `ProtoConverter` initialization) to enable warnings or runtime checks that identify potential data loss during automatic or custom conversions. This would require more complex analysis of conversion functions and might not be feasible for all cases.

- Preconditions:
  1. The application uses the `python-proto-converter` library.
  2. Protobuf message conversion is performed from a source proto with a float field to a destination proto with a corresponding integer field.
  3. A custom conversion function is implemented to handle the float to integer conversion.
  4. The custom conversion function uses direct integer casting (`int()`) which truncates decimal values.
  5. The application logic that consumes the converted protobuf messages relies on the precision of the original float value.

- Source code analysis:
  1. **File: `/code/src/pyproto/converter.py`**: This file contains the core logic of the `ProtoConverter` class.
  2. **Method: `ProtoConverter.convert(self, src_proto: FROM) -> TO`**: This method performs the protobuf conversion. It calls `_auto_convert` for automatic field conversions and then iterates through user-defined custom conversion functions.
  3. **Method: `ProtoConverter._auto_convert(self, src_proto, dest_proto)`**: This method handles automatic conversion of fields with the same name and type. It does not handle type conversions like float to integer directly.
  4. **Custom Conversion Functions**: The library relies on custom conversion functions, decorated with `@converter.convert_field`, to handle type conversions.
  5. **Example in `/code/example/converter_example.py` and `/code/README.md`**:
     ```python
     @converter.convert_field(field_names=["price"])
     def price_convert_function(self, src_proto, dest_proto):
         dest_proto.price = int(src_proto.price)
     ```
     - This example demonstrates a custom conversion function `price_convert_function` that is intended to convert the `price` field.
     - Inside this function, `dest_proto.price = int(src_proto.price)` directly casts the float value `src_proto.price` to an integer using `int()`.
     - The `int()` function truncates the decimal part. For example, if `src_proto.price` is `10.99`, `int(src_proto.price)` will be `10`, resulting in a loss of `0.99`.
  6. **No Built-in Mitigation**: The `ProtoConverter` class and its associated functions do not have any built-in checks, warnings, or alternative methods to handle potential data loss during such custom type conversions. The library provides the flexibility to perform conversions, but it leaves the responsibility of handling data integrity and precision entirely to the user implementing the custom conversion functions.

- Security test case:
  1. **Setup**:
     - Use the example protobuf definitions from `/code/example/example_proto.proto` or `/code/README.md` (MatchaMilkTea with float price, GreenTeaMilkTea with int64 price).
     - Implement the `MatchaToGreenTeaConverter` class as shown in `/code/example/converter_example.py` or `/code/README.md`, including the `price_convert_function` that converts float price to integer price using `int()`.
     - Create an instance of `MatchaMilkTea` proto with a float price value that has a decimal part, e.g., price = `10.99`.
  2. **Execution**:
     - Instantiate the `MatchaToGreenTeaConverter`.
     - Call the `convert()` method of the converter, passing the `MatchaMilkTea` proto instance as input.
     - Get the resulting `GreenTeaMilkTea` proto instance.
  3. **Verification**:
     - Check the `price` field of the `GreenTeaMilkTea` proto.
     - Assert that the `price` field is an integer and its value is the truncated integer part of the original float price. For example, if the input `MatchaMilkTea.price` was `10.99`, assert that `GreenTeaMilkTea.price` is `10`.
     - Print both the original float price and the converted integer price to clearly demonstrate the data loss.
  4. **Application Logic Impact (Illustrative)**:
     - Hypothetically, assume an e-commerce application uses this converter to process product prices.
     - If a product's price is $10.99 and it gets converted to $10 due to this vulnerability, and if the application calculates discounts or totals based on this converted integer price, it will lead to incorrect calculations.
     - For example, a 10% discount on $10.99 should ideally be around $1.10, leading to a final price of ~$9.89. However, if the price is first truncated to $10, a 10% discount would be $1, and the final price would be $9. This is a small difference, but with larger prices or quantities, and depending on the application's sensitivity to price accuracy, this data loss can have significant consequences.  This step is to illustrate the potential impact and does not need to be a fully functional test case within the library's tests.
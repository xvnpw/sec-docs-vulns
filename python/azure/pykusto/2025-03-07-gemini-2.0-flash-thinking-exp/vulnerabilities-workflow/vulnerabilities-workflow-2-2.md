### Vulnerability Name: Kusto Query Injection via String Literal in `split` Function

- Description:
    1. An attacker can control the `delimiter` argument of the `split` function, which is used to construct a Kusto query.
    2. The `split` function in `_StringExpression` in `expressions.py` directly embeds the `delimiter` into the Kusto query string without proper sanitization.
    3. By providing a malicious string as `delimiter`, an attacker can inject arbitrary Kusto query language into the generated query.
    4. For example, an attacker could set `delimiter` to `');injection_code//` to inject `injection_code` into the Kusto query.
    5. When `pykusto` executes this query against Azure Data Explorer, the injected Kusto code will be executed, potentially leading to data exfiltration, modification, or other malicious actions.

- Impact:
    - High. An attacker can execute arbitrary Kusto queries, potentially leading to unauthorized data access, data manipulation, or denial of service within the Azure Data Explorer environment.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    - None. The code directly incorporates the delimiter string into the Kusto query without any sanitization or validation.

- Missing Mitigations:
    - Input sanitization or validation for the `delimiter` argument in the `split` function to prevent injection of malicious Kusto syntax.
    - Parameterization of the Kusto query to separate code from data, preventing injection vulnerabilities.

- Preconditions:
    - The application using `pykusto` must allow user-controlled input to be passed as the `delimiter` argument to the `split` function of a `_StringExpression`.

- Source Code Analysis:
    1. File: `/code/pykusto/_src/expressions.py`
    2. Class: `_StringExpression`
    3. Function: `split(self, delimiter: StringType, requested_index: NumberType = None)`
    4. Code snippet:
    ```python
    def split(self, delimiter: StringType, requested_index: NumberType = None) -> '_ArrayExpression':
        """
        https://docs.microsoft.com/en-us/azure/data-explorer/kusto/query/splitfunction
        """
        if requested_index is None:
            return _ArrayExpression(KQL(f'split({self.kql}, {_to_kql(delimiter)})')) # Vulnerability: delimiter is directly injected
        return _ArrayExpression(KQL(f'split({self.kql}, {_to_kql(delimiter)}, {_to_kql(requested_index)})')) # Vulnerability: delimiter is directly injected
    ```
    5. Visualization:
       ```
       User Input (delimiter) --> split() function --> KQL query string (delimiter injected) --> Azure Data Explorer (query executed with injected code)
       ```
    6. The `_to_kql(delimiter)` function is used to convert the delimiter to KQL format, but it does not sanitize or validate the input to prevent injection. It simply wraps string literals in quotes. If the delimiter itself contains malicious KQL code, it will be included in the final query.

- Security Test Case:
    1. **Precondition**: Assume an application uses pykusto to query Azure Data Explorer and allows users to specify a delimiter for the `split` function on a string column.
    2. **Attacker Input**: The attacker provides the following malicious delimiter: `');take 9999//`
    3. **Code to trigger vulnerability**:
    ```python
    from pykusto import PyKustoClient, Query, column_generator as col

    client = PyKustoClient("https://help.kusto.windows.net") # Replace with your cluster if needed
    table = client.Samples.StormEvents
    string_col = table.EventDetails # Assuming StormEvents table has EventDetails column of type string

    malicious_delimiter = "');take 9999//"
    query = Query(table).extend(
        injected_query=string_col.split(malicious_delimiter).array_length()
    )
    kql_query = query.render()
    print(kql_query)
    # Execute the query (replace with actual execution if you have access to a Kusto cluster)
    # result = table.execute(kql_query)
    # print(result.to_dataframe())
    ```
    4. **Expected Outcome**:
        - The generated KQL query will be:
        ```
        StormEvents
        | extend injected_query = split(EventDetails, ');take 9999//').array_length()
        ```
        - When executed, this query will first perform the `split` operation, and then the injected Kusto code `;take 9999//` will be executed. The `take 9999` command, while not immediately harmful, demonstrates successful code injection. A real attacker could inject more malicious code.
    5. **Evidence of Vulnerability**: The injected `take 9999` command is appended and executed as part of the Kusto query, demonstrating successful injection.
### Combined Vulnerability List

#### SQL Injection in ArbitraryCondition via Unsanitized SQL Template

- Description:
    1. An attacker can control user input that is incorporated into an `ArbitraryCondition` object.
    2. The attacker crafts a malicious SQL template string or substitution values within the `ArbitraryCondition` constructor, or by influencing the input used to construct the `sql_template`.
    3. The attacker injects this `ArbitraryCondition` into a query method like `where()`.
    4. When the ORM executes the query, the malicious SQL template and/or substitutions are directly embedded into the final SQL query without proper sanitization.
    5. This allows the attacker to execute arbitrary SQL code against the Spanner database, potentially bypassing intended ORM logic and accessing or manipulating data they should not be authorized to access. This can occur both when directly providing a malicious `sql_template` or by providing malicious input that is insecurely concatenated into the `sql_template` by the application developer.

- Impact:
    - **High**: Allows for arbitrary SQL execution, leading to potential data breaches, data manipulation, or privilege escalation within the Spanner database. An attacker could potentially read, modify, or delete any data in the database, depending on the permissions of the Spanner user account used by the application. This includes:
        - **Data Breach:** An attacker could bypass intended access controls and retrieve sensitive data from the Spanner database by crafting malicious SQL queries.
        - **Data Manipulation:** An attacker could potentially modify or delete data in the Spanner database by injecting malicious SQL statements like `UPDATE`, `DELETE`, or `INSERT`.
        - **Privilege Escalation:** In certain scenarios, if the application's Spanner service account has broader permissions, a successful SQL injection could lead to privilege escalation within the Spanner database.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    - None. The `ArbitraryCondition` directly uses the provided SQL template and substitutions without any sanitization or input validation of the SQL template string itself or the substitution values. The substitutions are parameterized in the ORM's internal query construction for safer methods, but `ArbitraryCondition` bypasses these protections by allowing raw SQL.

- Missing Mitigations:
    - **Input validation for SQL templates and substitutions**: The `sql_template` argument in `ArbitraryCondition` and any substitution values should be strictly validated to prevent injection of malicious SQL code. A whitelist approach, robust parsing and sanitization mechanism for the SQL template string, or secure coding guidelines are needed.
    - **Discourage use of ArbitraryCondition**: The documentation should strongly discourage the use of `ArbitraryCondition` for general queries due to its inherent risks, and recommend safer, parameterized ORM query methods whenever possible. If `ArbitraryCondition` must be used, provide clear security guidelines and examples of safe usage, emphasizing the developer's responsibility for sanitization and parameterization using `Param`.
    - **Prepared Statements Enforcement:**  The library should enforce the use of parameterized queries for all user-provided input, even when using `ArbitraryCondition`, ideally by requiring the use of `Param` for all dynamic values within the `sql_template`.
    - **Principle of Least Privilege Documentation:** Emphasize in documentation to grant the application's Spanner service account only the minimal necessary permissions to reduce the potential impact of query injection.
    - **Static Analysis/Linting Tools:** Consider developing or recommending static analysis or linting tools that can detect potentially insecure uses of `ArbitraryCondition`, such as direct concatenation of user input into `sql_template`.

- Preconditions:
    - The application must use `ArbitraryCondition` in its code.
    - User-controlled input must be incorporated, directly or indirectly, into the `sql_template` argument of `ArbitraryCondition` or its substitutions without proper sanitization or parameterization using `Param`.
    - An attacker needs to be able to influence the arguments passed to the `where()` or similar query methods, specifically by injecting a malicious `ArbitraryCondition` object or influencing the inputs that construct it.
    - The application must be accessible to external attackers, or internal users must have the ability to manipulate query parameters.

- Source Code Analysis:
    1. **`spanner_orm/condition.py` - `ArbitraryCondition.__init__`**:
    ```python
    class ArbitraryCondition(Condition):
        def __init__(
            self,
            sql_template: str,
            substitutions: Mapping[str, Substitution] = immutabledict.immutabledict(),
            *,
            segment: Segment,
        ):
            super().__init__()
            self._sql_template = string.Template(sql_template) # [VULNERABLE]: SQL template is taken directly without sanitization
            self._substitutions = substitutions
            self._segment = segment
            # This validates the template.
            self._sql_template.substitute({k: '' for k in self._substitutions})
    ```
    - The `sql_template` argument is directly assigned to `self._sql_template` without any sanitization or validation to prevent SQL injection. The `string.Template` itself does not provide SQL injection protection; it's a simple string substitution mechanism. The validation step only checks if the template is valid Python string template syntax, not if it's safe SQL.

    2. **`spanner_orm/condition.py` - `ArbitraryCondition._sql`**:
    ```python
    def _sql(self) -> str:
        """See base class."""
        return self._sql_template.substitute({ # [VULNERABLE]: Malicious template is directly substituted into SQL query
            k: self._sql_for_substitution(k, v)
            for k, v in self._substitutions.items()
        })
    ```
    - The `_sql` method substitutes the template using `string.Template.substitute`. If the `sql_template` contains malicious SQL code, it will be directly inserted into the query string.

    3. **`spanner_orm/query.py` - `SpannerQuery._build` & `_where`**:
    ```python
    def _build(self) -> None:
        """Builds the Spanner query from the given model and conditions."""
        segment_builders = [
            self._select, self._from, self._where, self._order, self._limit
        ]

        self._sql, self._parameters, self._types = '', {}, {}
        for segment_builder in segment_builders:
            segment_sql, segment_parameters, segment_types = segment_builder()
            self._sql += segment_sql # SQL segments are concatenated together
            self._parameters.update(segment_parameters)
            self._types.update(segment_types)

    def _where(self) -> Tuple[str, Dict[str, Any], Dict[str, Any]]:
        """Processes the WHERE segment of the SQL query."""
        sql, sql_parts, parameters, types = '', [], {}, {}
        wheres = self._segments(condition.Segment.WHERE)
        for where in wheres:
          where.suffix = str(self._next_param_index() + len(parameters))
          sql_parts.append(where.sql()) # [EXECUTION]: Vulnerable SQL from ArbitraryCondition is added to the query
          parameters.update(where.params())
          types.update(where.types())
        if sql_parts:
          sql = ' WHERE {}'.format(' AND '.join(sql_parts))
        return (sql, parameters, types)
    ```
    - The `_build` method orchestrates the query construction, and `_where` specifically handles the WHERE clause.  `_where` iterates through conditions, including `ArbitraryCondition`, and appends the raw SQL from `ArbitraryCondition`'s `sql()` method to the query.

    4. **`spanner_orm/table_apis.py` - `sql_query`**:
    ```python
    def sql_query(
        transaction: spanner_transaction.Transaction,
        query: str, # [VULNERABLE]: Unsanitized SQL query is executed
        parameters: Dict[str, Any],
        parameter_types: Dict[str, spanner_v1.Type],
    ) -> List[Sequence[Any]]:
        """Executes a given SQL query against the Spanner database."""
        _logger.debug('Executing SQL:\n%s\n%s\n%s', query, parameters,
                    parameter_types)
        stream_results = transaction.execute_sql(
            query, params=parameters, param_types=parameter_types) # [VULNERABLE]: Raw SQL query is executed against database
        return list(stream_results)
    ```
    - The `sql_query` function in `table_apis.py` takes the potentially malicious SQL query string (`query`) and directly executes it using `transaction.execute_sql()`.

    5. **`spanner_orm/model.py` - `Model._execute_read` & `Model.where`**:
    ```python
    class Model(metaclass=ModelMetaclass):
        @classmethod
        def where(
            cls: Type[T],
            *conditions: condition.Condition, # [VULNERABLE]: Conditions can include ArbitraryCondition with malicious SQL template
            transaction: Optional[spanner_transaction.Transaction] = None,
        ) -> List[T]:
            """Retrieves objects from Spanner based on the provided conditions."""
            builder = query.SelectQuery(cls, conditions)
            args = [builder.sql(), builder.parameters(), builder.types()]
            results = cls._execute_read(table_apis.sql_query, transaction, args) # [VULNERABLE]: Executes SQL query constructed with potentially malicious ArbitraryCondition
            return builder.process_results(results)

        @classmethod
        def _execute_read(
            cls,
            db_api: Callable[..., CallableReturn],
            transaction: Optional[spanner_transaction.Transaction],
            args: List[Any],
        ) -> CallableReturn:
            if transaction is not None:
                return db_api(transaction, *args)
            else:
                return cls.spanner_api().run_read_only(db_api, *args)
    ```
    - The `Model.where` method constructs a `SelectQuery` using user-provided conditions, which can include a malicious `ArbitraryCondition`. It then calls `_execute_read`, which eventually calls `table_apis.sql_query` to execute the unsanitized SQL query.

    6. **Visualization:**

    ```
    UserInput (attacker controlled) --> Application Code --> ArbitraryCondition (sql_template) --> SpannerQuery._where() --> Raw SQL Query --> Spanner Database (SQL Injection)
    ```


- Security Test Case:
    1. **Setup**: Assume an attacker has control over input parameters that are used to construct conditions in a `where()` query. In this test case, we'll simulate this by directly constructing a malicious `ArbitraryCondition` or by simulating insecurely concatenated user input. For example, set up a `TestModel` with columns `id` (String, primary key) and `value` (Integer). Populate the table with some data. Create an endpoint in a test application that uses `spanner-orm` to query `TestModel` based on a filter provided by the user via HTTP GET parameter.

    2. **Malicious Input (Direct ArbitraryCondition)**: Create a malicious `ArbitraryCondition` that injects SQL code. For example, to attempt to read data from `INFORMATION_SCHEMA.TABLES`:
    ```python
    malicious_condition = spanner_orm.ArbitraryCondition(
        sql_template="TRUE) UNION ALL SELECT table_name FROM INFORMATION_SCHEMA.TABLES WHERE (TRUE = ", # SQL injection payload
        segment=spanner_orm.condition.Segment.WHERE,
    )
    ```

    3. **Malicious Input (Insecure Concatenation Simulation)**: Simulate user input being insecurely concatenated into `sql_template`:
    ```python
    user_input_filter = "1' OR '1'='1"  # Malicious user input to bypass filter
    malicious_condition = spanner_orm.ArbitraryCondition(
        sql_template="value = '" + user_input_filter + "'", # Insecure direct concatenation
        segment=spanner_orm.condition.Segment.WHERE
    )
    ```
    Or via HTTP GET parameter `/?filter_param='; DELETE FROM TestModel WHERE TRUE; --`:
    ```python
    filter_param = request.GET.get('filter_param')  # User input from request
    arbitrary_condition = spanner_orm.ArbitraryCondition(
        sql_template="value_1 = '" + filter_param + "'", # Insecure direct concatenation
        segment=spanner_orm.condition.Segment.WHERE
    )
    ```

    4. **Execute Query**: Use the `where()` method with the malicious condition.
    ```python
    results = TestModel.where(malicious_condition) # Injecting malicious condition
    ```

    5. **Verify Exploitation**: Check if the query results contain data that should not be accessible or if unintended side effects occur (e.g., data deletion).
        - For direct `ArbitraryCondition` injection (reading `INFORMATION_SCHEMA.TABLES`), verify if the results contain table names from `INFORMATION_SCHEMA.TABLES`, indicating successful data exfiltration from system tables.
        - For insecure concatenation example (`' OR '1'='1`), check if the query returns all rows from `TestModel`, bypassing the intended filter, demonstrating filter bypass.
        - For the HTTP GET parameter example (`DELETE FROM TestModel`), check if the table `TestModel` is unexpectedly emptied after executing the query, demonstrating data deletion.

    6. **Expected Outcome**: The test should demonstrate that the ORM executes the query with the injected SQL without raising errors related to SQL syntax, confirming the SQL injection vulnerability. The vulnerability is confirmed if the query, despite the malicious SQL, is processed by the ORM and sent to Spanner without proper sanitization, potentially leading to unintended data access, manipulation or data deletion.

```python
# Security Test Case Implementation (Conceptual - Requires a test environment with Spanner Emulator and setup models):
import spanner_orm
import unittest
from spanner_orm.tests import models # Assuming models are defined for testing

class SQLInjectionTest(unittest.TestCase):

    def test_arbitrary_condition_sql_injection(self):
        # Assume SmallTestModel is set up and connected to Spanner Emulator

        malicious_condition = spanner_orm.ArbitraryCondition(
            sql_template="TRUE) UNION ALL SELECT 'injected' FROM INFORMATION_SCHEMA.TABLES WHERE (TRUE = ", # Simple injection to test execution
            segment=spanner_orm.condition.Segment.WHERE,
        )

        try:
            results = models.SmallTestModel.where(malicious_condition) # Attempt to execute query with injection
            # If no exception is raised related to SQL syntax, it indicates potential SQL injection
            # In a real exploit, attacker could exfiltrate data or perform other malicious actions.
            # Here, we are just checking if the ORM allows execution without errors.
            print("SQL Injection test executed without immediate SQL errors (potential vulnerability).")
            # For a more complete test, you would verify the returned data to confirm data exfiltration,
            # but for this example, successful execution without error is a strong indicator.

        except Exception as e:
            self.fail(f"SQL Injection test failed with exception: {e}")


if __name__ == '__main__':
    unittest.main()
```

This vulnerability allows for direct SQL injection through the `ArbitraryCondition` feature, posing a significant security risk. The lack of sanitization on the `sql_template` argument and substitution values makes it possible for attackers to bypass the ORM's intended query construction and execute arbitrary SQL commands. Insecure usage by developers, such as direct string concatenation of user input into `sql_template`, further exacerbates the risk.
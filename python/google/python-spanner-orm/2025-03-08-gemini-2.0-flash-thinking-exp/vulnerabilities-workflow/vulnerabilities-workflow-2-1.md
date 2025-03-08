### Vulnerability List

- Vulnerability Name: SQL Injection in ArbitraryCondition via unsanitized SQL template

- Description:
    1. An attacker can create an `ArbitraryCondition` object.
    2. The attacker crafts a malicious SQL template string within the `ArbitraryCondition` constructor.
    3. The attacker injects this `ArbitraryCondition` into a query method like `where()`.
    4. When the ORM executes the query, the malicious SQL template is directly embedded into the final SQL query without proper sanitization.
    5. This allows the attacker to execute arbitrary SQL code against the Spanner database, potentially bypassing intended ORM logic and accessing or manipulating data they should not be authorized to access.

- Impact:
    - **High**: Allows for arbitrary SQL execution, leading to potential data breaches, data manipulation, or privilege escalation within the Spanner database. An attacker could potentially read, modify, or delete any data in the database, depending on the permissions of the Spanner user account used by the application.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    - None. The `ArbitraryCondition` directly uses the provided SQL template without any sanitization or input validation of the SQL template string itself. The substitutions are parameterized, but the core SQL structure is not protected.

- Missing Mitigations:
    - **Input validation for SQL templates**: The `sql_template` argument in `ArbitraryCondition` should be strictly validated to prevent injection of malicious SQL code. A whitelist approach or a more robust parsing and sanitization mechanism for the SQL template string is needed.
    - **Discourage use of ArbitraryCondition**: The documentation should strongly discourage the use of `ArbitraryCondition` for general queries due to its inherent risks, and recommend safer, parameterized ORM query methods whenever possible. If `ArbitraryCondition` must be used, provide clear security guidelines and examples of safe usage, emphasizing the developer's responsibility for sanitization.

- Preconditions:
    - The application must use `ArbitraryCondition` and allow user-controlled input to influence the `sql_template` argument, directly or indirectly.
    - An attacker needs to be able to influence the arguments passed to the `where()` or similar query methods, specifically by injecting a malicious `ArbitraryCondition` object.

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

    3. **`spanner_orm/query.py` - `SpannerQuery._build`**:
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
    ```
    - The `_build` method concatenates SQL segments, including the potentially malicious SQL from `ArbitraryCondition`, into the final SQL query `self._sql`.

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

- Security Test Case:
    1. **Setup**: Assume an attacker has control over input parameters that are used to construct conditions in a `where()` query. In this test case, we'll simulate this by directly constructing a malicious `ArbitraryCondition`.
    2. **Malicious Input**: Create a malicious `ArbitraryCondition` that injects SQL code. For example, to attempt to read data from a table named `AdminTable` (assuming it exists but should not be accessible via normal ORM methods):
    ```python
    malicious_condition = spanner_orm.ArbitraryCondition(
        sql_template="TRUE) UNION ALL SELECT key FROM AdminTable WHERE (TRUE = ", # SQL injection payload
        segment=spanner_orm.condition.Segment.WHERE,
    )
    ```
    3. **Execute Query**: Use the `where()` method with the malicious condition.
    ```python
    results = SmallTestModel.where(malicious_condition) # Injecting malicious condition
    ```
    4. **Verify Exploitation**: Check if the query results contain data from the `AdminTable`. If the SQL injection is successful, the results may contain data from `AdminTable` columns (in this example, the 'key' column is selected). In a real-world scenario, an attacker could exfiltrate sensitive data, modify data, or perform other unauthorized actions. In this test case, we will simply assert that the query executes without error, which is an indicator of successful injection.  A more robust test would involve setting up a test table and verifying data exfiltration, but for demonstration purposes, checking for execution without error is sufficient.

    5. **Expected Outcome**: The test should demonstrate that the ORM executes the query with the injected SQL without raising errors related to SQL syntax, confirming the SQL injection vulnerability. The vulnerability is confirmed if the query, despite the malicious SQL, is processed by the ORM and sent to Spanner without proper sanitization, potentially leading to unintended data access or manipulation (though data access verification from a potentially non-existent table like `AdminTable` is not feasible in this test without setting up such a table, the successful execution is the key indicator).

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

This vulnerability allows for direct SQL injection through the `ArbitraryCondition` feature, posing a significant security risk. The lack of sanitization on the `sql_template` argument makes it possible for attackers to bypass the ORM's intended query construction and execute arbitrary SQL commands.
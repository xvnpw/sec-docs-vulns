## Vulnerability List

### 1. SQL Injection via `ArbitraryCondition`

* Description:
    1. An attacker can use the `ArbitraryCondition` to inject malicious SQL code into Spanner queries.
    2. The `ArbitraryCondition` allows users to provide raw SQL fragments with substitutions.
    3. If the substitutions are not properly sanitized, an attacker could craft malicious input that gets directly embedded into the SQL query, leading to unintended data access or manipulation.
    4. For example, in `ArbitraryCondition`, the `sql_template` and `substitutions` parameters are taken directly from the user without any sanitization.
    5. When `_sql()` method is called, it substitutes the provided values into the template using string substitution, without escaping or validating the values.
    6. This can be exploited by injecting malicious SQL code within the substitution values.

* Impact:
    - **Data Breach:** An attacker could bypass intended access controls and retrieve sensitive data from the Spanner database by crafting malicious SQL queries.
    - **Data Manipulation:** An attacker could potentially modify or delete data in the Spanner database by injecting malicious SQL statements like `UPDATE`, `DELETE`, or `INSERT`.
    - **Privilege Escalation:** In certain scenarios, if the application's Spanner service account has broader permissions, a successful SQL injection could lead to privilege escalation within the Spanner database.

* Vulnerability Rank: High

* Currently Implemented Mitigations:
    - None. The code directly uses user-provided SQL templates and substitutions in `ArbitraryCondition` without sanitization.

* Missing Mitigations:
    - **Input Sanitization:** Implement robust input sanitization and validation for the `sql_template` and `substitutions` parameters in `ArbitraryCondition`.
    - **Prepared Statements:** Internally, the ORM uses parameterized queries for conditions like `equal_to()`, but `ArbitraryCondition` bypasses this by allowing raw SQL. The library should enforce the use of parameterized queries for all user-provided input, even within `ArbitraryCondition`.
    - **Principle of Least Privilege:** Ensure that the Spanner service account used by the application has the minimum necessary privileges to perform its intended operations, limiting the impact of potential SQL injection attacks.

* Preconditions:
    - The application must use `ArbitraryCondition` and allow user-controlled input to be used as part of the `sql_template` or `substitutions`.

* Source Code Analysis:
    1. **File:** `/code/spanner_orm/condition.py`
    2. **Class:** `ArbitraryCondition`
    3. **Method:** `__init__(self, sql_template: str, substitutions: Mapping[str, Substitution] = immutabledict.immutabledict(), *, segment: Segment)`
        ```python
        class ArbitraryCondition(Condition):
            ...
            def __init__(
                self,
                sql_template: str,
                substitutions: Mapping[str, Substitution] = immutabledict.immutabledict(),
                *,
                segment: Segment,
            ):
                super().__init__()
                self._sql_template = string.Template(sql_template) # User provided template
                self._substitutions = substitutions # User provided substitutions
                self._segment = segment
                ...
        ```
    4. **Method:** `_sql(self) -> str`
        ```python
            def _sql(self) -> str:
                """See base class."""
                return self._sql_template.substitute({ # Vulnerable string substitution
                    k: self._sql_for_substitution(k, v)
                    for k, v in self._substitutions.items()
                })
        ```
    5. **Vulnerability:** The `_sql()` method in `ArbitraryCondition` uses `string.Template.substitute()` to directly embed user-provided substitution values into the SQL query. This method performs simple string substitution without any sanitization or escaping, making it vulnerable to SQL injection. An attacker can craft malicious substitution values that contain SQL code, which will be executed by Spanner.

* Security Test Case:
    1. **Setup:** Assume a `TestModel` exists with columns `id` (String, primary key) and `value` (Integer). Populate the table with some data.
    2. **Craft Malicious Input:** Create an `ArbitraryCondition` where the `sql_template` is designed to inject malicious SQL.
        ```python
        malicious_condition = spanner_orm.ArbitraryCondition(
            sql_template="value = $evil_value",
            substitutions={
                "evil_value": spanner_orm.Param.from_value("1 OR 1=1") # Injecting 'OR 1=1'
            },
            segment=spanner_orm.condition.Segment.WHERE
        )
        ```
    3. **Execute Query:** Use the `where()` method with the malicious condition.
        ```python
        results = TestModel.where(malicious_condition)
        ```
    4. **Verify Exploitation:** Check if the query results include data that should not be accessible under normal circumstances. In this case, `OR 1=1` will always be true, effectively bypassing the intended condition and potentially returning all rows in the `TestModel` table, regardless of their 'value'.
    5. **Expected Result:** The query should return all rows from `TestModel`, demonstrating that the injected SQL (`OR 1=1`) was successfully executed, bypassing the intended filtering. This proves the SQL injection vulnerability.
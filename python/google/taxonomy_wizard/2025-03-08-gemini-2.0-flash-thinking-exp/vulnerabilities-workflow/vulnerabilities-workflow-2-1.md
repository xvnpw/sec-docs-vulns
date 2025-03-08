### Vulnerability List

- Vulnerability Name: **Unrestricted SQL Query Template Generation in Configurator Cloud Function**
- Description:
    1. An attacker with access to the Google Admin Sheet can modify the 'validation_query_template' within the TaxonomyDimension configuration.
    2. The Configurator Cloud Function fetches this 'validation_query_template' from the Google Sheet without proper sanitization or validation.
    3. This unsanitized template is then used by the JinjaRenderer to generate SQL queries that are executed against BigQuery.
    4. By injecting malicious Jinja syntax or SQL code within the 'validation_query_template', an attacker can potentially execute arbitrary SQL queries in the BigQuery dataset.
- Impact:
    - **High Impact:** Unauthorized data access, data manipulation, or even deletion within the BigQuery dataset associated with the Taxonomy Wizard project. An attacker could read sensitive taxonomy data, modify existing configurations, or potentially escalate privileges within the BigQuery environment depending on the service account permissions.
- Vulnerability Rank: **High**
- Currently Implemented Mitigations:
    - **None:** The code does not implement any input validation or sanitization on the 'validation_query_template' fetched from the Google Sheet before using it in Jinja rendering.
- Missing Mitigations:
    - **Input Sanitization:** Implement strict input validation and sanitization for the 'validation_query_template' in the Configurator Cloud Function before using it with the JinjaRenderer. This should include escaping Jinja syntax and SQL keywords or using a safer templating mechanism that prevents code injection.
    - **Principle of Least Privilege:**  Ensure that the service account used by the Configurator Cloud Function has the minimum necessary BigQuery permissions. Avoid granting `bigquery.dataEditor` or `bigquery.admin` roles if `bigquery.dataViewer` and `bigquery.jobUser` suffice for intended functionality.
- Preconditions:
    - An attacker must have edit access to the Google Admin Sheet used to configure the Taxonomy Wizard. This access is typically controlled within the organization using the Google Admin console.
- Source Code Analysis:
    1. **File: `/code/resources/python_cloud_functions/configurator/main.py`**
    2. The `create_taxonomy_spec_set` function in `main.py` orchestrates the creation of `Specification` objects.
    3. **File: `/code/resources/python_cloud_functions/configurator/taxonomy.py`**
    4. Inside the `Specification` class, the `create_validation_query_template` method is called. This method uses `JinjaRenderer` to generate SQL queries.
    5. **File: `/code/resources/python_cloud_functions/configurator/taxonomy.py`**
    6. ```python
       def create_validation_query_template(self, renderer: JinjaRenderer):
           if self.field_structure_type == FieldStructureType.DELIMITED:
               self.validation_query_template = \
                   renderer.load_and_render_template(_DELIMITED_VALIDATOR_FILENAME,
                                                     spec=self)
           else:
               raise Exception(
                   f'Unsupported `field_structure_type` "{self.field_structure_type} in Spec "{self.name}".'
               )
       ```
    7. The `renderer.load_and_render_template` function from `JinjaRenderer` class is used to render the template.
    8. **File: `/code/resources/python_cloud_functions/configurator/jinja_renderer.py`**
    9. ```python
       class JinjaRenderer:
           """Class to help with Jinja2."""
           _env: jinja2.Environment

           def __init__(self, file_path: str = _DEFAULT_TEMPLATES_FILE_PATH):
               loader = jinja2.FileSystemLoader(searchpath=file_path, followlinks=True)
               autoescape = jinja2.select_autoescape(enabled_extensions=('html', 'xml'),
                                                     default_for_string=True)
               self._env = jinja2.Environment(autoescape=autoescape, loader=loader)

           def load_and_render_template(self, file_name: str, **kwargs: Any):
               template = self._env.get_template(file_name)
               return template.render(kwargs)
       ```
    10. The `JinjaRenderer` uses `jinja2.Environment` to load and render templates. Importantly, `autoescape` is enabled, but this only escapes HTML and XML, not SQL or Jinja syntax itself.
    11. **File: `/code/resources/python_cloud_functions/configurator/main.py`**
    12. The `validation_query_template` itself originates from the Google Sheet configuration, specifically from the 'TaxonomyDimension' data, which is processed in `create_taxonomy_dimensions` function within `main.py`.
    13. **Vulnerability:** There is no sanitization or validation of the `validation_query_template` retrieved from the Google Sheet before it's passed to the Jinja renderer. This allows an attacker to inject arbitrary Jinja syntax or SQL code into the template through the Google Sheet, leading to potential SQL injection when the Configurator Cloud Function generates and uses these queries.

- Security Test Case:
    1. **Precondition:** Ensure you have deployed the Configurator Cloud Function and have access to the Admin Google Sheet.
    2. **Step 1:** Open the Admin Google Sheet.
    3. **Step 2:** Navigate to the sheet containing 'TaxonomyDimension' data (e.g., 'Taxonomy Dimensions').
    4. **Step 3:** Locate a 'validation_query_template' column (this column might need to be added to the sheet schema if it's not already present, or find the configuration mechanism that populates this, assuming it's intended to be configurable via the sheet, based on the description).
    5. **Step 4:** In the 'validation_query_template' for a specific TaxonomyDimension, inject malicious Jinja/SQL code. For example, if the template is supposed to select data, try injecting code that performs a different action, like a `UNION` clause to extract data from another table or a function call. A simple test could be to try to make the query fail in a predictable way by injecting invalid SQL. For instance, if the original template is like `SELECT ... FROM ... WHERE ...` try replacing it with `SELECT SLEEP(10)`.
    6. **Step 5:** Trigger the Configurator Cloud Function to regenerate the taxonomy specifications. This is typically done through a button or menu item in the Admin Sheet that calls the Apps Script, which in turn calls the Configurator Cloud Function with the updated sheet data.
    7. **Step 6:** Monitor the logs of the Configurator Cloud Function. If the injected SQL is executed, you might observe a delay (if using `SLEEP`), error messages related to the injected code, or unexpected data modifications in BigQuery, depending on the nature of the injection and the permissions.
    8. **Step 7:** Examine the BigQuery logs (if available and permissions allow) to see the executed queries. Confirm if the injected SQL or Jinja code was indeed part of the query executed against BigQuery.
    9. **Expected Result:** If the vulnerability exists, you should observe evidence that the injected code was processed and potentially executed by BigQuery, confirming the SQL injection vulnerability. For the `SLEEP(10)` example, the Configurator Cloud Function execution might take significantly longer than usual. For invalid SQL injection, you should see BigQuery error messages in the logs.

This vulnerability allows for significant unauthorized actions within the BigQuery environment, making it a **High** severity issue. Immediate mitigation through input sanitization and principle of least privilege is recommended.
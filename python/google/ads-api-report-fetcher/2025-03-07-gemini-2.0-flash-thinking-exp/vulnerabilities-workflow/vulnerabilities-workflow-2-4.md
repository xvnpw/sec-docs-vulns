- Vulnerability Name: GAQL Injection via Macros
- Description:
    1. An attacker crafts a malicious query file containing a macro, for example: `SELECT customer.id FROM customer WHERE customer.id = "{account_id}"`.
    2. The attacker then provides a malicious value for the `account_id` macro through command-line arguments, such as `--macro.account_id="1234567890 UNION SELECT user_list.name FROM user_list --"`.
    3. When `gaarf` processes the query file, it substitutes the macro `{account_id}` with the attacker-provided malicious value without proper sanitization or escaping.
    4. This results in a modified GAQL query being sent to the Google Ads API, such as: `SELECT customer.id FROM customer WHERE customer.id = "1234567890 UNION SELECT user_list.name FROM user_list --"`.
    5. The injected SQL code `-- UNION SELECT user_list.name FROM user_list` bypasses the intended query logic and potentially allows the attacker to extract data from `user_list` table, which they are not supposed to access with the original query.
- Impact:
    - Unauthorized Access: Attackers can bypass intended data access restrictions and retrieve sensitive Google Ads data they are not authorized to view.
    - Data Breach: Successful exploitation can lead to the extraction of confidential customer data, report data, or other sensitive information managed within Google Ads.
    - Data Exfiltration: Attackers can potentially exfiltrate large volumes of data by crafting queries that iterate over or dump entire tables.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - None. The code directly substitutes macro values into the query string without sanitization or validation in both Python and NodeJS versions.
- Missing Mitigations:
    - Input Sanitization: Implement sanitization of macro values to remove or escape potentially harmful characters or SQL keywords before substitution.
    - Input Validation: Validate macro values against expected formats or patterns to ensure they conform to the intended query logic.
    - Parameterized Queries: Utilize parameterized queries or prepared statements provided by the Google Ads API client libraries to separate query logic from user-supplied data, preventing direct SQL injection.
- Preconditions:
    - The attacker must be able to provide macro values to the `gaarf` tool. This is typically done through command-line arguments using the `--macro.` flag or through configuration files.
    - The `gaarf` tool must be configured to execute queries against a Google Ads account accessible to the attacker (or an account the attacker wants to target).
- Source Code Analysis:
    - **Python:**
        - In `py/gaarf/query_post_processor.py`, the `replace_params_template` method performs macro substitution using Python's built-in `format()` function.
        - ```python
          def replace_params_template(
            self, query_text: str, params: Optional[Dict[str, Any]] = None
          ) -> str:
            ...
            if macros := params.get('macro'):
              query_text = query_text.format(**macros) # Vulnerable line
              logger.debug('Query text after macro substitution:\n%s', query_text)
            ...
            return query_text
          ```
        - The `format()` function directly substitutes the macro values into the query string without any sanitization. This makes the application vulnerable to GAQL injection if macro values are maliciously crafted.
    - **NodeJS:**
        - In `js/src/lib/query-parser.ts`, the `QueryParser` class handles macro substitution.
        - ```typescript
          private replaceMacros(query: string, params: Record<string, string>): string {
            if (!params?.macro) return query;
            let res = query;
            for (const macro in params.macro) {
              const macroValue = params.macro[macro];
              const macroRegexp = new RegExp(`{${macro}}`, 'g');
              res = res.replace(macroRegexp, macroValue); # Vulnerable line
            }
            return res;
          }
          ```
        - The `replaceMacros` method uses simple string replacement (`replace`) with regular expressions to substitute macro values. Similar to the Python version, this method does not perform any sanitization or validation of macro values, leading to GAQL injection vulnerability.
- Security Test Case:
    1. Create a query file named `malicious_query.sql` with the following content:
        ```sql
        SELECT customer.id FROM customer WHERE customer.id = "{account_id}"
        ```
    2. Run `gaarf` (NodeJS version) with the following command, providing a malicious macro value:
        ```bash
        gaarf malicious_query.sql --account=YOUR_MCC_ACCOUNT_ID --output=console --macro.account_id="'1234567890' UNION SELECT user_list.name FROM user_list --"
        ```
        or (Python version):
        ```bash
        gaarf malicious_query.sql --account=YOUR_MCC_ACCOUNT_ID --output=console --macro.account_id="'1234567890' UNION SELECT user_list.name FROM user_list --"
        ```
        Replace `YOUR_MCC_ACCOUNT_ID` with a valid MCC account ID.
    3. Observe the output in the console. If the vulnerability is successfully exploited, the output will likely contain data from the `user_list` table, indicating unauthorized data access beyond the intended scope of `customer.id` from the `customer` table.
    4. Examine the logs (if verbose logging is enabled) to see the constructed GAQL query. It should reflect the injected SQL code, confirming the GAQL injection vulnerability.

- Vulnerability Name: GAQL Injection via Templates
- Description:
    1. An attacker crafts a malicious query file using template syntax (Jinja or Nunjucks), for example:
        ```sql
        SELECT campaign.id FROM campaign {% if condition %} WHERE campaign.status = 'ENABLED' {% else %} WHERE campaign.status = 'PAUSED' {% endif %} {{ injected_code }}
        ```
    2. The attacker provides a malicious template value, for example: `--template.injected_code="UNION SELECT user_list.name FROM user_list --"`.
    3. When `gaarf` processes the query file, the template engine (Jinja or Nunjucks) renders the template, substituting `{{ injected_code }}` with the malicious value without sanitization.
    4. This results in a modified GAQL query being sent to the Google Ads API, such as: `SELECT campaign.id FROM campaign  UNION SELECT user_list.name FROM user_list --`.
    5. Similar to macro injection, the injected SQL code can alter the query logic, potentially leading to unauthorized data extraction.
- Impact:
    - Same as GAQL Injection via Macros.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - None. Template rendering is performed without any specific security considerations for preventing GAQL injection.
- Missing Mitigations:
    - Secure Template Configuration: Configure the template engine (Jinja/Nunjucks) to minimize the risk of code injection. However, this might not be sufficient to prevent GAQL injection in all cases.
    - Input Sanitization within Templates: Sanitize user-provided template values within the template rendering process to neutralize potentially malicious code.
    - Consider Alternatives to String Interpolation: Explore alternative methods for dynamic query construction that avoid direct string interpolation of user-provided values into GAQL queries.
- Preconditions:
    - The attacker must be able to provide template values to the `gaarf` tool, typically via command-line arguments using the `--template.` flag or configuration files.
    - The query files must utilize template syntax (Jinja/Nunjucks) to enable template-based injection.
- Source Code Analysis:
    - **Python:**
        - In `py/gaarf/query_post_processor.py`, the `expand_jinja` method uses Jinja2 to render templates.
        - ```python
          from jinja2 import Environment, FileSystemLoader, Template
          ...
          def expand_jinja(
            self, query_text: str, template_params: Optional[Dict[str, Any]] = None
          ) -> str:
            ...
            query = Template(query_text) # Vulnerable line - direct template creation
            ...
            return query.render(template_params) # Vulnerable line - direct rendering with user input
          ```
        - The code directly creates a Jinja `Template` object from the query string and renders it with user-supplied template parameters. Jinja2, by default, does not automatically sanitize or escape output against injection attacks in this usage pattern.
    - **NodeJS:**
        - In `js/src/lib/query-parser.ts`, the `QueryParser` class uses Nunjucks for template rendering.
        - ```typescript
          import {Environment, FileSystemLoader} from 'nunjucks';
          ...
          private renderTemplate(query: string, params: Record<string, string>): string {
            if (!params?.template) return query;
            const env = new Environment(new FileSystemLoader('.')); # Potentially insecure FileSystemLoader
            const template = env.fromString(query); # Vulnerable line - direct template loading from string
            return template.render(params.template); # Vulnerable line - direct rendering with user input
          }
          ```
        - The NodeJS version uses Nunjucks with `FileSystemLoader`, which might introduce additional risks if template files are loaded from attacker-controlled locations. The `renderTemplate` method directly renders the template string with user-provided parameters, making it vulnerable to template injection if the template or parameters are maliciously crafted.
- Security Test Case:
    1. Create a query file named `malicious_template_query.sql` with the following content:
        ```sql
        SELECT campaign.id FROM campaign {% if template_param == 'malicious' %} {{ injected_code }} {% endif %}
        ```
    2. Run `gaarf` (NodeJS version) with the following command, providing a malicious template value:
        ```bash
        gaarf malicious_template_query.sql --account=YOUR_MCC_ACCOUNT_ID --output=console --template.template_param=malicious --template.injected_code="UNION SELECT user_list.name FROM user_list --"
        ```
        or (Python version):
        ```bash
        gaarf malicious_template_query.sql --account=YOUR_MCC_ACCOUNT_ID --output=console --template.template_param=malicious --template.injected_code="UNION SELECT user_list.name FROM user_list --"
        ```
        Replace `YOUR_MCC_ACCOUNT_ID` with a valid MCC account ID.
    3. Observe the output in the console. Similar to the macro injection test, successful exploitation will likely result in data from `user_list` being displayed.
    4. Examine the logs to verify the constructed GAQL query, which should contain the injected SQL code from the template.
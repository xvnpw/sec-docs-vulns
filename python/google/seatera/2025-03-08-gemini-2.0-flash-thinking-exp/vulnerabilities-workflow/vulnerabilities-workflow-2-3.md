### Vulnerability List

- Vulnerability Name: Input Validation Vulnerability in Run Settings

- Description:
    User inputs for clicks, impressions, CTR, cost, conversions, start_date, and end_date in the "Run Settings" section of the web application are not properly validated before being processed. An attacker can manipulate these inputs by providing negative numbers, non-numeric values, or dates in incorrect formats. This can lead to unexpected behavior in the application, potentially skewing the analysis results or causing application errors.

- Impact:
    Generation of skewed or misleading keyword and exclusion recommendations in the Google Sheets report. Although this does not directly expose sensitive data, it can lead advertisers to make incorrect decisions based on flawed analysis. In certain scenarios, providing unexpected input types might lead to application-level errors, although this was not confirmed to be denial of service.

- Vulnerability Rank: Medium

- Currently Implemented Mitigations:
    None. There is no input validation implemented in the `frontend.py` to sanitize or validate user-provided parameters before they are passed to the backend for processing and query generation.

- Missing Mitigations:
    Input validation should be implemented in the `frontend.py` to ensure that:
    * Clicks, impressions, cost, and conversions are non-negative numeric values (integers or floats as appropriate).
    * CTR is a non-negative numeric value within a valid percentage range.
    * Start and end dates are valid date formats and the start date is not after the end date.
    * Consider using type casting and error handling to gracefully manage unexpected input types.

- Preconditions:
    The attacker must have access to the public URL of the deployed SeaTerA web application and be able to interact with the "Run Settings" form in the frontend.

- Source Code Analysis:
    1. File: `/code/frontend.py`
    2. In the `Run Settings` expander, the code uses `st.number_input` and `st.date_input` to collect user inputs for thresholds and date ranges.
    3. Example for clicks threshold:
       ```python
       clicks.number_input("Clicks", min_value=0, key="clicks")
       ```
       While `min_value=0` prevents negative clicks via the UI widget, it does not enforce type validation or handle non-numeric input directly at the input stage.
    4. These input values are stored in `st.session_state` and passed as a dictionary named `parameters` to the `run_from_ui` function in `main.py`.
    5. Function `run_tool` in `frontend.py` collects parameters like this:
       ```python
       parameters = {
               'start_date': str(st.session_state.start_date),
               'end_date': str(st.session_state.end_date),
               'clicks': st.session_state.clicks,
               'impressions': st.session_state.impressions,
               'ctr': st.session_state.ctr,
               'cost': st.session_state.cost,
               'conversions': st.session_state.conversions,
               'accounts': st.session_state.accounts_selected
           }

       run_from_ui(parameters, st.session_state.config)
       ```
    6. File: `/code/main.py`
    7. The `run_from_ui` function then calls `RunSettings.from_dict(params)`:
       ```python
       run_settings = RunSettings.from_dict(params)
       ```
    8. File: `/code/utils/entities.py`
    9. In `RunSettings.from_dict` and `RunSettings.__init__`, basic date validation is performed to check for date presence and order, and cost is converted to cost micros. However, no explicit type validation or range checks are performed on the threshold values (clicks, impressions, ctr, conversions, cost) themselves to ensure they are valid numbers.
    10. Subsequently, in `/code/utils/ads_searcher.py`, these unvalidated threshold values are directly embedded into the GAQL queries using f-strings within the `SearchTermBuilder.build` method.
    11. Because of the missing input validation in `frontend.py` and `utils/entities.py`, invalid or unexpected input types for thresholds can be passed to the GAQL query generation.

- Security Test Case:
    1. Open the SeaTerA web application in a browser.
    2. Navigate to the "Run Settings" section.
    3. In the "Thresholds pickers" section, specifically for the "Clicks" input field, enter a non-numeric value such as "abc".
    4. Click the "Run" button.
    5. Observe the application's behavior. Check if:
        * The application frontend or backend throws an error due to the invalid input.
        * The application proceeds to generate a report, potentially with skewed or incorrect results due to the invalid input being processed.
        * Check the application logs for any error messages indicating issues with data type conversion or query execution.
    6. Repeat steps 3-5 with other threshold fields (Impressions, CTR, Cost, Conversions), trying different types of invalid inputs such as:
        * Negative numbers (even though `min_value=0` is set, backend might not handle negative values correctly if passed programmatically).
        * Very large numbers that might exceed the expected range.
        * Special characters or symbols.
    7. For the "Start Date" and "End Date" fields, try entering dates in incorrect formats (e.g., "2023-June-01", "01/01/2023") or an invalid date range where the start date is after the end date.
    8. Verify that the application does not crash or produce unexpected results and ideally provides user-friendly error messages indicating the invalid inputs, preventing the execution of the analysis with invalid parameters.
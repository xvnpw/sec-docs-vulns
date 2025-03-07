- Vulnerability Name: Unintended SDLC Event Injection in Production
- Description:
    - A user is instructed to download and run JMeter scripts from this repository for a demo purpose.
    - The `example.jmx` script includes a "Tear Down Thread Group" that sends a Software Delivery Lifecycle (SDLC) event to a Dynatrace tenant.
    - The script is pre-configured with placeholders (`DT_TENANT_LIVE_PLACEHOLDER` and `DT_API_TOKEN_PLACEHOLDER`) for the Dynatrace tenant URL and API token, which are intended to be replaced by the user.
    - If a user is misled into using a production Dynatrace API token and running the script against their production Dynatrace environment, the SDLC event will be unintentionally sent to their production system.
    - This could lead to the injection of demo/test data into a production Dynatrace environment, potentially causing misleading data in production dashboards and reports, and triggering unintended workflows or automations based on these SDLC events.
- Impact:
    - Injection of demo/test SDLC events into a production Dynatrace environment.
    - Potential for misleading data in production Dynatrace dashboards and reports, affecting the accuracy of production monitoring and analysis.
    - Risk of triggering unintended workflows or automations in production that are configured to react to SDLC events, leading to unexpected actions in the production environment.
- Vulnerability Rank: Medium
- Currently Implemented Mitigations:
    - Documentation in `docs/run-demo.md` advises that the default target is `example.com`, and users should modify `example.jmx` to target their own instrumented service.
    - The documentation explicitly states "Expect No Traffic in Dynatrace" by default when using the unmodified script, reinforcing that it's not intended for production monitoring without modification.
    - The README and documentation clearly present this project as a demo, implying it is for learning and testing purposes, not production use.
    - A disclaimer in `docs/snippets/disclaimer.md` specifies the project is a demo, support is provided via GitHub issues only, and materials are "as-is" without warranties, urging users to use them at their own risk.
- Missing Mitigations:
    - Add a prominent warning in the `docs/run-demo.md` and potentially in the `README.md` specifically cautioning users against running the demo scripts with production API tokens or against production Dynatrace environments.
    - Consider adding comments within the `example.jmx` script itself, near the `DT_TENANT_LIVE_PLACEHOLDER` and `DT_API_TOKEN_PLACEHOLDER` variables, to explicitly warn users about the production environment risks.
    - Implement a check within the JMeter script (though this might be complex within JMeter itself) or in the setup instructions to remind users to verify they are not using a production API token and environment when running the demo.
- Preconditions:
    - An attacker misleads a user into believing it is safe or necessary to run the provided JMeter scripts against a production environment.
    - The user possesses a valid Dynatrace API token with `openpipeline.events_sdlc` permission for their production Dynatrace environment.
    - The user incorrectly configures the `example.jmx` script (or fails to modify the placeholders) to target their production Dynatrace tenant instead of a test or demo environment.
    - The user successfully executes the JMeter script.
- Source Code Analysis:
    - File: `/code/jmeterscripts/example.jmx`
        - Locate the "Tear Down Thread Group" within the JMeter script. This thread group is designed to execute after the main load test is complete.
        - Inside the "Tear Down Thread Group", identify the HTTP Request sampler. This sampler is configured to send the SDLC event to Dynatrace.
        - Observe that the HTTP Request sampler is set to perform a `POST` request to the endpoint `/platform/ingest/v1/events.sdlc`.
        - Notice that the "Server Name or IP" field in the HTTP Request sampler is set to the variable `${DT_TENANT_LIVE_PLACEHOLDER}`, and the "Path" is set to `/platform/ingest/v1/events.sdlc`. These placeholders are intended to be replaced with the Dynatrace tenant URL.
        - Examine the "HTTP Header Manager" within the HTTP Request sampler. It includes an "Authorization" header which uses `${DT_API_TOKEN}` as the value. This placeholder is intended to be replaced with a Dynatrace API token.
        - The script logic within the "Tear Down Thread Group" will unconditionally send an SDLC event to the configured Dynatrace endpoint using the provided API token upon completion of the JMeter load test, regardless of whether the target environment is production or test.
    - File: `/code/docs/run-demo.md`
        - Review the instructions provided to users for running the demo.
        - The instructions guide users to execute the `example.jmx` script.
        - While the documentation mentions modifying the target URL for instrumented services, it does not explicitly and strongly warn against using production API tokens or running against production Dynatrace environments when demonstrating the SDLC event functionality.
- Security Test Case:
    1. Pre-requisites:
        - Obtain a valid Dynatrace API token for a production Dynatrace environment. Ensure this token has the `openpipeline.events_sdlc` permission to send SDLC events.
        - Download or clone the GitHub repository containing the JMeter scripts and documentation to your local machine or a test environment (like GitHub Codespaces as suggested in the demo).
    2. Configure JMeter Script for Production:
        - Open the `example.jmx` file located in the `jmeterscripts` directory using a text editor.
        - Locate the `DT_TENANT_LIVE_PLACEHOLDER` variable within the "Tear Down Thread Group" -> HTTP Request sampler -> "Server Name or IP" field. Replace `DT_TENANT_LIVE_PLACEHOLDER` with the actual URL of your production Dynatrace tenant (e.g., `your-production-tenant.live.dynatrace.com`).
        - Locate the `DT_API_TOKEN_PLACEHOLDER` variable within the "Tear Down Thread Group" -> HTTP Request sampler -> "HTTP Header Manager" -> "Authorization" header. Replace `DT_API_TOKEN_PLACEHOLDER` with the valid production Dynatrace API token obtained in step 1.
        - Save the changes to the `example.jmx` file.
    3. Execute JMeter Script:
        - Navigate to the `apache-jmeter/bin` directory within the downloaded repository in your terminal.
        - Execute the JMeter script using the command: `./jmeter.sh -n -t /path/to/your/repository/jmeterscripts/example.jmx` (replace `/path/to/your/repository` with the actual path to the repository on your system).
    4. Verify SDLC Event in Production Dynatrace:
        - Once the JMeter script execution is complete, log in to your production Dynatrace environment using a web browser.
        - Navigate to the Dynatrace Notebooks feature (or use DQL query). Press `ctrl + k` and search for `notebooks`.
        - Create a new notebook or open an existing one.
        - Add a new DQL section to the notebook.
        - Paste and execute the following DQL query to search for SDLC events from the demo:
            ```
            fetch events
            | filter event.kind == "SDLC_EVENT"
            | filter event.provider == "jmeter"
            | filter event.category == "finished"
            ```
        - Examine the query results. You should observe a new SDLC event listed, indicating that the demo script has successfully sent an event to your production Dynatrace environment.
        - Inspect the details of the event to confirm it matches the expected data from the `example.jmx` script (e.g., provider: `jmeter`, category: `finished`, and other metadata).
    5. Expected Result:
        - The security test case is successful if a new SDLC event, originating from the execution of `example.jmx`, is found within the production Dynatrace environment. This confirms the vulnerability of unintended SDLC event injection into production when using production credentials and environment with the demo script.
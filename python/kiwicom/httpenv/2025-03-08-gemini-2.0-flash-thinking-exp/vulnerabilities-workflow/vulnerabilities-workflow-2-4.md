- Vulnerability name: Unprotected Environment Variables Access
- Description:
  1. An attacker can send a GET request to the `/v1/<name>` endpoint, replacing `<name>` with the name of the environment variable they want to retrieve.
  2. The `httpenv` service, without any authentication or authorization, directly accesses the in-memory registry `envs` and retrieves the value associated with the provided `<name>`.
  3. The service returns the value of the environment variable in the HTTP response body.
  4. If the attacker knows or can guess the name of sensitive environment variables, they can retrieve their values.
- Impact:
  - Exposure of sensitive information stored in environment variables.
  - This can include passwords, API keys, database credentials, and other secrets.
  - Successful exploitation can lead to unauthorized access to other systems or data, depending on the nature of the exposed secrets.
- Vulnerability rank: High
- Currently implemented mitigations:
  - None. The service is implemented without any access control or authentication mechanisms.
- Missing mitigations:
  - **Authentication:** Implement authentication to verify the identity of the requester before granting access to environment variables.
  - **Authorization:** Implement authorization to control which users or roles are allowed to access specific environment variables or the entire service.
  - **Network Access Control:** Restrict network access to the service to only trusted networks or IP addresses (e.g., using firewall rules or network policies). This is especially important if the service is intended to be used only within a CI/CD pipeline.
- Preconditions:
  - The `httpenv` service must be deployed and accessible over the network to the attacker.
  - The attacker needs to know or guess the names of the environment variables stored in the service.
- Source code analysis:
  - The vulnerability lies within the `v1(name)` function in `/code/httpenv.py`:
    ```python
    @route('/v1/<name>')
    def v1(name):
        return envs.get(name, '')
    ```
    - This function is directly mapped to the `/v1/<name>` endpoint using `bottle's` `@route` decorator.
    - When a GET request is made to `/v1/<name>`, this function is executed.
    - `envs.get(name, '')` retrieves the value associated with the `name` key from the `envs` dictionary. If the key is not found, it returns an empty string `''`.
    - The retrieved value (or empty string) is directly returned as the HTTP response body.
    - There are no checks in place to validate the requester or their permissions before accessing and returning the environment variable.
  - Visualization:
    ```
    [Attacker] ---GET /v1/<variable_name>---> [httpenv Service]
    [httpenv Service] ---envs.get(<variable_name>)---> [envs Dictionary]
    [envs Dictionary] ---(value or '' )---> [httpenv Service]
    [httpenv Service] ---HTTP Response (value or '')---> [Attacker]
    ```
- Security test case:
  1. Deploy the `httpenv` service based on the provided `Dockerfile` and `httpenv.py`. Ensure the service is accessible over the network (e.g., on a public IP or within a test network).
  2. Using `curl` or `wget`, add a sensitive environment variable named `TEST_SECRET` with the value `secret_value` to the service:
     ```bash
     curl "http://<service-ip>/v1/add/TEST_SECRET/secret_value"
     ```
  3. Now, attempt to retrieve the value of `TEST_SECRET` from a different machine or network that has network access to the deployed `httpenv` service:
     ```bash
     curl "http://<service-ip>/v1/TEST_SECRET"
     ```
  4. **Expected Result:** The response body should contain the value `secret_value`, confirming that the environment variable's value has been successfully retrieved without any authentication or authorization. This demonstrates the information disclosure vulnerability.
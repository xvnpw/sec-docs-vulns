- Vulnerability Name: Unauthenticated Information Disclosure
- Description: An attacker can retrieve any environment variable stored in the `httpenv` service by sending an unauthenticated GET request to the `/v1/<name>` endpoint. This endpoint is designed to return the value of the environment variable specified by `<name>` directly in the HTTP response body. There are no authentication or authorization checks in place to restrict access to this endpoint. An attacker, if they can reach the service, can query arbitrary environment variables by guessing or knowing their names.
- Impact: High. Successful exploitation of this vulnerability allows an attacker to gain access to sensitive information stored as environment variables within the `httpenv` service. This could include конфиденциальные data such as API keys, database credentials, passwords, internal service addresses, and other secrets. Exposure of such information can lead to further attacks, such as unauthorized access to other systems, data breaches, or service disruptions.
- Vulnerability Rank: High
- Currently Implemented Mitigations: None. The service, as implemented, lacks any form of authentication or access control. Both `/v1/<name>` and `/v1/add/<name>/<value>` endpoints are publicly accessible without any restrictions.
- Missing Mitigations:
    - Authentication: Implement authentication mechanisms to verify the identity of the requester before granting access to the `/v1/<name>` endpoint. This could involve API keys, tokens, or other standard authentication methods.
    - Authorization: Implement authorization mechanisms to control which users or services are allowed to access specific environment variables or the entire endpoint. This could be role-based access control or attribute-based access control.
    - Network Segmentation: Restrict network access to the `httpenv` service to only authorized networks or IP addresses. This can be achieved through firewall rules or network policies to limit exposure of the service.
    - Encryption: While not directly mitigating the unauthenticated access, encrypting sensitive environment variables at rest and in transit could reduce the impact of information disclosure. However, this project stores variables in memory, so encryption at rest is not applicable in the current design. HTTPS should be used to encrypt data in transit.
- Preconditions:
    - The `httpenv` service must be deployed and running.
    - The attacker must be able to reach the `httpenv` service over the network. This could be if the service is exposed to the public internet or if the attacker has access to the network where the service is running (e.g., an internal network).
    - Environment variables must have been added to the service using the `/v1/add/<name>/<value>` endpoint prior to the attacker attempting to retrieve them.
- Source Code Analysis:
    - The vulnerability is located in the `httpenv.py` file, specifically within the definition of the `/v1/<name>` route:
      ```python
      @route('/v1/<name>')
      def v1(name):
          return envs.get(name, '')
      ```
      - `bottle.route('/v1/<name>')`: This decorator from the `bottle` framework registers the `v1` function to handle GET requests to paths matching `/v1/<name>`. The `<name>` part in the path becomes an argument to the `v1` function.
      - `def v1(name):`: This defines the function `v1` which takes `name` as an argument, extracted from the URL path.
      - `return envs.get(name, '')`: This line retrieves the value associated with the key `name` from the `envs` dictionary. `envs` is a global dictionary defined and initialized when the script starts: `envs = {}`. The `get(name, '')` method of the dictionary attempts to retrieve the value for the given `name`. If the `name` is not found as a key in the `envs` dictionary, it returns an empty string `''` as a default value.
      - **Vulnerability**: There are no authentication or authorization checks performed within the `v1` function or before it. Any request to `/v1/<name>` will directly access the `envs` dictionary and return the corresponding value (or an empty string if the variable is not set). This means anyone who can send HTTP requests to the service can retrieve any environment variable stored in it, simply by knowing or guessing the variable name.
    - The `/v1/add/<name>/<value>` endpoint, defined as:
      ```python
      @route('/v1/add/<name>/<value>')
      def v1_add(name, value):
          envs[name] = value
      ```
      - allows anyone to add or modify environment variables in the in-memory registry, further emphasizing the lack of access control throughout the application.

- Security Test Case:
    1. Deploy the `httpenv` service using Docker or directly running `httpenv.py`. Ensure the service is accessible on a specific address (e.g., `http://localhost:8080` or a public IP address).
    2. Add a sensitive environment variable. For example, using `curl`:
       ```bash
       curl "http://<service_address>/v1/add/TEST_SECRET/my_secret_value"
       ```
       Replace `<service_address>` with the actual address of the deployed service (e.g., `localhost:8080`).
    3. As an attacker, attempt to retrieve the value of the `TEST_SECRET` variable by sending a GET request to the `/v1/<name>` endpoint:
       ```bash
       curl "http://<service_address>/v1/TEST_SECRET"
       ```
       Replace `<service_address>` with the actual address of the deployed service.
    4. Observe the response. The response body should contain the value `my_secret_value`, which was set in step 2. This demonstrates that an attacker can successfully retrieve the sensitive environment variable `TEST_SECRET` without any authentication, confirming the Unauthenticated Information Disclosure vulnerability.
    5. To further test, try to retrieve a non-existent variable:
       ```bash
       curl "http://<service_address>/v1/NON_EXISTENT_VARIABLE"
       ```
       The response should be an empty string, as per the code's behavior (`envs.get(name, '')`), but importantly, there is still no authentication involved, and if a variable *does* exist, its value is disclosed.
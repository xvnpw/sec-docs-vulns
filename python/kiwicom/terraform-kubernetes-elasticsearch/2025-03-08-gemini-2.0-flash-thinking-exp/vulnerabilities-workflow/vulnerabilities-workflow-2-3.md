### Vulnerability List

* Vulnerability Name: Unauthenticated Elasticsearch Access
* Description:
    1. The Elasticsearch module is deployed on Kubernetes using default configurations.
    2. By default, the Elasticsearch Helm chart does not enable authentication (like Basic Authentication or API keys).
    3. The default service type is `ClusterIP`, which exposes the Elasticsearch service within the Kubernetes cluster.
    4. If the Kubernetes cluster's network policies or external access configurations (like LoadBalancer, NodePort, or Ingress misconfiguration) allow external access to the ClusterIP service, or if an attacker gains access to the Kubernetes cluster network, the Elasticsearch service becomes accessible without any authentication.
    5. An attacker can then interact with the Elasticsearch API, access sensitive data, modify or delete data, or even take control of the Elasticsearch cluster.
* Impact:
    * **Unauthorized Data Access:** Attackers can read, modify, or delete any data stored in the Elasticsearch cluster. This can lead to конфиденциальность breaches and data loss.
    * **Data Manipulation:** Attackers can modify existing data, inject malicious data, or corrupt the data integrity, leading to искажение of information and potential system malfunctions if applications rely on this data.
    * **Cluster Takeover:** In severe cases, attackers might gain administrative privileges within Elasticsearch (if security misconfigurations are present beyond just missing authentication), potentially leading to complete cluster takeover and denial of service for legitimate users.
* Vulnerability Rank: Critical
* Currently Implemented Mitigations:
    * None by default.
    * The module provides configuration options to enable security features, such as:
        * `security example`: Demonstrates how to enable node-to-node security and HTTPS using certificates and passwords.
        * `esConfig`: Allows users to provide custom `elasticsearch.yml` configuration to enable security features like X-Pack security (now part of the Elastic Basic license).
        * `keystore`: Allows managing sensitive settings like passwords securely.
        * `protocol: https`:  Allows switching to HTTPS for communication.
* Missing Mitigations:
    * **Enable Basic Authentication by default:** The default configuration should include at least basic authentication enabled to prevent unauthorized access.
    * **Enforce HTTPS by default:**  The default protocol should be HTTPS to encrypt communication between clients and the Elasticsearch cluster.
    * **Security Hardening Guide:** Provide clear documentation and guidance on how to properly secure the Elasticsearch cluster deployed with this module, including enabling authentication, authorization, and network security policies.
* Preconditions:
    1. An Elasticsearch cluster is deployed using this Terraform module with default configurations (without explicitly enabling security features).
    2. The Kubernetes service exposing Elasticsearch is accessible from outside the Kubernetes cluster's secure network, either due to network configuration, misconfiguration, or attacker gaining access to the internal network.
* Source Code Analysis:
    1. **File: /code/chart/values.yaml**:
        ```yaml
        esConfig: {}
        protocol: http
        ```
        * The `esConfig` is empty by default. This means that no security settings are automatically applied to the `elasticsearch.yml` configuration file, which is the primary way to configure Elasticsearch security features.
        * The `protocol` is set to `http` by default, meaning that communication with Elasticsearch will be over unencrypted HTTP unless explicitly changed.

    2. **File: /code/chart/templates/statefulset.yaml**:
        ```yaml
        containers:
        - name: "{{ template "elasticsearch.name" . }}"
          # ...
          readinessProbe:
            exec:
              command:
                - sh
                - -c
                - |
                  #!/usr/bin/env bash -e
                  # ...
                  http () {
                    local path="${1}"
                    local args="${2}"
                    set -- -XGET -s
                    if [ "$args" != "" ]; then
                      set -- "$@" $args
                    fi
                    if [ -n "${ELASTIC_USERNAME}" ] && [ -n "${ELASTIC_PASSWORD}" ]; then
                      set -- "$@" -u "${ELASTIC_USERNAME}:${ELASTIC_PASSWORD}"
                    fi
                    curl --output /dev/null -k "$@" "{{ .Values.protocol }}://127.0.0.1:{{ .Values.httpPort }}${path}"
                  }
                  # ...
        ```
        * The `readinessProbe` in the `statefulset.yaml` template uses `curl` to check the health of Elasticsearch.
        * Critically, the `if [ -n "${ELASTIC_USERNAME}" ] && [ -n "${ELASTIC_PASSWORD}" ]; then set -- "$@" -u "${ELASTIC_USERNAME}:${ELASTIC_PASSWORD}" ; fi` block shows that authentication is only added to the `curl` command if `ELASTIC_USERNAME` and `ELASTIC_PASSWORD` environment variables are set.
        * In the default `values.yaml`, these environment variables are not set, and therefore, the readiness probe (and by extension, the default Elasticsearch deployment) does not use authentication.

    **Visualization:**

    ```
    values.yaml (default):
    +------------------+     templates/statefulset.yaml:
    | esConfig: {}     | --> +---------------------------------------+
    | protocol: http   |     | containers:                           |
    +------------------+     | - readinessProbe:                     |
                               |     exec:                              |
                               |       command:                         |
                               |         - curl "{{ .Values.protocol }}://..." |
                               |         # No authentication by default |
                               +---------------------------------------+
    ```

* Security Test Case:
    1. **Prerequisites:**
        * Deploy the Elasticsearch module using the default configuration. For example, using the `default` example provided in the `chart/examples/default` directory.
        * Ensure `kubectl` is configured to interact with your Kubernetes cluster.
        * Port-forward the Elasticsearch master service to your local machine to simulate external access. For example: `kubectl port-forward service/elasticsearch-master 9200:9200 -n default` (assuming default namespace and service name).

    2. **Steps:**
        * Open a web browser or use `curl` command to access the Elasticsearch endpoint exposed via port forwarding: `http://localhost:9200`.
        * Try to access cluster health information without providing any credentials: `curl http://localhost:9200/_cluster/health?pretty`.
        * Attempt to create an index without authentication: `curl -XPUT 'http://localhost:9200/test_index?pretty' -H 'Content-Type: application/json' -d'{"settings": {"number_of_shards": 1, "number_of_replicas": 0}}'`.
        * Try to insert a document into the newly created index: `curl -XPOST 'http://localhost:9200/test_index/_doc?pretty' -H 'Content-Type: application/json' -d'{"field1": "test data"}'`.
        * Attempt to retrieve the document: `curl 'http://localhost:9200/test_index/_search?pretty' -H 'Content-Type: application/json' -d'{"query": {"match_all": {}}}'`.

    3. **Expected Results:**
        * Step 2: The `curl http://localhost:9200/_cluster/health?pretty` command should return the Elasticsearch cluster health information in JSON format, indicating successful unauthenticated access.
        * Step 3: The `curl -XPUT ...` command should successfully create the `test_index` without requiring authentication.
        * Step 4: The `curl -XPOST ...` command should successfully insert the document into `test_index` without authentication.
        * Step 5: The `curl 'http://localhost:9200/test_index/_search?pretty' ...` command should return the inserted document, confirming unauthenticated data access.

    4. **Conclusion:**
        * If all expected results are observed, it confirms that the Elasticsearch cluster deployed with default configurations is vulnerable to unauthenticated access, allowing external attackers to read, write, and manipulate data without any authorization.
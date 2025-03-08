- Vulnerability Name: Insecure Elasticsearch Endpoint Exposure due to Default Service Type
  - Description: By default, the Elasticsearch service is configured with `service.type: ClusterIP`. While `ClusterIP` itself is not exposed to the public internet, users might inadvertently or intentionally change this to `LoadBalancer` or `NodePort` in the `values.yaml` configuration to access Elasticsearch from outside the Kubernetes cluster. If this change is made without implementing any authentication or network restrictions, the Elasticsearch endpoint will be exposed to the public internet without protection. This allows any attacker with internet access to directly interact with the Elasticsearch cluster.
  - Impact: Unauthorized access to the Elasticsearch cluster, potentially leading to a full data breach, data manipulation, or denial of service by malicious actors. Sensitive data stored in Elasticsearch could be exposed, modified, or deleted.
  - Vulnerability Rank: High
  - Currently Implemented Mitigations:
    - The default `service.type` is `ClusterIP`, which is only accessible within the Kubernetes cluster, offering some level of network isolation by default.
    - The documentation in `/code/chart/README.md` provides information on configuration options, including security related parameters, but it doesn't explicitly warn against exposing the service publicly without authentication.
  - Missing Mitigations:
    - **Security Warning in README and values.yaml:** Add a prominent security warning in the README and `values.yaml` files, specifically when discussing `service.type`, highlighting the risks of setting it to `LoadBalancer` or `NodePort` without proper security measures.
    - **Guidance on Secure Service Exposure:** Provide clear guidance and examples on how to securely expose the Elasticsearch service if needed, including enabling authentication, network policies, and ingress configurations with authentication.
  - Preconditions:
    - The user modifies the `values.yaml` to set `service.type` to `LoadBalancer` or `NodePort`.
    - No additional security measures like Elasticsearch security features (e.g., X-Pack Security) or network restrictions are configured.
  - Source Code Analysis:
    - File: `/code/chart/values.yaml`
      ```yaml
      service:
        type: ClusterIP
      ```
      This section in `values.yaml` defines the default service type as `ClusterIP`.
    - File: `/code/chart/templates/service.yaml`
      ```yaml
      spec:
        type: {{ .Values.service.type }}
      ```
      This template uses the value from `values.yaml` to set the `type` of the Kubernetes Service resource. If a user alters `values.yaml` to `LoadBalancer` or `NodePort`, the deployed service will reflect this change, potentially making Elasticsearch publicly accessible.
  - Security Test Case:
    1. Deploy the Elasticsearch module using Helm with the following configuration in `values.yaml`:
       ```yaml
       service:
         type: LoadBalancer
       ```
       Leave all other security settings at their defaults.
    2. After deployment, retrieve the external IP address assigned to the LoadBalancer service by Kubernetes (e.g., using `kubectl get service <elasticsearch-service-name>`).
    3. From an external network (outside the Kubernetes cluster), use `curl` or a web browser to access the Elasticsearch cluster health endpoint on port 9200 using the external IP address: `curl <EXTERNAL_IP>:9200/_cluster/health`.
    4. Observe if the cluster health information is returned without requiring any authentication. If the health status is accessible without credentials, the vulnerability is confirmed.

- Vulnerability Name: Insecure Elasticsearch Endpoint due to Missing Default Authentication
  - Description: The Elasticsearch Helm chart deploys an Elasticsearch cluster without enabling authentication by default. This means that after deploying the cluster using the default configurations, the Elasticsearch HTTP endpoint is completely open and accessible to anyone who can reach it on the network. An attacker exploiting this vulnerability can perform any Elasticsearch operation, including reading, modifying, and deleting indices and data, without providing any credentials.
  - Impact: Critical data breach and data integrity risk. Unauthorized users can gain full administrative access to the Elasticsearch cluster and all its data. This can lead to severe consequences, including data theft, ransomware attacks, and complete system compromise.
  - Vulnerability Rank: Critical
  - Currently Implemented Mitigations:
    - None. The chart does not enforce or enable any authentication mechanism by default.
    - The chart provides configuration options to enable security features like X-Pack Security through `esConfig` and `secretMounts`, as demonstrated in the `examples/security` directory, but these are opt-in and not enabled by default.
  - Missing Mitigations:
    - **Enable Basic Authentication by Default (Recommended):** The most effective mitigation would be to enable basic authentication by default. This could be achieved by setting up a default username and password and enabling Elasticsearch security features in the default `esConfig`.
    - **Prompt for Authentication Configuration:** If default authentication is not desired, the chart could prompt the user to configure authentication during the deployment process, forcing them to make an explicit security decision.
    - **Strong Security Warning and Guidance:** Include a very strong and prominent security warning in the README and `values.yaml` emphasizing the critical importance of enabling authentication and the severe risks of running Elasticsearch in production without it. Provide step-by-step instructions and examples on how to enable authentication using X-Pack Security or other methods.
  - Preconditions:
    - Default deployment of the Elasticsearch module using Helm without any modifications to security settings in `values.yaml`.
    - The Elasticsearch service is network accessible to the attacker. This could be due to `service.type` being set to `LoadBalancer` or `NodePort`, or due to network configuration allowing access to `ClusterIP` from the attacker's location.
  - Source Code Analysis:
    - File: `/code/chart/values.yaml`
      ```yaml
      esConfig: {}
      ```
      The default `esConfig` is empty, indicating that no Elasticsearch configuration, including security settings, is applied by default. This results in Elasticsearch starting without authentication enabled.
    - File: `/code/chart/examples/security/security.yml`
      ```yaml
      esConfig:
        elasticsearch.yml: |
          xpack.security.enabled: true
      ```
      This example configuration demonstrates how to enable X-Pack Security by modifying `esConfig`, proving that security features are available but not default.
  - Security Test Case:
    1. Deploy the Elasticsearch module using Helm with the default `values.yaml` file, ensuring no security configurations are explicitly set.
    2. After deployment, obtain the endpoint to access the Elasticsearch service (e.g., ClusterIP service name, NodePort, or LoadBalancer IP, depending on your setup).
    3. Using `curl` or a web browser, attempt to access the Elasticsearch cluster health endpoint without providing any username or password: `curl <ELASTICSEARCH_ENDPOINT>:9200/_cluster/health`.
    4. If the cluster health information is successfully retrieved (typically a JSON response starting with `{"cluster_name" : ...}`), it confirms that the Elasticsearch endpoint is accessible without authentication, and the vulnerability is present.
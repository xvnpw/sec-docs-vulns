- Vulnerability Name: Elasticsearch cluster exposed without authentication
- Description: The Elasticsearch Helm chart, when deployed with default configurations, does not enforce authentication. This means that if the Kubernetes service exposing Elasticsearch is publicly accessible (e.g., Service type LoadBalancer without restricted `loadBalancerSourceRanges`), anyone can access the Elasticsearch cluster without providing any credentials. An attacker can then read, modify, or delete data, and potentially gain complete control over the Elasticsearch cluster and the data it holds.
- Impact: High
- Vulnerability Rank: Critical
- Currently Implemented Mitigations:
    - The documentation in `chart/README.md` and examples like `chart/examples/security/security.yml` guide users on how to enable security features like authentication and SSL/TLS.
    - The `security.yml` example demonstrates how to enable `xpack.security.enabled: true` and configure authentication using secrets for username and password.
- Missing Mitigations:
    - The default `values.yaml` should enable basic authentication by default.
    - The module should provide a more prominent warning in the README about the security implications of deploying Elasticsearch without authentication when exposed publicly.
    - Implement network policies to restrict access to the Elasticsearch service within the Kubernetes cluster by default.
- Preconditions:
    - The Elasticsearch service is exposed publicly, for example using `service.type: LoadBalancer` without restricting access using `service.loadBalancerSourceRanges` or other network security measures outside of the module's scope.
    - Default `values.yaml` configurations are used, where security features like authentication are not enabled.
- Source Code Analysis:
    - File: `/code/chart/values.yaml`
        ```yaml
        service:
          type: ClusterIP # Default service type is ClusterIP
        ```
        By default, the service type is `ClusterIP`, which is only accessible within the Kubernetes cluster. However, users can easily change this to `LoadBalancer` in `values.yaml` or via Helm CLI arguments.
        ```yaml
        esConfig: {}
        ```
        The default `esConfig` is empty, meaning that security features like `xpack.security.enabled: true` are not enabled by default.
    - File: `/code/chart/examples/security/security.yml`
        ```yaml
        esConfig:
          elasticsearch.yml: |
            xpack.security.enabled: true
            ...
        extraEnvs:
          - name: ELASTIC_PASSWORD
            valueFrom:
              secretKeyRef:
                name: elastic-credentials
                key: password
          - name: ELASTIC_USERNAME
            valueFrom:
              secretKeyRef:
                name: elastic-credentials
                key: username
        ```
        This example shows how to configure security, but it's not the default. The security configurations are explicitly set in the `esConfig` and credentials are provided via secrets, which are good security practices, but not enforced by default.
    - File: `/code/chart/templates/service.yaml`
        ```yaml
        spec:
          type: {{ .Values.service.type }}
          ports:
          - name: {{ .Values.service.httpPortName | default "http" }}
            protocol: TCP
            port: {{ .Values.httpPort }}
        ```
        This template uses the `service.type` value directly, allowing users to choose `LoadBalancer` without any default security restrictions enforced by the chart itself.
- Security Test Case:
    1. Deploy the Elasticsearch cluster using the default `values.yaml` and set `service.type: LoadBalancer`.
        ```bash
        helm install elasticsearch ./code/chart --set service.type=LoadBalancer
        ```
    2. Obtain the external IP of the LoadBalancer service.
        ```bash
        kubectl get service elasticsearch-master -o jsonpath='{.status.loadBalancer.ingress[0].ip}'
        ```
        Let's say the external IP is `EXTERNAL_IP`.
    3. Attempt to access the Elasticsearch cluster health endpoint without any authentication from outside the Kubernetes cluster, for example using `curl` from your local machine or a publicly accessible server.
        ```bash
        curl http://EXTERNAL_IP:9200/_cluster/health?pretty
        ```
    4. If the Elasticsearch cluster is vulnerable, the command will return the cluster health information without prompting for credentials, indicating unauthorized access. An attacker can then perform further actions like reading indices, modifying data, or shutting down the cluster.
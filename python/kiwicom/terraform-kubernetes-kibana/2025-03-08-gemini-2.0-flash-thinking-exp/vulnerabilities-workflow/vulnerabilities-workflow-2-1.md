### Vulnerability List

- Vulnerability Name: Kibana instance exposed without authentication
- Description:
    1. The Helm chart for Kibana deploys a Kibana instance on Kubernetes. By default, Kibana might not enforce user authentication, depending on its configuration and version.
    2. The Helm chart's default `service.type` is `ClusterIP`, which makes Kibana accessible only within the Kubernetes cluster. However, the chart allows users to easily expose Kibana publicly by setting `ingress.enabled: true` or changing `service.type` to `LoadBalancer` or `NodePort`.
    3. If a user exposes Kibana publicly using these options without configuring additional authentication mechanisms, the Kibana instance will be accessible over the internet without any login requirements.
    4. An external attacker can access the publicly exposed Kibana endpoint without providing any credentials.
    5. Once accessed, the attacker can view Kibana dashboards, visualizations, and potentially gain insights into the data indexed in the connected Elasticsearch cluster. Depending on the Kibana and Elasticsearch configurations and any existing Elasticsearch security measures, the attacker might be able to perform further actions like modifying dashboards, creating new visualizations to extract sensitive data, or even potentially interacting with the underlying Elasticsearch data if Kibana has sufficient permissions.
- Impact:
    - Unauthorized access to Kibana dashboards and visualizations.
    - Potential information disclosure through access to dashboards that visualize sensitive data from Elasticsearch.
    - Risk of unauthorized modification or deletion of Kibana dashboards, leading to disruption of monitoring and analysis capabilities.
    - In a worst-case scenario, depending on Kibana's configured permissions and Elasticsearch security settings, the attacker could potentially gain broader access to the Elasticsearch cluster and the data it contains.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - Default `service.type` is `ClusterIP`, which restricts external access to Kibana by default, requiring explicit configuration to expose it publicly.
    - The Helm chart sets security context for the Kibana pod, dropping capabilities and running as non-root user, which improves the container's security posture but does not directly address authentication for Kibana itself.
- Missing Mitigations:
    - The Helm chart does not provide a built-in option or configuration parameter to enforce authentication for Kibana. Users need to manually configure authentication within the `kibanaConfig` section or implement external authentication proxies if required.
    - The documentation (`README.md` files) does not explicitly warn users about the security implications of exposing Kibana without authentication when using `ingress` or changing the `service.type`. It lacks clear guidance on how to secure Kibana access when it is exposed publicly.
- Preconditions:
    - The user must explicitly configure the Helm chart to expose Kibana publicly, either by setting `ingress.enabled: true` or changing `service.type` to `LoadBalancer` or `NodePort`.
    - The user must not have configured any authentication mechanism for Kibana, either through `kibanaConfig` (e.g., using X-Pack security if available in their Kibana version) or by using an external authentication proxy in front of Kibana.
    - The underlying Elasticsearch cluster may or may not have its own security enabled. Even with Elasticsearch security, if Kibana is not secured, attackers might still be able to leverage Kibana's access to Elasticsearch for unauthorized data access or manipulation, depending on the specific Elasticsearch security policies and Kibana's roles.
- Source Code Analysis:
    - **`/code/chart/values.yaml`**: The default values for `ingress.enabled` is `false` and `service.type` is `ClusterIP`. These defaults are secure as they do not expose Kibana publicly without explicit user configuration.
    - **`/code/chart/templates/ingress.yaml`**: This template creates an Ingress resource if `.Values.ingress.enabled` is `true`. It exposes Kibana based on the configured hosts and paths. There is no built-in authentication mechanism configured in this template.
    ```yaml
    {{- if .Values.ingress.enabled -}}
    {{- $fullName := include "kibana.fullname" . -}}
    apiVersion: {{ template "kibana.ingress.apiVersion" . }}
    kind: Ingress
    metadata:
      name: {{ $fullName }}
      ...
    spec:
    {{- if .Values.ingress.tls }}
      tls:
    {{ toYaml .Values.ingress.tls | indent 4 }}
    {{- end }}
      rules:
      {{- range .Values.ingress.hosts }}
        - host: {{ .host }}
          http:
            paths:
              - path: {{ .path }}
                backend:
                  serviceName: {{ $fullName }}
                  servicePort: {{ .port }}
      {{- end }}
    {{- end }}
    ```
    - **`/code/chart/templates/service.yaml`**: This template creates a Service resource of the type specified by `.Values.service.type`. If the type is set to `LoadBalancer` or `NodePort`, it can expose Kibana publicly.  Again, no authentication is configured here.
    ```yaml
    apiVersion: v1
    kind: Service
    metadata:
      name: {{ template "kibana.fullname" . }}
      ...
    spec:
      type: {{ .Values.service.type }}
      ...
      ports:
        {{- range .Values.service.ports }}
        - port: {{ .port }}
        ...
          targetPort: {{ .targetPort }}
        {{- end }}
      selector:
        app: {{ .Chart.Name }}
        release: {{ .Release.Name | quote }}
    ```
    - **`/code/chart/README.md` and `/code/README.md`**:  The documentation does not sufficiently emphasize the importance of securing Kibana when exposing it publicly. While the "Security" example in `chart/examples/security/` shows how to connect to a secured Elasticsearch, it doesn't demonstrate or mandate securing Kibana itself with authentication when exposed.

- Security Test Case:
    1. Deploy Kibana using the Helm chart with the following configuration in `values.yaml`:
    ```yaml
    ingress:
      enabled: true
      hosts:
        - host: kibana.example.com # Replace with your desired hostname
          path: /
          port: 5601
    ```
    2. Install the Helm chart using `helm install --name test-kibana ./chart -f values.yaml`.
    3. After deployment, obtain the external IP or hostname for the Ingress resource. This depends on your Kubernetes environment and Ingress controller setup. For example, if using Minikube: `minikube tunnel` and then get the ingress URL using `kubectl get ingress test-kibana-kibana -o jsonpath='{.status.loadBalancer.ingress[0].hostname}'` or similar depending on your setup. In a cloud environment, it might be an external IP address assigned to a LoadBalancer.
    4. Access the Kibana URL (e.g., `http://kibana.example.com` or the IP obtained in the previous step) in a web browser or using `curl`.
    5. Observe that the Kibana interface loads without prompting for any username or password.
    6. Navigate through Kibana, explore dashboards, and attempt to perform actions such as creating a new dashboard or visualization.
    7. Verify that you can access and interact with Kibana without any authentication, confirming the vulnerability.
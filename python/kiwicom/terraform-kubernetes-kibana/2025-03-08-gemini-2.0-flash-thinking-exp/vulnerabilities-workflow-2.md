## Combined Vulnerability List

### Kibana instance exposed without authentication

* Description:
    1. The Helm chart for Kibana deploys a Kibana instance on Kubernetes. By default, Kibana might not enforce user authentication, depending on its configuration and version.
    2. The Helm chart's default `service.type` is `ClusterIP`, which makes Kibana accessible only within the Kubernetes cluster. However, the chart allows users to easily expose Kibana publicly by setting `ingress.enabled: true` or changing `service.type` to `LoadBalancer` or `NodePort`.
    3. If a user exposes Kibana publicly using these options without configuring additional authentication mechanisms, the Kibana instance will be accessible over the internet without any login requirements.
    4. An external attacker can access the publicly exposed Kibana endpoint without providing any credentials.
    5. Once accessed, the attacker can view Kibana dashboards, visualizations, and potentially gain insights into the data indexed in the connected Elasticsearch cluster. Depending on the Kibana and Elasticsearch configurations and any existing Elasticsearch security measures, the attacker might be able to perform further actions like modifying dashboards, creating new visualizations to extract sensitive data, or even potentially interacting with the underlying Elasticsearch data if Kibana has sufficient permissions.

* Impact:
    - Unauthorized access to Kibana dashboards and visualizations.
    - Potential information disclosure through access to dashboards that visualize sensitive data from Elasticsearch.
    - Risk of unauthorized modification or deletion of Kibana dashboards, leading to disruption of monitoring and analysis capabilities.
    - In a worst-case scenario, depending on Kibana's configured permissions and Elasticsearch security settings, the attacker could potentially gain broader access to the Elasticsearch cluster and the data it contains.

* Vulnerability Rank: High

* Currently Implemented Mitigations:
    - Default `service.type` is `ClusterIP`, which restricts external access to Kibana by default, requiring explicit configuration to expose it publicly.
    - The Helm chart sets security context for the Kibana pod, dropping capabilities and running as non-root user, which improves the container's security posture but does not directly address authentication for Kibana itself.

* Missing Mitigations:
    - The Helm chart does not provide a built-in option or configuration parameter to enforce authentication for Kibana. Users need to manually configure authentication within the `kibanaConfig` section or implement external authentication proxies if required.
    - The documentation (`README.md` files) does not explicitly warn users about the security implications of exposing Kibana without authentication when using `ingress` or changing the `service.type`. It lacks clear guidance on how to secure Kibana access when it is exposed publicly.

* Preconditions:
    - The user must explicitly configure the Helm chart to expose Kibana publicly, either by setting `ingress.enabled: true` or changing `service.type` to `LoadBalancer` or `NodePort`.
    - The user must not have configured any authentication mechanism for Kibana, either through `kibanaConfig` (e.g., using X-Pack security if available in their Kibana version) or by using an external authentication proxy in front of Kibana.
    - The underlying Elasticsearch cluster may or may not have its own security enabled. Even with Elasticsearch security, if Kibana is not secured, attackers might still be able to leverage Kibana's access to Elasticsearch for unauthorized data access or manipulation, depending on the specific Elasticsearch security policies and Kibana's roles.

* Source Code Analysis:
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

* Security Test Case:
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

### Insecure Ingress Configuration - HTTP traffic exposed when TLS is not configured

* Description:
    1. The Kibana Helm chart allows users to expose Kibana through an Ingress resource by setting `ingress.enabled: true`.
    2. If the `ingress.tls` section in `values.yaml` is not configured, the Ingress resource will be created without TLS termination.
    3. This results in Kibana being exposed over HTTP, even if Kibana itself is configured for HTTPS internally or is intended to handle sensitive data.
    4. An attacker could intercept network traffic to the Kibana instance and potentially gain access to sensitive data transmitted over HTTP.

* Impact: Exposure of sensitive data transmitted to and from Kibana over unencrypted HTTP. This could include user credentials, search queries, visualized data, and other sensitive information handled by Kibana.

* Vulnerability Rank: High

* Currently Implemented Mitigations:
    - None. The chart does not enforce TLS configuration for Ingress.

* Missing Mitigations:
    - The chart should provide guidance or enforce TLS configuration when Ingress is enabled.
    - Ideally, the chart should have a default configuration that encourages secure communication, such as enabling TLS by default for Ingress or at least warning users about the risks of exposing Kibana over HTTP via Ingress.

* Preconditions:
    - `ingress.enabled` is set to `true` in `values.yaml`.
    - `ingress.tls` is not configured or is empty in `values.yaml`.
    - Kibana is deployed and accessible through the created Ingress resource.

* Source Code Analysis:
    - File: `/code/chart/templates/ingress.yaml`
    ```yaml
    {{- if .Values.ingress.enabled -}}
    {{- $fullName := include "kibana.fullname" . -}}
    apiVersion: {{ template "kibana.ingress.apiVersion" . }}
    kind: Ingress
    metadata:
      name: {{ $fullName }}
      labels:
        app: {{ .Chart.Name }}
        release: {{ .Release.Name }}
        heritage: {{ .Release.Service }}
      annotations:
        {{- range $key, $value := .Values.ingress.annotations }}
        {{ $key }}: {{ $value | quote }}
        {{- end }}
        {{- range $key, $value := .Values.commonAnnotations }}
        {{ $key }}: {{ $value | quote }}
        {{- end }}
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
    - The `{{- if .Values.ingress.tls }}` block in `ingress.yaml` template is conditional. If `.Values.ingress.tls` is not defined in `values.yaml` or is empty, this block is skipped.
    - Consequently, the Ingress resource will be created without TLS configuration in the `spec`.
    - The `rules` section always creates `http` rules, regardless of TLS configuration.
    - This means if `ingress.enabled` is true and `ingress.tls` is missing, the service will be exposed over HTTP.

* Security Test Case:
    1. Deploy Kibana using the Helm chart with the following `values.yaml` configuration:
    ```yaml
    ingress:
      enabled: true
      hosts:
        - host: kibana.example.com
          path: /
          port: 5601
    ```
    2. After deployment, access Kibana using `http://kibana.example.com`.
    3. Observe that Kibana is accessible over HTTP, indicated by the browser address bar showing `http://` and the page loading correctly.
    4. Use a network interception tool (like Wireshark or tcpdump) to capture traffic between your browser and the Kibana server when accessing `http://kibana.example.com`.
    5. Analyze the captured traffic and confirm that the communication is happening over unencrypted HTTP, and sensitive data (if any is transmitted during interaction with Kibana) is visible in plain text.
    6. This demonstrates that Kibana is exposed over HTTP when Ingress is enabled without TLS configuration.

### Insecure Defaults Leading to Public Exposure and Potential Exploitation

* Description:
    1. The Terraform module deploys Kibana on Kubernetes using a Helm chart.
    2. By default, the module does not enforce or guide users towards enabling crucial security features in Kibana, such as HTTPS for the Kibana web interface and authentication.
    3. If users deploy Kibana using the default configurations and expose it publicly without further hardening, the Kibana instance will be vulnerable to various attacks due to the lack of basic security measures. This includes potential unauthorized access and data breaches.
    4. For example, without HTTPS, communication is unencrypted, and without authentication, anyone can access Kibana. These insecure defaults increase the attack surface and potential impact of other vulnerabilities, such as XSS vulnerabilities within Kibana itself, as there are no basic security layers in place.

* Impact:
    - High. Deployment with insecure defaults leads to a publicly exposed Kibana instance vulnerable to unauthorized access and data interception.
    - Lack of HTTPS exposes sensitive data transmitted between users and Kibana.
    - Missing authentication allows any attacker to access Kibana dashboards and potentially the underlying Elasticsearch data, depending on Kibana and Elasticsearch configurations.
    - Increased risk of exploitation of other vulnerabilities, such as XSS, due to the absence of foundational security measures like HTTPS and authentication.

* Vulnerability Rank: High

* Currently Implemented Mitigations:
    - None in the Terraform module itself. The module allows users to configure `kibanaConfig` in `values.yaml` to enable security features in Kibana, but there are no default security configurations enabled, and no explicit guidance within the module to enforce or encourage secure configurations.

* Missing Mitigations:
    - The module should provide secure defaults or strongly encourage users to configure security settings.
    - This could include:
        - Providing default configurations that enable HTTPS for Kibana. This might involve options for users to easily provide TLS certificates or guidance on generating them.
        - Adding documentation and examples, directly within the module's README or comments in `values.yaml`, on how to enable authentication and authorization in Kibana using `kibanaConfig`.
        - Consider providing a "security-focused" deployment profile or example in the `examples/` directory that demonstrates a hardened Kibana deployment with HTTPS and authentication enabled.
        - Adding input variables to directly control critical security settings like enabling HTTPS and authentication, making them more visible and easier to configure.

* Preconditions:
    - Kibana is deployed using this Terraform module.
    - Kibana is exposed publicly, typically through an Ingress or LoadBalancer, making it accessible from the internet or untrusted networks.
    - Users rely on default configurations provided by the module and do not explicitly enable HTTPS and authentication for Kibana through `kibanaConfig` or other means.

* Source Code Analysis:
    - File: `/code/chart/values.yaml`
        ```yaml
        elasticsearchURL: "" # "http://elasticsearch-master:9200"
        elasticsearchHosts: "http://elasticsearch-master:9200"
        ```
        - The default protocol for `elasticsearchHosts` is `http`, which is insecure. While this relates to Elasticsearch communication, it highlights a general lack of secure defaults.
        - There are no default configurations within `values.yaml` that directly enable or suggest enabling HTTPS for Kibana itself (`server.ssl.enabled`) or authentication (`xpack.security.enabled`).
    - File: `/code/chart/templates/deployment.yaml`
        ```yaml
        containers:
        - name: kibana
          image: "{{ .Values.image }}:{{ .Values.imageTag }}"
          imagePullPolicy: "{{ .Values.imagePullPolicy }}"
          env:
          {{- $major_version := int (index (.Values.imageTag | splitList ".") 0) -}}
          {{- $minor_version := int (index (.Values.imageTag | splitList ".") 1) -}}
          {{- if (and (le $major_version 6) (le $minor_version 5)) -}}
            {{- if .Values.elasticsearchURL }}
            - name: ELASTICSEARCH_URL
              value: "{{ .Values.elasticsearchURL }}"
            {{- end }}
          {{- else }}
            {{- if .Values.elasticsearchHosts }}
            - name: ELASTICSEARCH_HOSTS
              value: "{{ .Values.elasticsearchHosts }}"
            {{- end }}
          {{- end }}
            - name: SERVER_HOST
              value: "{{ .Values.serverHost }}"
        ```
        - The deployment template sets up the Kibana container based on provided values but does not inject any configurations that enforce HTTPS or authentication by default. It relies entirely on the user to provide these configurations through `kibanaConfig` or other means.

* Security Test Case:
    1. **Prerequisites:** Deploy Elasticsearch using a separate module or manually. Ensure Kubernetes cluster is running and `kubectl` is configured to access it. Install Terraform and Helm.
    2. **Deployment:**
        ```terraform
        terraform {
          required_providers {
            kubernetes = {
              source  = "hashicorp/kubernetes"
            }
            helm = {
              source  = "hashicorp/helm"
              version = "~> 2.0"
            }
          }
        }

        provider "kubernetes" {
          # Configure your Kubernetes provider here, e.g., using kubeconfig
        }

        provider "helm" {
          kubernetes {
            host                   = provider.kubernetes.host
            cluster_ca_certificate = provider.kubernetes.cluster_ca_certificate
            token                  = provider.kubernetes.token
          }
        }

        module "kibana" {
          source = "./code" # Assuming the module code is in the 'code' directory

          elasticsearch_hosts = ["http://<elasticsearch-service-ip>:9200"] # Replace with your Elasticsearch service IP
          namespace           = "kibana-test"
        }
        ```
        - Create a `main.tf` file with the above content, replacing `<elasticsearch-service-ip>` with the actual IP or hostname of your Elasticsearch service.
        - Initialize Terraform: `terraform init`
        - Apply Terraform configuration: `terraform apply -auto-approve`
        - This will deploy Kibana in the `kibana-test` namespace with default settings.
    3. **Expose Kibana (if not already using Ingress or LoadBalancer, for testing purposes use port-forward):**
        ```bash
        kubectl port-forward service/release-name-kibana 5601:5601 -n kibana-test &
        ```
        - Access Kibana in your browser at `http://localhost:5601`.
    4. **Verify lack of HTTPS and Authentication**:
        - Observe that Kibana is accessible via `http://` and there is no login prompt.
        - Access Kibana and confirm you can browse dashboards and visualizations without any authentication.
    5. **Clean Up:**
        ```bash
        terraform destroy -auto-approve
        ```
        ```bash
        helm uninstall release-name -n kibana-test # if helm was used directly
        ```

This test case demonstrates the insecure defaults by showing the lack of HTTPS and Authentication in a default deployment, highlighting the vulnerability of insecure defaults and missing hardening guidance.
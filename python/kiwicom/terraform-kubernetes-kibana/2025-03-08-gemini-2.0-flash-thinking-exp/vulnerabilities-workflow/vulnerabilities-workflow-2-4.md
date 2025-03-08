### Vulnerability List:

- Vulnerability Name: Insecure Defaults and Missing Hardening Guidance for Kibana Deployment
- Description:
    1. The Terraform module deploys Kibana on Kubernetes using a Helm chart.
    2. By default, the module does not enforce or guide users towards enabling crucial security features in Kibana, such as HTTPS and authentication.
    3. If users deploy Kibana using the default configurations and expose it publicly without further hardening, the Kibana instance will be vulnerable to Cross-Site Scripting (XSS) and other attacks inherent to Kibana itself if not properly secured.
    4. An attacker could exploit XSS vulnerabilities in Kibana dashboards to compromise user sessions or gain unauthorized access to Kibana functionality and potentially the underlying Elasticsearch data.
- Impact:
    - High. If Kibana is deployed with default settings and exposed, it is vulnerable to XSS attacks. Successful XSS attacks can lead to session hijacking, data theft, unauthorized access to Kibana, and potentially the underlying Elasticsearch data. This can compromise the confidentiality, integrity, and availability of the Kibana instance and associated data.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - None in the Terraform module itself. The module allows users to configure `kibanaConfig` in `values.yaml` to enable security features in Kibana, but there are no default security configurations enabled, and no explicit guidance within the module to enforce or encourage secure configurations.
- Missing Mitigations:
    - The module should provide secure defaults or strongly encourage users to configure security settings.
    - This could include:
        - Providing default configurations that enable HTTPS for Kibana. This might involve options for users to easily provide TLS certificates or guidance on generating them.
        - Adding documentation and examples, directly within the module's README or comments in `values.yaml`, on how to enable authentication and authorization in Kibana using `kibanaConfig`.
        - Consider providing a "security-focused" deployment profile or example in the `examples/` directory that demonstrates a hardened Kibana deployment with HTTPS and authentication enabled.
        - Adding input variables to directly control critical security settings like enabling HTTPS and authentication, making them more visible and easier to configure.
- Preconditions:
    - Kibana is deployed using this Terraform module.
    - Kibana is exposed publicly, typically through an Ingress or LoadBalancer, making it accessible from the internet or untrusted networks.
    - Users rely on default configurations provided by the module and do not explicitly enable HTTPS and authentication for Kibana through `kibanaConfig` or other means.
- Source Code Analysis:
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
- Security Test Case:
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
    4. **Inject XSS Payload:**
        - Go to "Visualize" in Kibana.
        - Create a new Visualization: "Markdown".
        - In the markdown editor, enter the following XSS payload: `<script>alert('XSS Vulnerability Detected in Kibana')</script>`.
        - Save the visualization (e.g., name it "XSS Test").
        - Create a new Dashboard and add the "XSS Test" visualization to it.
        - View the dashboard.
    5. **Verification:**
        - Observe if an alert box with the message "XSS Vulnerability Detected in Kibana" appears in your browser.
        - If the alert box appears, it confirms that Kibana is vulnerable to XSS due to the insecure default deployment without proper hardening.

This test case demonstrates how a default deployment using this module, without additional security configurations, can be vulnerable to XSS, highlighting the vulnerability of insecure defaults and missing hardening guidance.
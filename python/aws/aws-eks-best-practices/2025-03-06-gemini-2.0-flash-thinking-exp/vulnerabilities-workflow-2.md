## Vulnerabilities list:

### Vulnerability 1

- Vulnerability name: Gatekeeper Policies - Namespace Exclusion Vulnerability
- Description:
    - A malicious actor could submit a pull request suggesting to exclude the `kube-system` namespace from Gatekeeper policies as a best practice.
    - If this pull request is merged, users who apply these policies to their clusters will inadvertently disable security controls for the `kube-system` namespace.
    - Attackers could then deploy malicious workloads or modify existing components within the `kube-system` namespace, potentially gaining cluster-admin level privileges or compromising critical system components.
- Impact:
    - High. Compromise of the `kube-system` namespace can lead to full cluster compromise, including control plane access and data exfiltration.
- Vulnerability rank: Critical
- Currently implemented mitigations:
    - None. The documentation explicitly suggests excluding `kube-system` namespace.
- Missing mitigations:
    - The documentation should explicitly warn against excluding critical namespaces like `kube-system` from security policies.
    - The documentation should recommend a more secure approach, such as carefully auditing and whitelisting exceptions for specific add-ons within `kube-system` instead of a blanket exclusion.
- Preconditions:
    - An attacker successfully submits and merges a pull request that promotes excluding `kube-system` namespace from Gatekeeper policies.
    - Users follow the documentation and deploy the example Gatekeeper policies without reviewing or modifying them.
- Source code analysis:
    - File: `/code/policies/alternative-gatekeeper/README.md`
    - The `README.md` file under `/code/policies/alternative-gatekeeper/` suggests: "**NOTE:** We excluded the `kube-system` namespace in all of the constraints as many infrastructure add-ons have legitimate need for, and thus require exceptions these limitations of, elevated privileges. If you deploy those things to the kube-system namespace they will not be blocked by these example policies."
    - This note, while intending to be helpful for avoiding conflicts with legitimate add-ons, can be misinterpreted as a best practice to generally exclude `kube-system` without fully understanding the security implications.
    - An attacker can leverage this suggestion to create a pull request that emphasizes and reinforces this exclusion as a best practice, making it more likely to be accepted and implemented by users.
- Security test case:
    - Step 1: Create a pull request that modifies `/code/policies/alternative-gatekeeper/README.md` to strongly recommend excluding the `kube-system` namespace from Gatekeeper policies for "stability and compatibility".
    - Step 2: As a reviewer, merge the pull request without fully considering the security implications.
    - Step 3: As a user, follow the updated documentation and deploy the Gatekeeper policies to an EKS cluster, without modifying the namespace exclusions.
    - Step 4: Deploy a malicious pod in the `kube-system` namespace, for example, a privileged pod or a pod that violates other security best practices that the Gatekeeper policies are supposed to enforce.
    - Step 5: Observe that the malicious pod is successfully deployed in `kube-system` namespace, demonstrating the bypassed security controls.

### Vulnerability 2

- Vulnerability name: Insecure IAM Role Trust Policy
- Description: The `enable-irsa` command-line utility creates an IAM role with an overly permissive trust policy. The trust policy allows any AWS service ("Service": "eks.amazonaws.com") to assume the created IAM role. This violates the principle of least privilege and could allow unintended services or actors to assume the role. An attacker exploiting this vulnerability could potentially gain unauthorized access to AWS resources if they can leverage any AWS service to assume the created role.
- Impact: Unauthorized access to AWS resources. An attacker could potentially escalate privileges or access sensitive data within the AWS account.
- Vulnerability rank: High
- Currently implemented mitigations: None. The script as provided creates an IAM role with a wide-open trust policy.
- Missing mitigations: The IAM role's trust policy should be restricted to allow only the `aws-node` service account, within the `kube-system` namespace, of the specific EKS cluster to assume the role. This can be achieved by modifying the `create_iam_role` function to construct a more restrictive `AssumeRolePolicyDocument`.
- Preconditions: An administrator must run the `enable-irsa` utility, providing a cluster name and role name.
- Source code analysis:
  - In the file `/code/projects/enable-irsa/src/main.py`, the function `create_iam_role` defines the trust policy for the IAM role being created.
  - The `AssumeRolePolicyDocument` is hardcoded to allow any service principal `eks.amazonaws.com` to assume the role:
    ```python
    assume_role_policy_document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "Service": "eks.amazonaws.com"
                },
                "Action": "sts:AssumeRole"
            }
        ]
    }
    ```
  - This policy is overly broad, as it does not restrict the role assumption to a specific service account or EKS cluster, violating the principle of least privilege.
- Security test case:
  1. Execute the `enable-irsa` utility using the command: `python main.py --cluster-name test-cluster --role-name test-role`.
  2. Log in to the AWS Management Console and navigate to the IAM service.
  3. Find the IAM role created by the script (e.g., `test-role`).
  4. Inspect the trust policy of the created IAM role.
  5. Observe that the `Principal` section of the trust policy is set to:
     ```json
     "Principal": {
         "Service": "eks.amazonaws.com"
     }
     ```
  6. This confirms that the trust policy is insecurely configured, allowing any AWS service to assume the role, and validates the vulnerability.

### Vulnerability 3

- Vulnerability name: Cluster Autoscaler IAM Role with Wildcard Resource
- Description:
  - A user follows the best practices guide and deploys Cluster Autoscaler using the provided IAM policy example.
  - The IAM policy example in the guide uses a wildcard "*" for the Resource element in the "Allow" statement for actions "autoscaling:SetDesiredCapacity" and "autoscaling:TerminateInstanceInAutoScalingGroup".
  - An attacker, by misinterpreting this best practice, might create an IAM role with this overly permissive policy in their EKS cluster.
  - An attacker who gains access to the Cluster Autoscaler's IAM role (e.g., through compromised Kubernetes service account or node) can then use these permissions to manipulate any Auto Scaling Group in the AWS account, not just those related to the EKS cluster. This could lead to disruption of other services or resources managed by Auto Scaling Groups in the same AWS account.
- Impact: An attacker with access to the Cluster Autoscaler's IAM role can potentially disrupt or manipulate any Auto Scaling Group within the AWS account, leading to broader service disruptions beyond the EKS cluster itself.
- Vulnerability rank: High
- Currently implemented mitigations: The guide mentions "employ least privilege access by limiting Actions `autoscaling:SetDesiredCapacity` and `autoscaling:TerminateInstanceInAutoScalingGroup` to the Auto Scaling groups that are scoped to the current cluster." This is a mitigation, but the example policy itself is still vulnerable.
- Missing mitigations: The example IAM policy should be updated to use specific ARNs for the Resource element, limiting the actions to only the Auto Scaling Groups associated with the EKS cluster. The guide should also strongly emphasize the importance of least privilege and provide clear instructions on how to scope down the IAM policy to the necessary resources.
- Preconditions: User must follow the best practices guide and implement the example IAM policy for Cluster Autoscaler without modification.
- Source code analysis:
  - File: /code/content/cluster-autoscaling/index.md
  - The `Resource: "*"` in the example policy is the source of the vulnerability.
  - ```markdown
    ### Employ least privileged access to the IAM role

    When the [Auto Discovery](https://github.com/kubernetes/autoscaler/blob/master/cluster-autoscaler/cloudprovider/aws/README.md#Auto-discovery-setup) is used, we strongly recommend that you employ least privilege access by limiting Actions `autoscaling:SetDesiredCapacity` and `autoscaling:TerminateInstanceInAutoScalingGroup` to the Auto Scaling groups that are scoped to the current cluster.

    ...

    ```json
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "autoscaling:SetDesiredCapacity",
                    "autoscaling:TerminateInstanceInAutoScalingGroup"
                ],
                "Resource": "*"
                ...
    ```
- Security test case:
  - Deploy Cluster Autoscaler in an EKS cluster using the example IAM policy provided in `/code/content/cluster-autoscaling/index.md`.
  - Obtain the IAM role ARN used by the Cluster Autoscaler (e.g., by inspecting the service account annotations or the Cluster Autoscaler pod's IAM role).
  - Use AWS CLI or SDK with the Cluster Autoscaler's IAM role credentials.
  - Attempt to modify the DesiredCapacity or Terminate instances of an Auto Scaling Group that is NOT related to the EKS cluster (e.g., another ASG in the same AWS account or a different ASG).
  - Verify that the action is successful, proving that the wildcard resource allows access to resources outside the intended scope.
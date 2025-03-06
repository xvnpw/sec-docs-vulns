### Vulnerability List

- Vulnerability Name: Cluster Autoscaler IAM Role with Wildcard Resource
- Description:
  - A user follows the best practices guide and deploys Cluster Autoscaler using the provided IAM policy example.
  - The IAM policy example in the guide uses a wildcard "*" for the Resource element in the "Allow" statement for actions "autoscaling:SetDesiredCapacity" and "autoscaling:TerminateInstanceInAutoScalingGroup".
  - An attacker, by misinterpreting this best practice, might create an IAM role with this overly permissive policy in their EKS cluster.
  - An attacker who gains access to the Cluster Autoscaler's IAM role (e.g., through compromised Kubernetes service account or node) can then use these permissions to manipulate any Auto Scaling Group in the AWS account, not just those related to the EKS cluster. This could lead to disruption of other services or resources managed by Auto Scaling Groups in the same AWS account.
- Impact: An attacker with access to the Cluster Autoscaler's IAM role can potentially disrupt or manipulate any Auto Scaling Group within the AWS account, leading to broader service disruptions beyond the EKS cluster itself.
- Vulnerability Rank: High
- Currently Implemented Mitigations: The guide mentions "employ least privilege access by limiting Actions `autoscaling:SetDesiredCapacity` and `autoscaling:TerminateInstanceInAutoScalingGroup` to the Auto Scaling groups that are scoped to the current cluster." This is a mitigation, but the example policy itself is still vulnerable.
- Missing Mitigations: The example IAM policy should be updated to use specific ARNs for the Resource element, limiting the actions to only the Auto Scaling Groups associated with the EKS cluster. The guide should also strongly emphasize the importance of least privilege and provide clear instructions on how to scope down the IAM policy to the necessary resources.
- Preconditions: User must follow the best practices guide and implement the example IAM policy for Cluster Autoscaler without modification.
- Source Code Analysis:
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
- Security Test Case:
  - Deploy Cluster Autoscaler in an EKS cluster using the example IAM policy provided in `/code/content/cluster-autoscaling/index.md`.
  - Obtain the IAM role ARN used by the Cluster Autoscaler (e.g., by inspecting the service account annotations or the Cluster Autoscaler pod's IAM role).
  - Use AWS CLI or SDK with the Cluster Autoscaler's IAM role credentials.
  - Attempt to modify the DesiredCapacity or Terminate instances of an Auto Scaling Group that is NOT related to the EKS cluster (e.g., another ASG in the same AWS account or a different ASG).
  - Verify that the action is successful, proving that the wildcard resource allows access to resources outside the intended scope.
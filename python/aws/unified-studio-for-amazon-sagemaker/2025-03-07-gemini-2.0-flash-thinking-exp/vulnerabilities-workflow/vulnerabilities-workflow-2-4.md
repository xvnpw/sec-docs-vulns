### Vulnerability List:

- Vulnerability Name: Overly Permissive IAM Policy in Example for EMR Compute Access Role
- Description:
    - The documentation for migrating EMR compute (in `/code/migration/emr/README.md`, section "Step 2.1.3: Create EMR Access Role/Modify Project Role/Bring your own Role", step 1) provides an example IAM policy for creating an EMR Access Role.
    - This example policy uses a wildcard resource `arn:aws:elasticmapreduce:<region>:<AccountID>:cluster/*` for `elasticmapreduce:ListInstances`, `elasticmapreduce:DescribeCluster`, and `elasticmapreduce:DescribeSecurityConfiguration` actions.
    - An attacker could leverage this overly permissive policy to gain information about *all* EMR clusters in the specified AWS account and region, not just the intended cluster, if a user creates a role using this example policy without modification.
    - This is because the resource is defined as `arn:aws:elasticmapreduce:<region>:<AccountID>:cluster/*` which allows the actions on all clusters within the account and region, instead of being restricted to a specific cluster ARN.
- Impact:
    - Information Disclosure: An attacker with a role based on the example policy could list and describe all EMR clusters within the AWS account and region. This could reveal sensitive information about the organization's EMR infrastructure, including cluster configurations, instance details, and security configurations, potentially aiding further attacks.
- Vulnerability Rank: Medium
- Currently Implemented Mitigations:
    - None. The documentation provides the example policy as is, without explicitly warning about the broad scope of the wildcard resource and suggesting to restrict it to specific clusters.
- Missing Mitigations:
    - Documentation should be updated to explicitly warn users about the security implications of using a wildcard resource in the EMR Access Role policy.
    - Documentation should recommend restricting the resource in the policy to the specific EMR cluster ARN that the SageMaker Unified Studio project needs to access, instead of using a wildcard.
    - Consider providing a more restrictive example policy in the documentation that targets a specific cluster ARN.
- Preconditions:
    - A user follows the documentation in `/code/migration/emr/README.md` to create an EMR Access Role for connecting an existing EMR on EC2 cluster to SageMaker Unified Studio.
    - The user copies and uses the example IAM policy provided in the documentation without modifying the resource definition to be specific to their intended EMR cluster.
    - The attacker gains access to a role or user that has been granted this overly permissive EMR Access Role.
- Source Code Analysis:
    - The vulnerability is not in the source code of the Python scripts, but in the example IAM policy provided in the documentation file `/code/migration/emr/README.md`.
    - The relevant code snippet from `/code/migration/emr/README.md` is:
    ```
    {
    "Version": "2012-10-17",
    "Statement": [
    {
    "Sid": "EmrAccess",
    "Effect": "Allow",
    "Action": [
    "elasticmapreduce:ListInstances",
    "elasticmapreduce:DescribeCluster",
    "elasticmapreduce:DescribeSecurityConfiguration"
    ],
    "Resource": "arn:aws:elasticmapreduce:<region>:<AccountID>:cluster/*"
    }
    ]
    }
    ```
    - The `Resource: "arn:aws:elasticmapreduce:<region>:<AccountID>:cluster/*"` line is the source of the vulnerability. The wildcard `*` at the end of the ARN for `cluster` means the policy applies to all clusters in the specified region and account.
    - An attacker exploiting a role with this policy can use AWS CLI commands like `aws emr list-clusters` and `aws emr describe-cluster --cluster-id <cluster-id>` to enumerate and inspect details of EMR clusters beyond the intended scope.

- Security Test Case:
    1. **Prerequisites:**
        - An AWS account with EMR clusters running.
        - Access to create IAM roles and policies in the AWS account.
        - An attacker persona with AWS CLI configured and IAM credentials that can be modified.
    2. **Steps:**
        - As an attacker (or a test user mimicking an attacker), create an IAM policy using the example code from `/code/migration/emr/README.md` exactly as provided, specifically with `Resource: "arn:aws:elasticmapreduce:<region>:<AccountID>:cluster/*"`. Name it "OverlyPermissiveEMRAccessPolicy".
        - Create an IAM role, e.g., "AttackerEMRAccessRole", and attach the "OverlyPermissiveEMRAccessPolicy" to it.
        - Configure the attacker's AWS CLI to use the "AttackerEMRAccessRole" credentials.
        - Use the AWS CLI command `aws emr list-clusters` to list all EMR clusters in the region.
        - Use the AWS CLI command `aws emr describe-cluster --cluster-id <any-cluster-id-from-list-clusters>` to describe details of any EMR cluster in the account.
    3. **Expected Result:**
        - The `aws emr list-clusters` command should successfully list all EMR clusters in the account.
        - The `aws emr describe-cluster` command should successfully return detailed information about the specified EMR cluster.
        - This demonstrates that the policy allows access to list and describe *all* EMR clusters due to the wildcard resource, confirming the vulnerability.
    4. **Remediation:**
        - Modify the "OverlyPermissiveEMRAccessPolicy" to restrict the `Resource` to a specific EMR cluster ARN, e.g., `arn:aws:elasticmapreduce:<region>:<AccountID>:cluster/j-xxxxxxxxxxxxx`.
        - Re-run the security test case with the modified policy.
    5. **Expected Result after Remediation:**
        - The `aws emr list-clusters` command should still list all EMR clusters (as `ListClusters` doesn't operate on specific cluster resources).
        - However, the `aws emr describe-cluster --cluster-id <cluster-id>` command should now only succeed for the specific cluster ARN defined in the policy's `Resource`, or fail with an authorization error if a different cluster ID is used (depending on the exact intended access and policy design). If the intention is to only allow `ListInstances` and `DescribeSecurityConfiguration` on a specific cluster, the `DescribeCluster` action with a wildcard resource should also be restricted to the specific cluster resource.
        - This confirms that restricting the resource scope mitigates the information disclosure vulnerability.
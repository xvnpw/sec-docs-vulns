* Vulnerability name: Overly Permissive IAM Role due to Trust Policy Merging in BYOR Utility
* Description:
    1. The `byor.py` script allows users to bring their own IAM role (`--bring-in-role-arn`) to replace or enhance the default SageMaker Unified Studio project role.
    2. In both `use-your-own-role` and `enhance-project-role` modes, the script merges the trust policy of the project's auto-generated execution role with the trust policy of the BYOR role. This is done by the `_combine_trust_policy` function.
    3. The `_combine_trust_policy` function appends statements from the BYOR role's trust policy to the project role's trust policy if they are not already present, effectively making the project role trust both the original trusted entities and the entities trusted by the BYOR role.
    4. If the BYOR role's trust policy is overly permissive (e.g., trusts `arn:aws:iam::*:root` or a wide range of AWS accounts or services), these overly permissive trust relationships will be added to the project role's trust policy.
    5. Consequently, the SageMaker Unified Studio project role, which is used by various services and users within the SageMaker environment, will inherit these overly permissive trust relationships, potentially allowing unintended entities to assume this powerful project role.
    6. An attacker could leverage this by crafting a BYOR role with a deliberately broad trust policy and using the `byor.py` script to apply it to a SageMaker Unified Studio project.
    7. After the script execution, any principal that is trusted by the attacker-controlled BYOR role will also be trusted by the SageMaker project role.
    8. If the attacker's principal can now assume the SageMaker project role, they gain access to all resources and permissions associated with that role within the SageMaker Unified Studio environment.
* Impact:
    - **High Impact:** Unauthorized IAM principals can assume the SageMaker Unified Studio project role.
    - Privilege Escalation: Attackers can escalate their privileges to the level of the project role, which typically has broad access within the SageMaker Unified Studio environment, including data, compute resources, and potentially connected AWS services.
    - Data Breach: With an assumed project role, attackers could access sensitive data stored and processed within SageMaker Unified Studio.
    - Resource Manipulation: Attackers could use the project role to manipulate SageMaker resources, EMR clusters, Athena connections, and other integrated services.
    - Lateral Movement: Compromise of the project role can facilitate lateral movement to other AWS resources accessible from within the SageMaker Unified Studio environment.
* Vulnerability rank: High
* Currently implemented mitigations:
    - No specific mitigation is implemented in the `byor.py` script to prevent merging overly permissive trust policies.
    - The README.md for `bring-your-own-role` section provides a "Required Permissions" policy for the script executor, but it does not warn against using overly permissive BYOR roles.
    - The README.md mentions "Important Prerequisites and Considerations" but these are focused on operational aspects (resource creation, job management) and not on the security implications of BYOR role trust policies.
* Missing mitigations:
    - **Input Validation for BYOR Role Trust Policy:** Implement validation in `byor.py` to analyze the trust policy of the `--bring-in-role-arn`.
    - **Warning for Overly Permissive Trust Policies:** If the BYOR role's trust policy is deemed overly permissive (e.g., contains `arn:aws:iam::*:root` or broad service principals), the script should issue a warning to the user and ideally halt execution or require explicit confirmation to proceed.
    - **Least Privilege Guidance in Documentation:** Update the README.md for `bring-your-own-role` to strongly emphasize the principle of least privilege when creating BYOR roles. Provide examples of secure trust policies and explicitly warn against overly broad trust relationships.
    - **Review of Merged Trust Policy:** Before applying the merged trust policy, the script could display the resulting merged policy to the user for review and confirmation, especially when potentially permissive statements are being added.
* Preconditions:
    1. The attacker needs to have the ability to execute the `byor.py` script. This typically means they need to be an administrator of the SageMaker Unified Studio domain or project, as described in the "Configuration Steps" of the `bring-your-own-role/README.md`.
    2. The attacker needs to be able to create or control an IAM role (`--bring-in-role-arn`) with an overly permissive trust policy.
    3. The target SageMaker Unified Studio project must be configured to use the `bring-your-own-role` migration utility.
* Source code analysis:
    1. **`byor.py` script:** The core vulnerability lies in the `_combine_trust_policy` function within the `byor.py` script.
    2. **`_combine_trust_policy(trust_policy_1, trust_policy_2)` function:**
       ```python
       def _combine_trust_policy(trust_policy_1, trust_policy_2):
           combined_trust_policy = trust_policy_1.copy()
           for new_statement in trust_policy_2['Statement']:
               if not any(_statements_equal(new_statement, existing_statement)
                          for existing_statement in combined_trust_policy['Statement']):
                   combined_trust_policy['Statement'].append(new_statement)
           return combined_trust_policy
       ```
       - This function takes two trust policies as input (`trust_policy_1` is the project role's trust policy, `trust_policy_2` is the BYOR role's trust policy).
       - It iterates through each statement in `trust_policy_2['Statement']`.
       - For each `new_statement`, it checks if an equivalent statement already exists in `trust_policy_1['Statement']` using the `_statements_equal` function.
       - If no equivalent statement exists, the `new_statement` is appended to `combined_trust_policy['Statement']`.
       - The function returns the `combined_trust_policy`.
    3. **Vulnerability:** The vulnerability is that this merging logic blindly adds trust policy statements from the BYOR role to the project role without any validation or security checks. If the BYOR role's trust policy contains overly broad or malicious statements, these will be directly incorporated into the project role's trust policy, widening the circle of principals that can assume the project role. There is no mechanism to prevent the inclusion of statements like:
       ```json
       {
           "Effect": "Allow",
           "Principal": {"AWS": "arn:aws:iam::*:root"},
           "Action": "sts:AssumeRole"
       }
       ```
       or trusting a wide range of AWS accounts or services that are not intended to have access to the SageMaker Unified Studio project.
    4. **Script Execution Flow (relevant parts):**
       - In both `ROLE_REPLACEMENT` and `ROLE_ENHANCEMENT` modes of `byor.py`, the script calls `_combine_trust_policy` to merge trust policies.
       - The merged trust policy is then applied to the project role using `_update_trust_policy`.
       - This directly leads to the described vulnerability if a malicious or misconfigured BYOR role is used.
* Security test case:
    1. **Pre-requisites:**
        -  Have an AWS account with SageMaker Unified Studio enabled.
        -  Create a SageMaker Unified Studio Domain and Project.
        -  Ensure you have permissions to execute the `byor.py` script as per the "Configuration Steps" in `bring-your-own-role/README.md`.
    2. **Create a malicious BYOR IAM Role:**
        - Create an IAM role named `MaliciousBYORRole` in your AWS account.
        - Attach a benign policy to this role (e.g., a policy with no permissions or read-only access to S3). This is not relevant to the vulnerability but IAM roles must have at least one policy.
        - Set the trust policy of `MaliciousBYORRole` to be overly permissive. For example, allow any AWS account to assume this role:
          ```json
          {
              "Version": "2012-10-17",
              "Statement": [
                  {
                      "Effect": "Allow",
                      "Principal": {"AWS": "*"},
                      "Action": "sts:AssumeRole"
                  }
              ]
          }
          ```
          **WARNING:** Using "*" for `Principal` in a real-world scenario is highly insecure. This is for demonstration purposes only. For a less dangerous test, you could replace `"*"` with your own AWS account ID for testing within your own account.
        - Note the ARN of `MaliciousBYORRole`.
    3. **Execute `byor.py` in `enhance-project-role` mode:**
        - Navigate to the directory containing `byor.py` in your terminal.
        - Run the `byor.py` script with the `enhance-project-role` command, providing your SageMaker Domain ID, Project ID, and the ARN of `MaliciousBYORRole`. Replace placeholders with your actual values. Do not include the `--execute` flag initially to preview changes.
          ```bash
          python3 byor.py enhance-project-role \
              --domain-id <Your-SageMaker-Domain-Id> \
              --project-id <Your-SageMaker-Project-Id> \
              --bring-in-role-arn arn:aws:iam::<Your-AWS-Account-ID>:role/MaliciousBYORRole \
              --region <Your-AWS-Region>
          ```
        - Review the output. It should show the proposed trust policy update for the project role, including the overly permissive statement from `MaliciousBYORRole`.
    4. **Execute `byor.py` with `--execute` flag:**
        - Run the same command as in step 3, but now include the `--execute` flag to apply the changes:
          ```bash
          python3 byor.py enhance-project-role \
              --domain-id <Your-SageMaker-Domain-Id> \
              --project-id <Your-SageMaker-Project-Id> \
              --bring-in-role-arn arn:aws:iam::<Your-AWS-Account-ID>:role/MaliciousBYORRole \
              --region <Your-AWS-Region> \
              --execute
          ```
        - The script should execute and update the project role's trust policy.
    5. **Verify the updated trust policy of the project role:**
        - Find the IAM role name of your SageMaker project role. This can be usually identified by the prefix `datazone_usr_role_` and your project ID in the IAM console.
        - In the IAM console, navigate to the project role and check its trust policy.
        - **Vulnerability Confirmation:** The trust policy of the project role should now include the overly permissive statement from `MaliciousBYORRole`'s trust policy, specifically the statement allowing `arn:aws:iam::*:root` (or `arn:aws:iam::<Your-AWS-Account-ID>:root` if you used your own account ID for safer testing) to assume the role, in addition to the original trust relationships. This confirms that the vulnerability exists, as the project role now trusts a broader set of principals than intended due to the trust policy merging in `byor.py`.
    6. **Clean up:**
        - Revert the project role's trust policy to its original state (if possible, or by recreating the project).
        - Delete the `MaliciousBYORRole`.
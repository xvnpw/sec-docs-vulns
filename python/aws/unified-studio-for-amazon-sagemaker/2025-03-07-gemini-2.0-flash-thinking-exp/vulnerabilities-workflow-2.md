## Combined Vulnerability List

### 1. Overly Permissive IAM Role due to Trust Policy Merging Vulnerability

- **Vulnerability Name:** Overly Permissive IAM Role due to Trust Policy Merging

- **Description:**
    1. The `byor.py` script, used in both `use-your-own-role` and `enhance-project-role` modes, allows users to bring their own IAM role (BYOR) to integrate with SageMaker Unified Studio projects.
    2. In both modes, the script attempts to merge the trust policy of the project's auto-generated execution role with the trust policy of the provided BYOR role. This merging is performed by the `_combine_trust_policy` function.
    3. The `_combine_trust_policy` function iterates through statements in the BYOR role's trust policy and appends them to the project role's trust policy if they are not considered duplicates. Duplicate detection is performed by the `_statements_equal` function.
    4. The `_statements_equal` function, intended to identify logically equivalent policy statements, uses a string-based comparison after sorting nested elements within the statements. This approach is not semantically robust and can fail to recognize equivalent statements if they differ in formatting, ordering, or use slightly different but logically identical constructs.
    5. Due to the limitations of `_statements_equal`, the merging process in `_combine_trust_policy` can incorrectly combine trust policies. If the BYOR role has a more permissive trust policy, the merging logic might fail to retain the restrictive aspects of the original Project role's trust policy while incorporating the broader permissions of the BYOR role's policy.
    6. Consequently, if a user provides a BYOR role with an overly permissive trust policy (e.g., trusts `arn:aws:iam::*:root` or a wide range of AWS accounts), these overly permissive trust relationships can be added to the SageMaker Unified Studio project role.
    7. An attacker could exploit this by crafting a BYOR role with a deliberately broad trust policy. By executing the `byor.py` script with this malicious BYOR role, they can effectively broaden the trust policy of the SageMaker project role.
    8. After the script execution, any principal trusted by the attacker-controlled BYOR role will also be trusted by the SageMaker project role. If the attacker's principal can now assume the SageMaker project role, they gain unauthorized access to the SageMaker Unified Studio environment and its associated resources.

- **Impact:**
    - **High Impact:** Unauthorized IAM principals can assume the SageMaker Unified Studio project role.
    - **Privilege Escalation:** Attackers can escalate their privileges to the level of the project role, gaining broad access within the SageMaker Unified Studio environment.
    - **Data Breach:** With an assumed project role, attackers could access sensitive data stored and processed within SageMaker Unified Studio.
    - **Resource Manipulation:** Attackers could use the project role to manipulate SageMaker resources, EMR clusters, Athena connections, and other integrated services.
    - **Lateral Movement:** Compromise of the project role can facilitate lateral movement to other AWS resources accessible from within the SageMaker Unified Studio environment.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
    - No specific mitigation is implemented in the `byor.py` script to prevent merging overly permissive trust policies or to correctly merge trust policies in a semantically sound manner.
    - The README.md provides "Required Permissions" for the script executor but lacks warnings about overly permissive BYOR roles or the risks of incorrect trust policy merging.

- **Missing Mitigations:**
    - **Robust Trust Policy Merging Mechanism:** Replace the current `_combine_trust_policy` and `_statements_equal` functions with a more robust and semantically correct trust policy merging mechanism. This should involve deep inspection of policy statements, understanding their logical intent, and potentially using policy analysis libraries.
    - **Input Validation for BYOR Role Trust Policy:** Implement validation in `byor.py` to analyze the trust policy of the `--bring-in-role-arn` before merging.
    - **Warning for Overly Permissive Trust Policies:** If the BYOR role's trust policy is deemed overly permissive (e.g., contains `arn:aws:iam::*:root` or broad service principals), the script should issue a warning and halt execution or require explicit user confirmation.
    - **Least Privilege Guidance in Documentation:** Update the README.md to strongly emphasize least privilege for BYOR roles. Provide examples of secure trust policies and explicitly warn against overly broad trust relationships and the risks of incorrect merging.
    - **Review of Merged Trust Policy:** Before applying the merged policy, the script could display the resulting merged policy to the user for review and confirmation, especially when potentially permissive statements are being added.

- **Preconditions:**
    1. The attacker must have the ability to execute the `byor.py` script, typically requiring administrator permissions within the SageMaker Unified Studio domain or project.
    2. The attacker needs to control or create an IAM role (`--bring-in-role-arn`) with an overly permissive trust policy.
    3. The target SageMaker Unified Studio project must be configured to use the `bring-your-own-role` migration utility.

- **Source Code Analysis:**
    1. **`byor.py` script:** The vulnerability is centered around the `_combine_trust_policy` and `_statements_equal` functions in the `byor.py` script.
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
       - This function merges trust policies by appending new statements from `trust_policy_2` to `trust_policy_1` if they are not considered duplicates by `_statements_equal`.

    3. **`_statements_equal(statement1, statement2)` function:**
       ```python
       def _statements_equal(statement1, statement2):
           # Helper function to sort nested structures in trust policy
           def sort_nested(item):
               if isinstance(item, dict):
                   return {k: sort_nested(v) for k, v in sorted(item.items())}
               elif isinstance(item, list):
                   return sorted(sort_nested(i) for i in item)
               else:
                   return item

           # Sort all nested structures
           sorted_statement1 = sort_nested(sort_nested(statement1)) # Double sort (typo?)
           sorted_statement2 = sort_nested(sort_nested(statement2)) # Double sort (typo?)
           return json.dumps(sorted_statement1, sort_keys=True) == json.dumps(sorted_statement2, sort_keys=True)
       ```
       - This function attempts to determine statement equality by converting policy statements to JSON strings and comparing them after sorting nested elements.
       - **Vulnerability:** The string-based comparison in `_statements_equal` is semantically weak. It can fail to recognize logically equivalent statements that have different formatting (e.g., different order of keys, whitespace differences, different casing, use of shorthand notations, or complex conditions expressed in different ways). This flaw leads to incorrect trust policy merging in `_combine_trust_policy`, potentially resulting in overly permissive merged policies. There is no validation to prevent the inclusion of overly permissive statements.

- **Security Test Case:**
    1. **Pre-requisites:**
        - AWS account with SageMaker Unified Studio enabled.
        - Create a SageMaker Unified Studio Domain and Project.
        - Permissions to execute `byor.py`.
    2. **Create a malicious BYOR IAM Role:**
        - Create an IAM role named `MaliciousBYORRole`.
        - Set its trust policy to be overly permissive, e.g., allowing any AWS account to assume it:
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
        - Note the ARN of `MaliciousBYORRole`.
    3. **Execute `byor.py` in `use-your-own-role` mode (or `enhance-project-role`):**
        ```bash
        python3 byor.py use-your-own-role \
            --domain-id <Your-SageMaker-Domain-Id> \
            --project-id <Your-SageMaker-Project-Id> \
            --bring-in-role-arn arn:aws:iam::<Your-AWS-Account-ID>:role/MaliciousBYORRole \
            --region <Your-AWS-Region> \
            --execute
        ```
    4. **Verify the updated trust policy of the project role (or BYOR role in `use-your-own-role` mode):**
        - Check the trust policy of the relevant role in the IAM console.
        - **Vulnerability Confirmation:** Verify that the trust policy now includes the overly permissive statement from `MaliciousBYORRole`, indicating that the merging process has broadened the trust relationships.
    5. **Attempt Role Assumption:**
        - From a different AWS account or principal, attempt to assume the modified project role.
        - Successful role assumption from an unintended principal confirms the vulnerability.
    6. **Clean up:** Revert trust policies and delete test roles.


### 2. Privilege Escalation via Bring Your Own Role Enhancement

- **Vulnerability Name:** Privilege Escalation via Bring Your Own Role Enhancement

- **Description:**
    1. An attacker who has permissions to execute the `byor.py` script in `enhance-project-role` mode can escalate the privileges of the default SageMaker Unified Studio project role.
    2. The attacker uses the `enhance-project-role` command, providing the ARN of a custom IAM role (`bring-in-role-arn`) that is intentionally configured with overly permissive policies, such as `AdministratorAccess`.
    3. The `byor.py` script, when executed in `enhance-project-role` mode, copies managed policies, inline policies, tags, LakeFormation grants, and LakeFormation opt-ins directly from the specified `bring-in-role-arn` to the SageMaker Unified Studio project role.
    4. As a direct result of this policy copying, the project role inherits the excessive privileges associated with the `bring-in-role-arn`. This grants users and services assuming the project role within SageMaker Unified Studio significantly elevated privileges, potentially far beyond the intended scope of the project.
    5. This privilege escalation allows for unintended and broad access to SageMaker resources and potentially other AWS services, based on the permissions granted by the policies attached to the attacker-provided `bring-in-role-arn`.

- **Impact:**
    - Users of the SageMaker Unified Studio project, assuming the project role, gain elevated privileges beyond the intended scope.
    - Unauthorized access to sensitive data, modification or deletion of critical resources within SageMaker and potentially other AWS services.
    - In shared SageMaker environments, allows one project member to gain excessive privileges, impacting security and integrity.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
    - None. The script directly copies policies and permissions without any validation, filtering, or security restrictions.

- **Missing Mitigations:**
    - **Input Validation and Warning:** The script should validate the policies attached to the `--bring-in-role-arn`. Detect and warn against overly permissive policies like `AdministratorAccess` or policies with broad `Resource: "*"`.
    - **Policy Filtering and Least Privilege:** Instead of directly copying all policies, implement policy analysis to selectively copy only necessary permissions for SageMaker Unified Studio functionality, adhering to the principle of least privilege.
    - **Documentation Enhancement:** Update documentation to strongly emphasize the security risks of using overly permissive roles with `enhance-project-role`. Recommend least privilege roles and guide users on creating secure roles.

- **Preconditions:**
    - Attacker has IAM permissions to execute `byor.py`.
    - Attacker has or can create an IAM role with overly permissive policies (e.g., AdministratorAccess).
    - Attacker knows the Domain ID and Project ID of the target SageMaker Unified Studio project.

- **Source Code Analysis:**
    - File: `/code/migration/bring-your-own-role/byor.py`
    - Function: `byor_main`
    - Command: `ROLE_ENHANCEMENT`
    - Vulnerable Code Sections:
        ```python
        _copy_managed_policies_arn(byor_role, project_role, [], iam_client, args.execute) # Copies all managed policies
        _copy_inline_policies_arn(byor_role, project_role, iam_client, args.execute) # Copies all inline policies
        _copy_tags(byor_role['Role']['RoleName'], project_role['Role']['RoleName'], iam_client, args.execute) # Copies all tags
        _copy_lakeformation_grants(lakeformation, args.bring_in_role_arn, project_role['Role']['Arn'], args.execute, args.command) # Copies all LakeFormation grants
        _copy_lakeformation_opt_ins(lakeformation, args.bring_in_role_arn, project_role['Role']['Arn'], args.execute) # Copies all LakeFormation opt-ins
        ```
    - The listed functions directly copy permissions from the `byor_role` to the `project_role` without any filtering or validation.
    - `_copy_managed_policies_arn` and `_copy_inline_policies_arn` are particularly critical as they directly transfer policy documents, leading to privilege escalation if a highly permissive `byor_role` is used.

- **Security Test Case:**
    1. **Prerequisites:**
        - AWS account with SageMaker Unified Studio and AWS CLI configured.
        - Permissions to create IAM roles/policies and execute `byor.py`.
        - SageMaker Unified Studio project.
    2. **Create an overly permissive IAM role:**
        - Create IAM role `OverlyPermissiveRole`.
        - Attach `AdministratorAccess` managed policy to it.
        - Note the ARN of `OverlyPermissiveRole`.
    3. **Execute `enhance-project-role` script:**
        ```bash
        python3 byor.py enhance-project-role \
            --domain-id <your_domain_id> \
            --project-id <your_project_id> \
            --bring-in-role-arn <ARN_of_OverlyPermissiveRole> \
            --region <your_aws_region> \
            --execute
        ```
    4. **Verify Project Role Policies:**
        - Locate the project role (e.g., `datazone_usr_role_<project_id>_...`).
        - Check attached managed and inline policies in IAM console.
        - Verify `AdministratorAccess` (or equivalent) is now attached.
    5. **Test Elevated Privileges:**
        - Open SageMaker Studio for the project.
        - Attempt actions restricted by default project role but allowed by `AdministratorAccess` (e.g., access/modify resources outside project scope, actions in other AWS services).
        - Successful actions confirm privilege escalation.
    6. **Clean up:** Remove attached policies and delete test roles.

No vulnerabilities found
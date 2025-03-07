### Vulnerability List

- Vulnerability Name: Overly Permissive Trust Policy due to Incorrect Trust Policy Merging in BYOR Role Replacement/Enhancement
- Description:
    1. The `bring_your_own_role.py` script in `use-your-own-role` or `enhance-project-role` mode retrieves the existing trust policy of the SageMaker Project execution role and the trust policy of the "Bring Your Own Role" (BYOR).
    2. It attempts to merge these two trust policies using the `_combine_trust_policy` function.
    3. The `_combine_trust_policy` function aims to combine statements from both policies while avoiding duplicates using the `_statements_equal` function.
    4. If the `_statements_equal` function fails to correctly identify logically equivalent statements due to differences in formatting, ordering of elements within conditions, or complexity of policy statements, the merging process might incorrectly combine policies.
    5. Specifically, if the BYOR role has a more permissive trust policy than the original Project role (e.g., allowing broader or less restrictive conditions for role assumption), the merged policy applied to the BYOR role might become overly permissive. This can happen if the merging logic fails to recognize and retain the restrictive aspects of the original Project role's trust policy while incorporating the broader permissions of the BYOR role's policy.
    6. As a result, the BYOR role, intended to be used with the SageMaker Unified Studio project, might inadvertently grant broader access than intended, potentially allowing unintended entities (principals) to assume this role and gain access to the SageMaker environment.
- Impact:
    - If the trust policy of the BYOR role becomes overly permissive, unauthorized IAM principals might be able to assume this role.
    - This could lead to unauthorized access to the SageMaker Unified Studio environment and any resources accessible via the BYOR role, such as data in S3, EMR clusters, and other AWS services.
    - An attacker could potentially perform actions within the SageMaker environment using the assumed BYOR role, leading to data breaches, unauthorized modifications, or other malicious activities.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - None. The script attempts to merge trust policies, but the merging logic itself is vulnerable.
- Missing Mitigations:
    - Implement a robust and semantically correct trust policy merging mechanism. This should involve:
        - Deep inspection of policy statements and conditions, not just string-based comparisons.
        - Understanding the logical intent of different policy statements and conditions.
        - Employing a policy analysis library or method to correctly identify and merge equivalent or conflicting statements.
        - Prioritizing the principle of least privilege when merging policies, ensuring that the resulting policy is no more permissive than intended.
    - Thoroughly test the trust policy merging logic with various complex and nested policy structures to ensure correctness and prevent unintended policy widening.
- Preconditions:
    - An attacker needs to have access to execute the `bring_your_own_role.py` script with necessary IAM permissions (as described in the script's README).
    - The attacker must provide a "Bring Your Own Role" ARN that has a trust policy that is more permissive in some aspect than the default SageMaker Project execution role's trust policy.
- Source Code Analysis:
    - File: `/code/migration/bring-your-own-role/byor.py`
    - Function: `_combine_trust_policy(trust_policy_1, trust_policy_2)` and `_statements_equal(statement1, statement2)`
    - The vulnerability lies in the logic within these functions.
    - `_statements_equal` function converts policy statements into JSON strings and compares them after sorting nested elements. This string-based comparison is not semantically aware and can fail to recognize equivalent statements if they differ in formatting, ordering, or use slightly different but logically identical constructs.
    - `_combine_trust_policy` relies on `_statements_equal` to deduplicate statements. If `_statements_equal` is flawed, `_combine_trust_policy` might incorrectly merge or fail to deduplicate, potentially leading to an overly permissive combined policy.

    ```python
    def _combine_trust_policy(trust_policy_1, trust_policy_2):
        combined_trust_policy = trust_policy_1.copy()
        for new_statement in trust_policy_2['Statement']:
            if not any(_statements_equal(new_statement, existing_statement)
                       for existing_statement in combined_trust_policy['Statement']):
                combined_trust_policy['Statement'].append(new_statement)
        return combined_trust_policy

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
        sorted_statement1 = sort_nested(statement1)
        sorted_statement2 = sort_nested(statement2)
        return json.dumps(sorted_statement1, sort_keys=True) == json.dumps(sorted_statement2, sort_keys=True)
    ```
    - The script then uses `_update_trust_policy` to apply the potentially flawed merged trust policy to the BYOR role.

    ```python
    def _update_trust_policy(role_name, new_trust_policy, iam_client, execute_flag):
        if execute_flag:
            print(f"Updating trust policy for role: {role_name}")
            iam_client.update_assume_role_policy(
                RoleName=role_name,
                PolicyDocument=str(new_trust_policy).replace("'", '"')
            )
            print(f"Trust policy updated successfully for role: `{role_name}`\n")
        else:
            print(f"New trust policy for role `{role_name}` would be:")
            pprint(new_trust_policy)
            print(f"Trust policy update skipped for role: `{role_name}`, set --execute flag to True to do the actual update.\n")
    ```

- Security Test Case:
    1. **Setup**:
        - Create a SageMaker Studio Domain and Project in your AWS account.
        - Identify the automatically created Project execution role (let's call it `ProjectRole`). Get its ARN.
        - Create a new IAM role named `BYORole` with the following trust policy (intentionally overly permissive):
        ```json
        {
          "Version": "2012-10-17",
          "Statement": [
            {
              "Effect": "Allow",
              "Principal": {
                "AWS": "*"
              },
              "Action": "sts:AssumeRole"
            }
          ]
        }
        ```
        - Ensure you have an IAM user or role with permissions to run `bring_your_own_role.py` as per the script's documentation.
    2. **Run Script in Preview Mode**:
        - Navigate to the directory containing `bring_your_own_role.py`.
        - Execute the script in `use-your-own-role` mode with preview flag (without `--execute`):
        ```bash
        python3 byor.py use-your-own-role \
            --domain-id <your_domain_id> \
            --project-id <your_project_id> \
            --bring-in-role-arn <ARN_of_BYORole> \
            --region <your_aws_region>
        ```
        - Examine the output, specifically the "New trust policy for role `<BYORoleName>` would be:". Check if the displayed trust policy for `BYORole` is just the overly permissive policy you set, or if it's a merge that still includes restrictions from the original `ProjectRole`'s trust policy. In a vulnerable scenario, it might show the overly permissive policy, indicating incorrect merging.
    3. **Run Script to Apply Changes**:
        - If the preview in step 2 indicates an overly permissive merged policy, execute the script again with the `--execute` flag:
        ```bash
        python3 byor.py use-your-own-role \
            --domain-id <your_domain_id> \
            --project-id <your_project_id> \
            --bring-in-role-arn <ARN_of_BYORole> \
            --region <your_aws_region> \
            --execute
        ```
    4. **Verify Trust Policy in IAM**:
        - After successful execution, go to the AWS IAM console.
        - Find the `BYORole`.
        - Check its trust policy.
        - **Vulnerability Confirmation**: If the trust policy of `BYORole` is indeed the overly permissive policy (or a merge that is unexpectedly broad, allowing role assumption from `Principal: "*"`) and not properly restricted based on the original `ProjectRole`'s trust policy, the vulnerability is confirmed.
    5. **Attempt Role Assumption from External Account**:
        - From a different AWS account (or using an IAM user/role outside the intended scope of the SageMaker project), attempt to assume the `BYORole` using `sts:AssumeRole`.
        - If successful, it demonstrates that the BYOR role has become overly permissive, allowing unintended access.

This vulnerability allows for potential privilege escalation by replacing the project role with a BYOR role that ends up having a broader trust policy than intended, due to flaws in the trust policy merging logic.
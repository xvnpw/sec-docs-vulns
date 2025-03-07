#### 1. Vulnerability Name: Privilege Escalation via Bring Your Own Role Enhancement

- Description:
    1. An attacker, with permissions to execute the `byor.py` script in `enhance-project-role` mode, can escalate the privileges of the default SageMaker Unified Studio project role.
    2. The attacker uses the `enhance-project-role` command and specifies a custom IAM role (`bring-in-role-arn`) that has overly permissive policies (e.g., AdministratorAccess).
    3. The script copies managed policies, inline policies, tags, LakeFormation grants, and LakeFormation opt-ins from the `bring-in-role-arn` to the SageMaker Unified Studio project role.
    4. As a result, the project role inherits the excessive privileges of the `bring-in-role-arn`, granting unintended and broad access to SageMaker resources and potentially other AWS services for users assuming the project role within the SageMaker Unified Studio project.

- Impact:
    - Users of the SageMaker Unified Studio project, assuming the project role, will gain elevated privileges beyond the intended scope of the project.
    - This can lead to unauthorized access to sensitive data, modification or deletion of critical resources within SageMaker and potentially other AWS services, depending on the policies attached to the overly permissive `bring-in-role-arn`.
    - In a shared SageMaker Unified Studio environment, this vulnerability can allow one project member to gain excessive privileges, impacting the security and integrity of the entire project and potentially the associated AWS account.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    - None. The script directly copies policies and permissions without validation or restriction.

- Missing Mitigations:
    - **Input Validation and Warning:** The script should validate the policies attached to the `--bring-in-role-arn`. If overly permissive policies like `AdministratorAccess` or policies with broad `Resource: "*"` are detected, the script should display a warning to the user, highlighting the security risks of proceeding.
    - **Policy Filtering:** Instead of directly copying all policies, the script should analyze the policies of the `--bring-in-role-arn` and selectively copy only the permissions that are strictly necessary for the intended functionality within SageMaker Unified Studio. This would require a more sophisticated policy analysis and permission mapping logic.
    - **Documentation Enhancement:** The documentation should be updated to clearly emphasize the security risks associated with using overly permissive roles with the `enhance-project-role` command. It should strongly recommend using least privilege roles as `--bring-in-role-arn` and provide guidance on how to create such roles.

- Preconditions:
    - The attacker must have the necessary IAM permissions to execute the `byor.py` script.
    - The attacker needs to have access to an IAM role with overly permissive policies (e.g., AdministratorAccess) or be able to create one.
    - The attacker must know the Domain ID and Project ID of the SageMaker Unified Studio project they wish to target.

- Source Code Analysis:
    - File: `/code/migration/bring-your-own-role/byor.py`
    - Function: `byor_main`
    - Command: `ROLE_ENHANCEMENT`
    - Code Flow:
        ```python
        elif args.command == ROLE_ENHANCEMENT:
            print(f"Enhance Project Role...")
            # Get Project's Auto Generated Role
            project_role = _find_project_execution_role(args, iam_client)
            # ...
            # Get BYOR Role's trust policy
            byor_role = iam_client.get_role(
                RoleName=_get_role_name_from_arn(args.bring_in_role_arn),
            )
            # ...
            # Copy BYOR Role's managed policies to Project Role
            _copy_managed_policies_arn(byor_role, project_role, [], iam_client, args.execute) # Vulnerable code: Copies all managed policies
            # Copy BYOR Role's inline policies to Project Role
            _copy_inline_policies_arn(byor_role, project_role, iam_client, args.execute) # Vulnerable code: Copies all inline policies
            # Copy BYOR Role's Tags to Project Role
            _copy_tags(byor_role['Role']['RoleName'], project_role['Role']['RoleName'], iam_client, args.execute) # Vulnerable code: Copies all tags
            # Copy LakeFormation Permissions and Opt-Ins
            _copy_lakeformation_grants(lakeformation, args.bring_in_role_arn, project_role['Role']['Arn'], args.execute, args.command) # Vulnerable code: Copies all LakeFormation grants
            _copy_lakeformation_opt_ins(lakeformation, args.bring_in_role_arn, project_role['Role']['Arn'], args.execute) # Vulnerable code: Copies all LakeFormation opt-ins
            if args.execute:
                print(f"Successfully enhance project user role: {project_role['Role']['Arn']} referring to your own role: {byor_role['Role']['Arn']}")
        ```
    - The functions `_copy_managed_policies_arn`, `_copy_inline_policies_arn`, `_copy_tags`, `_copy_lakeformation_grants`, and `_copy_lakeformation_opt_ins` in `byor.py` directly transfer permissions from the `byor_role` to the `project_role` without any filtering or validation.
    - Specifically, `_copy_managed_policies_arn` iterates through attached managed policies of the `byor_role` and attaches them to the `project_role`. Similarly, `_copy_inline_policies_arn` copies all inline policies. This behavior leads to the privilege escalation vulnerability if a highly permissive `byor_role` is used.

- Security Test Case:
    1. **Prerequisites:**
        - AWS account with SageMaker Unified Studio enabled.
        - Permissions to create IAM roles and policies, and execute the `byor.py` script.
        - A SageMaker Unified Studio project.
        - AWS CLI configured.
        - Clone the GitHub repository containing the `byor.py` script.
    2. **Create an overly permissive IAM role:**
        - Create an IAM role named `OverlyPermissiveRole`.
        - Attach the `AdministratorAccess` managed policy to `OverlyPermissiveRole`.
        - Note the ARN of `OverlyPermissiveRole`.
    3. **Execute `enhance-project-role` script:**
        - Navigate to the directory containing `byor.py` in your terminal.
        - Run the following command, replacing placeholders with your actual values:
          ```bash
          python3 byor.py enhance-project-role \
              --domain-id <your_domain_id> \
              --project-id <your_project_id> \
              --bring-in-role-arn <ARN_of_OverlyPermissiveRole> \
              --region <your_aws_region> \
              --execute
          ```
    4. **Verify Project Role Policies:**
        - Find the project role name. It typically follows the pattern `datazone_usr_role_<project_id>_<tooling_bp_environment_id>`. You can find it in the IAM console by searching for roles containing `datazone_usr_role_`.
        - In the IAM console, navigate to the project role.
        - Check the attached managed policies and inline policies for the project role.
        - Verify that the `AdministratorAccess` policy (or equivalent policies from `OverlyPermissiveRole`) is now attached to the project role.
    5. **Test Elevated Privileges in SageMaker Studio:**
        - Open SageMaker Studio for the project.
        - Attempt to perform actions that are typically restricted by the default project role, but are permitted by `AdministratorAccess`. For example, try to access or modify resources outside the scope of the project, or perform actions in other AWS services from within a SageMaker Studio notebook using the project role credentials.
        - If these actions are successful, it confirms that the project role has been successfully escalated to have `AdministratorAccess` level privileges due to the `enhance-project-role` script.

This test case demonstrates that using `enhance-project-role` with an overly permissive role leads to privilege escalation of the SageMaker Unified Studio project role.
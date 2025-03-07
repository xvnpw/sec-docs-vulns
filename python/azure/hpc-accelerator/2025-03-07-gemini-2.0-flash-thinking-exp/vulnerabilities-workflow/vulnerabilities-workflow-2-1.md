- Vulnerability Name: Overly Permissive Inbound Network Security Group Rule in HPC AI Lab Deployment
- Description: The Bicep template `/code/scenarios/hpc_ai_lab/bicep/main.bicep` used for deploying the HPC AI Lab sets a default inbound Network Security Group (NSG) rule named `defaultInbound` that allows inbound traffic from the entire `VirtualNetwork`. If the virtual network where the HPC AI Lab is deployed is not properly segmented and is connected to a less secure network (e.g., corporate network or internet-facing resources without proper firewalling), this rule could allow unauthorized network access to the deployed HPC and AI resources from within the broader virtual network. An attacker within the same virtual network or a connected network could potentially exploit this rule to access services running on the deployed VMs, depending on the services and their configurations.
- Impact: Unauthorized network access to HPC and AI lab resources. Depending on the services running and their vulnerabilities, this could lead to data breaches, unauthorized operations, or further compromise of the HPC environment.
- Vulnerability Rank: Medium
- Currently Implemented Mitigations: None. The Bicep template sets up the rule as described without any restrictions within the code.
- Missing Mitigations:
    - Restrict the `defaultInbound` rule to only allow traffic from necessary subnets or specific IP ranges within the virtual network, rather than the entire `VirtualNetwork`.
    - Implement network segmentation to isolate the HPC AI Lab deployment in a dedicated subnet or virtual network with stricter access controls.
    - Document and recommend secure network configuration practices to users deploying the HPC AI Lab.
- Preconditions:
    - The user deploys the HPC AI Lab using the provided Bicep template `/code/scenarios/hpc_ai_lab/bicep/main.bicep`.
    - The Azure Virtual Network where the HPC AI Lab is deployed is connected to a wider network that may contain untrusted or less secure entities.
- Source Code Analysis:
    1. Open the file `/code/scenarios/hpc_ai_lab/bicep/main.bicep`.
    2. Locate the resource definition for the Network Security Group, which is named `batchPoolNsg` and `adfVmNsg`.
    3. Examine the `securityRules` property of these NSG resources.
    4. Observe the rule named `defaultInbound` (or similar name indicating default inbound rule).
    5. Notice that the `sourceAddressPrefixes` property for this rule includes `VirtualNetwork`, allowing inbound traffic from the entire virtual network.

    ```bicep
    resource batchPoolNsg 'Microsoft.Network/networkSecurityGroups@2021-08-01' = {
      name: '${prefix}-nsg-pool'
      location: location
      tags: tags
      properties: {
        securityRules: [
          {
            name: 'defaultInbound'
            properties: {
              priority: 100
              direction: 'Inbound'
              access: 'Allow'
              protocol: 'All'
              sourcePortRange: '*'
              destinationPortRange: '*'
              sourceAddressPrefixes: [
                'VirtualNetwork' // <--- Vulnerable rule definition
                'AzureLoadBalancerInbound'
              ]
              destinationAddressPrefix: '*'
            }
          }
          // ... other rules ...
        ]
      }
    }
    ```
- Security Test Case:
    1. Deploy the HPC AI Lab using the Bicep template `/code/scenarios/hpc_ai_lab/bicep/main.bicep` into an Azure subscription.
    2. Ensure the deployed VNET is connected to another VNET or network where you can place a test VM. If deploying in a standalone VNET, create a separate VM within the same VNET to simulate an attacker within the network.
    3. Identify the private IP address of one of the VMs in the deployed HPC AI Lab (e.g., the Batch pool VM or ADF VM).
    4. From the test VM (attacker VM) within the same or connected VNET, attempt to access common ports on the HPC AI Lab VM (e.g., SSH port 22, HTTP port 80, or any other relevant service ports) using tools like `nmap` or `telnet`.
    5. Verify that the connection is successful, indicating that the `defaultInbound` rule is allowing traffic from the VNET as expected. For example, using `telnet <HPC_AI_LAB_VM_IP> 22` should establish a connection if SSH port is open and accessible due to the rule.
    6. (Optional) Deploy a service on the HPC AI Lab VM (e.g., a simple web server on port 80) and verify that it is accessible from the test VM using a web browser or `curl`, further confirming the impact of the overly permissive rule.
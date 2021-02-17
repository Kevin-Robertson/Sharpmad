# Sharpmad
C# version of Powermad

This is not yet complete and has not been fully tested. It's also missing the following:
* Invoke-DNSUpdate   
* Get-KerberosAESKey

## Temp Readme

## ADIDNS Module

`Sharpmad.exe ADIDNS -Action new -Node test`   

|Action | Description |
|----------------|----------------|  
|AddACE | Add ACE to node.  |
|Disable | Tombstone a node.  |
|GetDACL | Get node or zone DACL.  |
|GetOwner |     Get node owner.  |
|GetAttribute | Get node attribute value.  |
|GetTombsone  | Get node tombstone status.  |
|GetZone |      Get zone partition location.  |
|New |          Add a node. | 
|GetAttribute | Set node attribute value. | 
|SetOwner |     Set node owner.  |
|Remove |       Remove a node. | 
|Rename |       Rename a node. | 
|RemoveACE |    Remove ACE from node.  |

## MachineAccountQuota Module

`Sharpmad.exe MAQ -Action new -MachineAccount test -MachinePassword password`  

|Action | Description |
|----------------|----------------|   
|AgentSmith |   Recursive machine account creator.  |
|Disable |      Disable a machine account.  |
|GetAttribute | Get machine account attribute value.  |
|GetCreator |   Get all machine account creators. | 
|New |          Add a machine account. | 
|Remove |       Remove a machine account (access required). | 
|SetAttribute | Get machine account attribute value. | 

## Parameters

### Common Parameters
 
|Parameter  | Description |
|----------------|----------------|   
|Append  |            Switch: Append an attribute value rather than overwriting.  |
|Attribute  |         LDAP attribute to get or set.  |
|Clear  |             Switch: Clear an attribute value.  |
|DistinguishedName  | Distinguished name to use. Do not include the ADIDNS node or MachineAccount name.  |
|Domain  |            Targeted domain in DNS format. | 
|DomainController  |  Domain controller to target. This parameter is mandatory on a non-domain attached system. | 
|Username  |          LDAP username in either domain\\username or UPN format. | 
|Verbose  |           Switch: Verbose output. | 
|Value  |             Attribute value. | 
|Password  |          LDAP password. |  

### ADIDNS Parameters
 
|Parameter  | Description |
|----------------|----------------|  
|Access    |          Access for ACE.  |
|AccessType  |        Allow or Deny for the ACE.  |
|Data    |            DNS record data.  |
|Forest   |           AD forest.  |
|Node  |              DNS record name.  |
|NodeNew   |          New node name for renames.  |
|Partition  |         AD partition where the zone is stored.  |
|Principal  |         ACE principal.  |
|Preference  |        MX record preference.  |
|Priority  |          SRV record priority.  |
|SOASerialNumber |    SOA serial number that will be incremented by 1.  |
|Static   |           Switch: Create a static record.  |
|Tombstone  |         Switch: Set the tombstone attribute to true upon node creation. | 
|TTL    |             DNS record TTL.  |
|Type    |            DNS record type. (A, AAAA, CNAME, DNAME, NS, MX, PTR, SRV, TXT)  |
|Weight    |          SRV record weight. |
|Zone      |          ADIDNS zone.  |

### MachineAccountQuota Parameters

|Parameter  | Description |
|----------------|----------------|   
|Container   |        AD container.  |
|MachineAccount  |    Machine account name.  |
|MachinePassword  |   Machine account password.  |
|Random     |         Create a machine account with a random password.  |

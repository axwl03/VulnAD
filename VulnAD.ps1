#requires -version 2

function New-Forest {
<#
.SYNOPSIS

Install a new AD forest with supplied domain name.

.DESCRIPTION

This function installs a new AD forest with supplied domain name. Administrator access is required.

.PARAMETER Domain

The domain name for the AD forest.

.PARAMETER SafeModeAdministratorPassword

The plaintext password for SafeModeAdministratorPassword.

.EXAMPLE

New-Forest -Domain victim.com -SafeModeAdministratorPassword "P@ssw0rd"

Install a new AD forest "victim.com".

#>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $SafeModeAdministratorPassword
    )
    Install-WindowsFeature -name AD-Domain-Services -IncludeManagementTools

    $SecurePassword = ConvertTo-SecureString -AsPlainText -Force $SafeModeAdministratorPassword
    Install-ADDSForest `
        -DomainName $Domain `
        -InstallDns `
        -DomainMode WinThreshold `
        -ForestMode WinThreshold `
        -SafeModeAdministratorPassword $SecurePassword `
        -Force `
        -NoRebootOnCompletion
}

function New-Domain {
<#
.SYNOPSIS

Install a new AD domain and add it to the specified parent domain with supplied domain name.

.DESCRIPTION

This function installs a new AD domain with supplied domain name. It also join current domain 
to the specified parent domain. Parent domain administrator access is required.

.PARAMETER Domain

The domain name for the newly created AD domain (without parent domain followed).

.PARAMETER ParentDomain

The parent domain name to join.

.PARAMETER SafeModeAdministratorPassword

The plaintext password for SafeModeAdministratorPassword.

.PARAMETER ParentDomainAdminUsername

The username for parent domain admin.

.PARAMETER ParentDomainAdminPassword

The plaintext password for parent domain admin.

.EXAMPLE

New-Domain -Domain taipei -ParentDomain victim.com -SafeModeAdministratorPassword "P@ssw0rd" -ParentDomainAdminUsername "VICTIM\Administrator" -ParentDomainAdminPassword "~ADTest"

Install a AD domain "taipei.victim.com" and join the parent domain "victim.com".

#>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ParentDomain,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $SafeModeAdministratorPassword,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ParentDomainAdminUsername,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ParentDomainAdminPassword
    )
    Install-windowsfeature -name AD-Domain-Services -IncludeManagementTools

    $SecurePassword = ConvertTo-SecureString -AsPlainText -Force $ParentDomainAdminPassword
    $Credential = New-Object System.Management.Automation.PSCredential -ArgumentList $ParentDomainAdminUsername, $SecurePassword
    $SecurePassword = ConvertTo-SecureString -AsPlainText -Force $SafeModeAdministratorPassword
    Install-AddsDomain `
        -ParentDomainName $ParentDomain `
        -NewDomainName $Domain `
        -InstallDNS `
        -CreateDNSDelegation `
        -SafeModeAdministratorPassword $SecurePassword `
        -Credential $Credential `
        -Force `
        -NoRebootOnCompletion
}

function Set-Network {
<#
.SYNOPSIS

Set IP address and DNS server for a specified interface.

.DESCRIPTION

This function is a simple wrapper which set an IP address and DNS server
for the specified interface index.

.PARAMETER IP

The IP address for the computer.

.PARAMETER DNSServers

The IP address list of the DNS servers.

.PARAMETER IfIndex

The index of the network adapter (listing adapters with Get-NetAdapter).

.EXAMPLE

Set-Network -IP 10.0.1.1 -DNSServers 8.8.8.8

Set IP address to 10.0.1.1 and set DNS server to 8.8.8.8 for the first network adapter.

#>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $IP,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $DNSServers,

        [ValidateNotNull()]
        [Uint32]
        $IfIndex = ((Get-NetAdapter).ifIndex | Select-Object -First 1)
    )
    if (Get-NetIPAddress | ?{$_.InterfaceIndex -eq $IfIndex}) {
        Remove-NetIPAddress -IfIndex $IfIndex -Confirm:$false
    }
    New-NetIPAddress -InterfaceIndex $IfIndex -IPAddress $IP -PrefixLength 24
    Set-DnsClientServerAddress -InterfaceIndex $IfIndex -ServerAddresses $DNSServers
}

function Create-UserFromJson {
<#
.SYNOPSIS

Create users listed in a json file.

.DESCRIPTION

This function creates users listed in a json file.
The json file contains a object array. Each object must contains "Username" and "Password" field.

.PARAMETER Path

The file path of the json file.

.EXAMPLE

Create-UserFromJson -Path .\credentials.json

Create user from credentials.json.

#>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Path
    )
    $Content = Get-Content $Path
    $Users = $Content | ConvertFrom-Json
    ForEach ($User in $Users) {
        $Username = $User.Username
        $Password = $User.Password
        if (Get-ADUser -Filter {SamAccountName -eq $Username}) {
            Write-Warning "The user '$Username' already exists"
        } Else {
            $SecurePassword = ConvertTo-SecureString $Password -Force -AsPlainText
            New-ADUser -Name $Username -AccountPassword $SecurePassword -PasswordNeverExpires $true -Enabled $true
        }
    }
}

function Set-Kerberoasting {
<#
.SYNOPSIS

Make an user kerberoastable.

.DESCRIPTION

This function adds a SPN for the specified user.
In order to kerberoast the user, you should make sure the specified user's password is crackable.

.PARAMETER User

The user that you want to be kerberoastable.

.PARAMETER SPN

Service Principal Name that is added to the specified user.

.EXAMPLE

Set-Kerberoasting -User Luffy -SPN "roast/ws01.victim.com"

Add a SPN for user Luffy (who uses weak password) so that he is kerberoastable.

#>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $User,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $SPN
    )
    Set-ADUser -Identity $User -ServicePrincipalNames @{Add=$SPN}
}

function Set-ASREPRoasting {
<#
.SYNOPSIS

Make an user AS-REPRoastable.

.DESCRIPTION

This function sets the "DoesNotRequirePreAuth" attribute for the specified user.
In order to AS-REP roast the user, you should make sure the specified user's password is crackable.

.PARAMETER User

The user that you want to be AS-REPRoastable

.EXAMPLE

Set-ASREPRoasting -User Luffy

Make user Luffy AS-REPRoastable.

#>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $User
    )
    Set-ADAccountControl -Identity Luffy -DoesNotRequirePreAuth $true
}

function Set-UnconstainedDelegation {
<#
.SYNOPSIS

Configure unconstrained delegation for the specified account.

.DESCRIPTION

This function sets the "TrustedForDelegation" attribute for the specified account,
which allows this account to perform unconstrained delegation.

.PARAMETER Identity

The account whose "TrustedForDelegation" to be set.

.EXAMPLE

Set-UnconstrainedDelegation -Identity ws02

Allow ws02 to perform unconstrained delegation.

#>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Identity
    )
    Set-ADAccountControl -Identity $Identity -TrustedForDelegation $true
}

function Set-ConstrainedDelegation {
<#
.SYNOPSIS

Configure constrained delegation for the specified account.

.DESCRIPTION

This function sets "TrustedToAuthForDelegation" attribute for the specified account and
add a SPN to "msDs-AllowedToDelegateTo" attribute.

.PARAMETER Identity

The account whose "TrustedToAuthForDelegation" and "msDs-AllowedToDelegateTo" to be set.

.PARAMETER AllowedSPN

The allowed SPN for "msDs-AllowedToDelegateTo".

.EXAMPLE

Set-ConstrainedDelegation -Identity ws02 -AllowedSPN "HOST/ws01"

Allow ws02 to perform constrained delegation on "HOST/ws01".

#>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Identity,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $AllowedSPN
    )
    Set-ADAccountControl -Identity $Identity -TrustedToAuthForDelegation $true
    Set-ADComputer -Identity $Identity -Add @{'msDS-AllowedToDelegateTo'=@($AllowedSPN)}
}

function Set-RBCD {
<#
.SYNOPSIS

Configure resource-based constrained delegation for the specified account.

.DESCRIPTION

This function sets the "msDS-AllowedToActOnBehalfOfOtherIdentity" attribute for the specified account 
which allows the allowed account to perform resource-based constrained delegation.

.PARAMETER Identity

The account whose "msDS-AllowedToActOnBehalfOfOtherIdentity" to be set.

.PARAMETER AllowedIdentity

The allowed identity for "msDS-AllowedToActOnBehalfOfOtherIdentity".

.PARAMETER UserType

Specify that the identity is an user object.

.EXAMPLE

Set-RBCD -Identity ws02 -AllowedIdentity ws03

Allow ws03 to perform resource-based constrained delegation to ws02.

#>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Identity,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $AllowedIdentity,

        [Parameter()]
        [Switch]
        $UserType
    )
    if ($UserType.IsPresent) {
        Set-ADComputer -Identity $Identity -PrincipalsAllowedToDelegateToAccount $AllowedIdentity
    } else {
        Set-ADUser -Identity $Identity -PrincipalsAllowedToDelegateToAccount $AllowedIdentity
    }
}

function Add-WritePermissionToUser {
<#
.SYNOPSIS

Add write permission of an object to the specified user, which can be abused to
create RBCD.

.DESCRIPTION

This function adds a GenericWrite permission of an object to the specified user.

.PARAMETER DistinguishedName

The object whose write permission to be given.

.PARAMETER User

The user who is to be given the write permission.

.EXAMPLE

Add-WritePermissionToUser -DistinguishedName "CN=WS02,CN=Computers,DC=taipei,DC=victim,DC=com" -User Sanji

Add write permission of ws02 to user Sanji.

#>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $DistinguishedName,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $User
    )
    $path = 'AD:\' + $DistinguishedName
    $acl = Get-Acl -Path $path
    $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule (New-Object System.Security.Principal.NTAccount $User),"GenericWrite","Allow"
    $acl.AddAccessRule($ace)
    Set-Acl -Path $path -AclObject $acl
}
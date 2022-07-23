#requires -version 2

function New-Forest {
<#
.SYNOPSIS

Install a new AD forest with supplied domain name.

.DESCRIPTION

This function installs a new AD forest with supplied domain name. Administrator access is required.

.PARAMETER Domain

The domain name for the AD forest.

.PARAMETER PlaintextPassword

The plaintext password for SafeModeAdministratorPassword.

.EXAMPLE

New-Forest -Domain victim.com -PlaintextPassword "P@ssw0rd"

Install a new AD forest "victim.com" with password "P@ssw0rd".

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
        $PlaintextPassword
    )
    Install-WindowsFeature -name AD-Domain-Services -IncludeManagementTools

    $SecurePassword = ConvertTo-SecureString -AsPlainText -Force $PlaintextPassword
    Install-ADDSForest `
        -DomainName $Domain `
        -InstallDns `
        -DomainMode WinThreshold `
        -ForestMode WinThreshold `
        -SafeModeAdministratorPassword $SecurePassword `
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


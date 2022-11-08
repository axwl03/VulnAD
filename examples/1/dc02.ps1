$IP = "10.0.1.2"
$Hostname = "dc02"
$ParentDomain = "victim.com"
$ParentDCIP = "10.0.1.1"
$Domain = "taipei"
$ParentDomainAdminUsername = "VICTIM\Administrator"
$ParentDomainAdminPassword = "~ADTest" # TODO: modify this
$SafeModeAdministratorPassword = "P@ssw0rd"
$UserJsonFile = "credentials.json"
$ProgressFile = "progress.txt"
$Progress = 0

$ErrorActionPreference = "Stop"
. ..\..\VulnAD.ps1

if (Test-Path $ProgressFile) {
    $Progress = [Int](Get-Content $ProgressFile)
}
Switch ($Progress) {
    {$_ -le 0} {
        Set-Network -IP $IP -DNSServers $ParentDCIP
        Rename-Computer -NewName $Hostname -Force
        Write-Output 1 > $ProgressFile
        Restart-Computer
    }
    {$_ -le 1} {
        New-Domain -Domain $Domain -ParentDomain $ParentDomain -SafeModeAdministratorPassword $SafeModeAdministratorPassword -ParentDomainAdminUsername $ParentDomainAdminUsername -ParentDomainAdminPassword $ParentDomainAdminPassword
        Write-Output 2 > $ProgressFile
        Restart-Computer
    }
    {$_ -le 2} {
        Try {
            Get-ADComputer -Identity ws01 | Out-Null
            Get-ADComputer -Identity ws02 | Out-Null
        }
        Catch {
            Write-Output "Please complete the installation of ws01 and ws02 first."
            exit
        }
        Create-UserFromJson -Path $UserJsonFile
        Set-ASREPRoasting -User Usopp
        Set-Kerberoasting -User Chopper -SPN "roast/ws02.victim.com"
        net group "Domain Admins" Luffy /add /Domain
        Add-WritePermissionToUser -DistinguishedName "CN=WS02,CN=Computers,DC=taipei,DC=victim,DC=com" -User Sanji
        Set-UnconstainedDelegation -Identity ws01$
        Set-ConstrainedDelegation -Identity ws02$ -AllowedSPN 'CIFS/ws01'
        Invoke-Command -ComputerName ws02 -ScriptBlock {net localgroup administrators TAIPEI\Chopper /add}
        Write-Output 3 > $ProgressFile
    }
    {$_ -le 3} {
        Write-Output "Installation Success"
    }
}

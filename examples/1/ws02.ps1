$IP = "10.0.1.12"
$DCIP = "10.0.1.2"
$Hostname = "ws02"
$Domain = "taipei.victim.com"
$DomainAdminUsername = "Administrator"
$DomainAdminPassword = "~ADTest" # TODO: Modify this
$ProgressFile = "progress.txt"
$Progress = 0

$ErrorActionPreference = "Stop"
. ..\..\VulnAD.ps1

if (Test-Path $ProgressFile) {
    $Progress = [Int](Get-Content $ProgressFile)
}
Switch ($Progress) {
    {$_ -le 0} {
        Set-Network -IP $IP -DNSServers $DCIP
        Rename-Computer -NewName $Hostname -Force
        Write-Output 1 > $ProgressFile
        Restart-Computer
    }
    {$_ -le 1} {
        $SecurePassword = ConvertTo-SecureString -AsPlainText -Force $DomainAdminPassword
        $Credential = New-Object System.Management.Automation.PSCredential -ArgumentList $DomainAdminUsername, $SecurePassword
        Add-Computer -DomainName $Domain -Credential $Credential -Force
        Write-Output 2 > $ProgressFile
        Restart-Computer
    }
    {$_ -le 2} {
        Enable-PSRemoting
        winrm quickconfig
        Set-NetFirewallRule -DisplayGroup "Network Discovery" -Profile "Any" -Enabled true
        Set-NetFirewallRule -DisplayGroup "File and Printer Sharing" -Profile "Any" -Enabled true
        Set-NetFirewallRule -DisplayGroup "Remote Scheduled Tasks Management" -Profile "Any" -Enabled true
        Write-Output 3 > $ProgressFile
    }
    {$_ -le 3} {
        Write-Output "Installation Success"
    }
}

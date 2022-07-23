$IP = "10.0.1.1"
$Hostname = "dc01"
$Domain = "victim.com"
$Password = "P@ssw0rd"
$ProgressFile = "progress.txt"
$Progress = 0

$ErrorActionPreference = "Stop"
. ..\..\VulnAD.ps1

if (Test-Path $ProgressFile) {
    $Progress = [Int](Get-Content $ProgressFile)
}
Switch ($Progress) {
    {$_ -le 0} {
        Set-Network -IP $IP -DNSServers $IP
        Rename-Computer -NewName $Hostname -Force
        Write-Output 1 > $ProgressFile
        Restart-Computer
    }
    {$_ -le 1} {
        New-Forest -Domain $Domain -SafeModeAdministratorPassword $Password
        Write-Output 2 > $ProgressFile
        Restart-Computer
    }
    {$_ -le 2} {
        Write-Output "Installation Success"
    }
}
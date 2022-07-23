# Example 1

This example allows users to practice most of the AD attacks including forest privesc and delegation.
It requires 4 VMs in the same LAN. Each VM has a static IP.

## Prerequisites

Operating Systems:

- `dc01`: Windows Server
- `dc02`: Windows Server
- `ws01`: Windows 10
- `ws02`: Windows 10

Windows Server 2022 and Windows 10 21H2 are tested.
For Windows 10 machines, please run an elevated shell and execute `Set-ExecutionPolicy Unrestricted Force` 
in order to execute script.

## Installation

Please make sure the installation order:

1. `dc01`
2. `dc02`: complete stage 0 and 1 (follow the instructions while installing)
3. `ws01`
4. `ws02`
5. `dc02`

To install it, clone this repo to each machine and modify the TODOs in the script.
cd into `examples/1` and execute the corresponding script in an elevated shell.
For example, execute dc01.ps1 on the VM that you want it to become `dc01`:
```powershell
.\dc01.ps1
```
These scripts require you to run several times. Make sure to run it again after each reboot.
The installation is completed when it outputs "Installation Success".

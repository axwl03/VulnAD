# VulnAD

VulnAD consists of easy PowerShell scripts for building vulnerable ActiveDirectory environment for pentesting.

## Getting Started

Each example under `examples/` is a scenario of a vulnerable AD environment.
To setup the environment, install the VMs which are described in the README.md and run the corresponding script.
Take example 1 as an example, the steps are:

1. Install the VMs which is described in `examples/1/README.md`
2. Clone this repo to everyone VM
3. Execute the corresponding script on each VM, e.g. install `examples/1/dc01.ps1` on the VM that you want it to be `dc01`.
4. Attack it!

Also, a script might reboot several times and require you to manually run it again.
The script will display "Installation Success" once you complete installing it.
The installation order for the VMs is important. e.g. You cannot join a computer to the domain that hasn't configured yet, right?
Please read the corresponding README.md carefully.

## Attacks

You can practice/experiment the following techniques in the example lab:

- Lateral Movement
- Credential Dumping
- Pass the Hash
- Pass the Ticket
- Over Pass the Hash
- Kerberoasting
- AS-REP Roasting
- Unconstrained Delegation
- Constrained Delegation
- Resource-Based Constrained Delegation
- Golden Ticket
- Silver Ticket
- DCSync
- Skeleton Key Attack
- DSRM Abuse
- Custom SSP
- ACLs Abuse
- SID History Attack
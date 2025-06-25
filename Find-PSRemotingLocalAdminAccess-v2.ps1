# -----------------------------------------------------------------------------
# FIND-PSREMOTINGLOCALADMINACCESS-V2: PowerShell Remoting Local Admin Access Checker
#
# Author: Original by samratashok/nishang, Updated by x7331 (06/2025)
# Version: 2.0
#
# Description:
#   Checks if the current user has local administrative access on target machines
#   by attempting PowerShell Remoting commands. Success indicates local admin privileges.
#   Supports single hosts, host lists, or automatic domain enumeration.
#
# Usage:
#   .\Find-PSRemotingLocalAdminAccess-v2.ps1 [OPTIONS]
#
#   PARAMETERS:
#     -ComputerName <string>     Single target computer name
#     -ComputerFile <string>     File containing list of target computers
#     -StopOnSuccess             Stop scanning after first successful access
#     -Verbose                   Enable verbose output
#     -Debug                     Enable debug output
#
#   EXAMPLES:
#     .\Find-PSRemotingLocalAdminAccess-v2.ps1 -ComputerName "DC01" -Verbose
#     .\Find-PSRemotingLocalAdminAccess-v2.ps1 -ComputerFile "computers.txt" -StopOnSuccess
#     .\Find-PSRemotingLocalAdminAccess-v2.ps1 -Verbose  # Scan all domain computers
#
#   REQUIREMENTS:
#     - PowerShell 3.0 or higher
#     - PowerShell Remoting enabled on target machines
#     - Domain user account (for automatic enumeration)
#     - Network connectivity to target hosts
# -----------------------------------------------------------------------------

function Find-PSRemotingLocalAdminAccess-v2 
{
<#
.SYNOPSIS
    Check for local administrative access on target machines using PowerShell Remoting.

.DESCRIPTION
    This function attempts to run PowerShell Remoting commands against specified computers.
    Since PSRemoting requires local administrative privileges by default, successful
    execution indicates the current user has local admin access on the target machine.

.PARAMETER ComputerName
    Single target computer name to test.

.PARAMETER ComputerFile
    Path to file containing list of target computers (one per line).

.PARAMETER StopOnSuccess
    Stop scanning after finding the first successful access.

.EXAMPLE
    Find-PSRemotingLocalAdminAccess-v2 -ComputerName "DC01" -Verbose

.EXAMPLE
    Find-PSRemotingLocalAdminAccess-v2 -ComputerFile "C:\targets\computers.txt" -StopOnSuccess

.EXAMPLE
    Find-PSRemotingLocalAdminAccess-v2 -Verbose  # Scan all domain computers

.LINK
    https://github.com/samratashok/nishang
    http://www.labofapenetrationtester.com/

.NOTES
    Updated by x7331 (06/2025) - Fixed typos, improved error handling, added comments
#>

    [CmdletBinding()] Param(
        [Parameter(Mandatory=$False, Position=0, ValueFromPipeline=$true)]
        [String]
        $ComputerName,

        [Parameter(Mandatory=$False, Position=1, ValueFromPipeline=$true)]
        [String]
        $ComputerFile,

        [Parameter()]
        [Switch]
        $StopOnSuccess
    )

    # Set error action preference to silently continue to handle errors manually
    $ErrorActionPreference = "SilentlyContinue"
    
    Write-Verbose "Starting PowerShell Remoting local admin access check..."
    
    # Determine the list of computers to test
    if ($ComputerFile) {
        # Read computer list from file
        Write-Verbose "Reading computer list from file: $ComputerFile"
        if (Test-Path $ComputerFile) {
            $Computers = Get-Content $ComputerFile
            Write-Verbose "Loaded $($Computers.Count) computers from file"
        } else {
            Write-Error "Computer file not found: $ComputerFile"
            return
        }
    }
    elseif ($ComputerName) {
        # Use single computer name
        Write-Verbose "Testing single computer: $ComputerName"
        $Computers = @($ComputerName)
    }
    else {
        # Automatically enumerate all domain computers
        Write-Verbose "No computer specified, enumerating all domain computers..."
        try {
            $objSearcher = New-Object System.DirectoryServices.DirectorySearcher
            $objSearcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry
            $objSearcher.Filter = "(&(sAMAccountType=805306369))"
            $Computers = $objSearcher.FindAll() | ForEach-Object {$_.properties.dnshostname}
            Write-Verbose "Found $($Computers.Count) computers in domain"
        }
        catch {
            Write-Error "Failed to enumerate domain computers: $($_.Exception.Message)"
            return
        }
    }

    # Initialize counter for successful accesses
    $successCount = 0
    
    # Test each computer for local admin access using PowerShell Remoting
    foreach ($Computer in $Computers) {
        Write-Verbose "Testing PSRemoting access on: $Computer"
        
        # Clear previous error state
        $Error.Clear()
        
        # Attempt PowerShell Remoting command to test local admin access
        # Using a simple hostname command that requires admin privileges
        Write-Verbose "Attempting to run hostname command via PSRemoting on $Computer"
        $result = Invoke-Command -ScriptBlock {hostname} -ComputerName $Computer -ErrorAction SilentlyContinue
        
        # Get the first error (if any) for analysis
        $ourError = $Error[0]
        
        # Check if the PSRemoting command was successful
        if ($ourError -eq $null) {
            # No error means successful PSRemoting access - user has local admin privileges
            $successCount++
            Write-Host "SUCCESS: Local admin access confirmed on: $Computer" -ForegroundColor Green
            
            # Stop scanning if requested
            if ($StopOnSuccess) {
                Write-Verbose "StopOnSuccess flag set, stopping scan after first success"
                break
            }
        } 
        elseif (-not $ourError.Exception.Message.Contains("Access is denied.")) {
            # Error occurred but it's not an access denied error
            # This could be network issues, PSRemoting not enabled, host unreachable, etc.
            Write-Warning "Non-access error on $Computer`: $($ourError.Exception.Message)"
        } 
        else {
            # Access denied error - user does not have local admin privileges
            Write-Debug "Access denied on $Computer`: $($ourError.Exception.Message)"
        }
    }
    
    # Summary report
    Write-Verbose "Scan completed. Found $successCount computer(s) with local admin access."
    if ($successCount -gt 0) {
        Write-Host "SUMMARY: Local admin access found on $successCount computer(s)" -ForegroundColor Green
    } else {
        Write-Host "SUMMARY: No local admin access found on any tested computers" -ForegroundColor Yellow
    }
} 
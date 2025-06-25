# -----------------------------------------------------------------------------
# FIND-WMILOCALADMINACCESS-V2: WMI Local Admin Access Checker
#
# Author: Original by samratashok/nishang, Updated by x7331 (06/2025)
# Version: 2.0
#
# Description:
#   Checks if the current user has local administrative access on target machines
#   by attempting WMI queries. Success indicates local admin privileges.
#   Supports single hosts, host lists, or automatic domain enumeration.
#
# Usage:
#   .\Find-WMILocalAdminAccess-v2.ps1 [OPTIONS]
#
#   PARAMETERS:
#     -ComputerName <string>     Single target computer name
#     -ComputerFile <string>     File containing list of target computers
#     -StopOnSuccess             Stop scanning after first successful access
#     -Verbose                   Enable verbose output
#     -Debug                     Enable debug output
#
#   EXAMPLES:
#     .\Find-WMILocalAdminAccess-v2.ps1 -ComputerName "DC01" -Verbose
#     .\Find-WMILocalAdminAccess-v2.ps1 -ComputerFile "computers.txt" -StopOnSuccess
#     .\Find-WMILocalAdminAccess-v2.ps1 -Verbose  # Scan all domain computers
#
#   REQUIREMENTS:
#     - PowerShell 3.0 or higher
#     - Domain user account (for automatic enumeration)
#     - Network connectivity to target hosts
# -----------------------------------------------------------------------------

function Find-WMILocalAdminAccess-v2 
{
<#
.SYNOPSIS
    Check for local administrative access on target machines using WMI queries.

.DESCRIPTION
    This function attempts to run WMI commands against specified computers. Since WMI
    requires local administrative privileges by default, successful execution indicates
    the current user has local admin access on the target machine.

.PARAMETER ComputerName
    Single target computer name to test.

.PARAMETER ComputerFile
    Path to file containing list of target computers (one per line).

.PARAMETER StopOnSuccess
    Stop scanning after finding the first successful access.

.EXAMPLE
    Find-WMILocalAdminAccess-v2 -ComputerName "DC01" -Verbose

.EXAMPLE
    Find-WMILocalAdminAccess-v2 -ComputerFile "C:\targets\computers.txt" -StopOnSuccess

.EXAMPLE
    Find-WMILocalAdminAccess-v2 -Verbose  # Scan all domain computers

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
    
    Write-Verbose "Starting WMI local admin access check..."
    
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
    
    # Test each computer for local admin access
    foreach ($Computer in $Computers) {
        Write-Verbose "Testing WMI access on: $Computer"
        
        # Clear previous error state
        $Error.Clear()
        
        # Attempt WMI query to test local admin access
        # Win32_OperatingSystem is a common WMI class that requires admin privileges
        $result = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $Computer -ErrorAction SilentlyContinue 
        
        # Get the first error (if any) for analysis
        $ourError = $Error[0]
        
        # Check if the WMI query was successful
        if ($ourError -eq $null) {
            # No error means successful WMI access - user has local admin privileges
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
            # This could be network issues, host unreachable, etc.
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
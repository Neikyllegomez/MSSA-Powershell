# Import necessary modules
Import-Module ActiveDirectory

# Define reusable variables
$Today = Get-Date
$Yesterday = $Today.AddDays(-1)
$30DaysAgo = $Today.AddDays(-30)
$60DaysAgo = $Today.AddDays(-60)

# Bulk Create Users
function Create-BulkUsers {
    Import-Csv -Path "users.csv" | ForEach-Object {
        New-ADUser -Name $_.Name -GivenName $_.FirstName -Surname $_.LastName `
        -SamAccountName $_.Username -UserPrincipalName "$($_.Username)@yourdomain.com" `
        -Path "OU=Users,DC=yourdomain,DC=com" -AccountPassword (ConvertTo-SecureString "P@ssw0rd!" -AsPlainText -Force) -Enabled $true
    }
}

# Enumerate Expired User Accounts
function Get-ExpiredAccounts {
    Search-ADAccount -AccountExpired | Select-Object Name, SamAccountName, LastLogonDate
}

# Enumerate User Accounts Expired in Last 24 Hours
function Get-RecentExpiredAccounts {
    Search-ADAccount -AccountExpired | Where-Object { $_.AccountExpirationDate -gt $Yesterday }
}

# Locate and Unlock Specific User Account
function Unlock-UserAccount {
    param([string]$SamAccountName)
    Unlock-ADAccount -Identity $SamAccountName
}

# Retrieve All Locked Accounts
function Get-LockedAccounts {
    Search-ADAccount -LockedOut | Select-Object Name, SamAccountName
}

# Disable Accounts Unused for 30+ Days
function Disable-InactiveAccounts {
    Search-ADAccount -AccountInactive -TimeSpan 30.00:00:00 | ForEach-Object {
        Disable-ADAccount -Identity $_.SamAccountName
    }
}

# Move Disabled Users to Specific OU
function Move-DisabledAccounts {
    Search-ADAccount -AccountDisabled | ForEach-Object {
        Move-ADObject -Identity $_.DistinguishedName -TargetPath "OU=DisabledUsers,DC=yourdomain,DC=com"
    }
}

# Remove Disabled Users from All Groups Except Domain Users
function Clean-DisabledAccountsGroups {
    Search-ADAccount -AccountDisabled | ForEach-Object {
        $Groups = Get-ADUser $_.SamAccountName -Property MemberOf | Select-Object -ExpandProperty MemberOf
        $Groups | Where-Object { $_ -ne "CN=Domain Users,CN=Users,DC=yourdomain,DC=com" } | ForEach-Object {
            Remove-ADGroupMember -Identity $_ -Members $_.SamAccountName -Confirm:$false
        }
    }
}

# Add Users into Groups
function Add-UsersToGroup {
    param([string]$GroupName, [string[]]$UserNames)
    Add-ADGroupMember -Identity $GroupName -Members $UserNames
}

# Create Organizational Units (OUs)
function Create-OU {
    param([string]$OUName)
    New-ADOrganizationalUnit -Name $OUName -Path "DC=yourdomain,DC=com"
}

# Create Groups
function Create-Group {
    param([string]$GroupName)
    New-ADGroup -Name $GroupName -GroupScope Global -GroupCategory Security -Path "OU=Groups,DC=yourdomain,DC=com"
}

# List Computers with Specific OS
function Get-ComputersByOS {
    param([string]$OS)
    Get-ADComputer -Filter "OperatingSystem -like '*$OS*'" | Select-Object Name, OperatingSystem
}

# List Computers Not Logged In Within 30 Days
function Get-InactiveComputers {
    Get-ADComputer -Filter * -Property LastLogonDate | Where-Object { $_.LastLogonDate -lt $30DaysAgo }
}

# Automatically Remove Items from Downloads 60+ Days Old
function Clean-Downloads {
    Get-ChildItem -Path "C:\Users\*\Downloads" -Recurse | Where-Object { $_.LastWriteTime -lt $60DaysAgo } | Remove-Item -Force
}

# Remote Restart Computer
function Restart-RemoteComputer {
    param([string]$ComputerName)
    Restart-Computer -ComputerName $ComputerName -Force
}

# Retrieve Disk Size and Free Space
function Get-DiskSpace {
    param([string]$ComputerName)
    Get-WmiObject -Class Win32_LogicalDisk -ComputerName $ComputerName | Select-Object DeviceID, @{Name="Size(GB)";Expression={[math]::Round($_.Size / 1GB, 2)}}, @{Name="FreeSpace(GB)";Expression={[math]::Round($_.FreeSpace / 1GB, 2)}}
}

# Stop and Start Process on Remote Host
function Manage-RemoteProcess {
    param([string]$ComputerName, [string]$ProcessName)
    Invoke-Command -ComputerName $ComputerName -ScriptBlock {
        Stop-Process -Name $using:ProcessName -Force
        Start-Process $using:ProcessName
    }
}

# Stop and Start Services on Remote Host
function Manage-RemoteService {
    param([string]$ComputerName, [string]$ServiceName)
    Invoke-Command -ComputerName $ComputerName -ScriptBlock {
        Stop-Service -Name $using:ServiceName
        Start-Service -Name $using:ServiceName
    }
}

# List Installed Printers
function Get-Printers {
    Get-Printer | Select-Object Name, DriverName
}

# List IP Address of Remote Host
function Get-RemoteIPAddress {
    param([string]$ComputerName)
    Test-Connection -ComputerName $ComputerName | Select-Object IPV4Address
}

# Retrieve Network Adapter Properties
function Get-NetworkAdapterProperties {
    param([string]$ComputerName)
    Get-NetAdapter -CimSession $ComputerName | Select-Object Name, Status, MacAddress, LinkSpeed
}

# Release and Renew DHCP Leases
function Renew-DHCP {
    Get-NetAdapter | ForEach-Object { Renew-DhcpLease -InterfaceAlias $_.Name }
}

# Create a Network Share
function Create-NetworkShare {
    param([string]$ShareName, [string]$Path, [string]$User)
    New-SmbShare -Name $ShareName -Path $Path -FullAccess $User
}

# Delete Temporary Files for All Users
function Clean-TempFiles {
    Get-ChildItem -Path "C:\Users\*\AppData\Local\Temp" -Recurse | Remove-Item -Force
}

# List Top 15 Largest Files on a Drive
function Get-LargestFiles {
    param([string]$Drive)
    Get-ChildItem -Path $Drive -Recurse | Sort-Object Length -Descending | Select-Object FullName, @{Name="Size(MB)";Expression={[math]::Round($_.Length / 1MB, 2)}} -First 15
}

# Create Restore Point
function Create-RestorePoint {
    param([string]$Description)
    Checkpoint-Computer -Description $Description -RestorePointType MODIFY_SETTINGS
}

# Run Internet Speed Test
function Run-SpeedTest {
    Invoke-WebRequest -Uri "https://www.speedtest.net/api/js/servers" | ConvertFrom-Json | Select-Object -First 1
}

# Disable USB Ports
function Disable-USBPorts {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR" -Name "Start" -Value 4
}

# Free Up Disk Space
function Free-DiskSpace {
    Invoke-Command -ComputerName "RemotePCName" -ScriptBlock {
        Remove-Item "C:\Windows\Temp\*" -Force -Recurse
        Remove-Item "C:\Users\*\AppData\Local\Temp\*" -Force -Recurse
        Clear-RecycleBin -Force
    }
}

# Example: Call any of the above functions
# Create-BulkUsers
# Get-ExpiredAccounts


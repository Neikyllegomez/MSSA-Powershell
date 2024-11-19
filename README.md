# MSSA-Powershell
MSSA Project
# Bulk Create Users
Import-Csv -Path "users.csv" | ForEach-Object {
    New-ADUser -Name $_.Name -GivenName $_.FirstName -Surname $_.LastName `
    -SamAccountName $_.Username -UserPrincipalName "$($_.Username)@yourdomain.com" `
    -Path "OU=Users,DC=yourdomain,DC=com" -AccountPassword (ConvertTo-SecureString "P@ssw0rd!" -AsPlainText -Force) -Enabled $true
}
Search-ADAccount -AccountExpired | Select-Object Name, SamAccountName, LastLogonDate
$Yesterday = (Get-Date).AddDays(-1)
Search-ADAccount -AccountExpired | Where-Object { $_.AccountExpirationDate -gt $Yesterday }
Unlock-ADAccount -Identity "SamAccountName"
Search-ADAccount -AccountInactive -TimeSpan 30.00:00:00 | ForEach-Object {
    Disable-ADAccount -Identity $_.SamAccountName
}
Search-ADAccount -AccountDisabled | ForEach-Object {
    $Groups = Get-ADUser $_.SamAccountName -Property MemberOf | Select-Object -ExpandProperty MemberOf
    $Groups | Where-Object { $_ -ne "CN=Domain Users,CN=Users,DC=yourdomain,DC=com" } | ForEach-Object {
        Remove-ADGroupMember -Identity $_ -Members $_.SamAccountName -Confirm:$false
    }
}
Add-ADGroupMember -Identity "GroupName" -Members "User1", "User2"

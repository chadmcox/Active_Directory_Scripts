# Get users with PasswordNotRequired

```
Get-ADUser -Filter {PasswordNotRequired -eq $true} -Properties PasswordNotRequired
```

# Get users with PasswordNotRequired another way
```
Get-ADUser -LDAPFilter "(&(userAccountControl:1.2.840.113556.1.4.803:=32)(!(IsCriticalSystemObject=TRUE)))"
```

# Change PasswordNotRequired on all users
```
Get-ADUser -Filter {PasswordNotRequired -eq $true} -Properties PasswordNotRequired | Set-ADUser -PasswordNotRequired $false
```

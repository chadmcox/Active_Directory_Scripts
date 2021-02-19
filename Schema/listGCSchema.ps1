Get-ADObject -SearchBase "cn=Schema,$((get-adrootdse).configurationNamingContext)" `
  -LDAPFilter "(isMemberOfPartialAttributeSet=TRUE)" -Properties lDAPDisplayName | sort lDAPDisplayName | select lDAPDisplayName

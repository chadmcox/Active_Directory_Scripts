#How many accounts created in the last 30 days
$create_date = $([DateTime]::Today.AddDays(-30))
get-aduser -Filter {whencreated -gt $create_date} -Properties whencreated | measure | select count


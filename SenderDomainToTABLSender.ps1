#Connect Exchange Powershell First https://learn.microsoft.com/en-us/powershell/exchange/connect-to-exchange-online-powershell?view=exchange-ps

$csv = Import-CSV 'YOUR PATH/joesandboxiocs+11-03-23.csv'

foreach($line in $csv){
    if ($line.IndicatorType -eq "DomainName"){
        $url = $line.IndicatorValue 
        New-TenantAllowBlockListItems -ListType Sender -Block -Entries $url -NoExpiration -Notes $line.Description
        }
}

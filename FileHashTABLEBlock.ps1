#Connect Exchange Powershell First https://learn.microsoft.com/en-us/powershell/exchange/connect-to-exchange-online-powershell?view=exchange-ps

$csv = Import-CSV 'C:\Users\YOUR PATH\joesandboxiocs+11-03-23.csv'

foreach($line in $csv){
    if ($line.IndicatorType -eq "FileSha256"){
        $hash = $line.IndicatorValue 
        New-TenantAllowBlockListItems -ListType FileHash -Block -Entries $hash -NoExpiration
        }
}

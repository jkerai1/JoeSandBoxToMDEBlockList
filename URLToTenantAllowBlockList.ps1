#Connect Exchange Powershell First https://learn.microsoft.com/en-us/powershell/exchange/connect-to-exchange-online-powershell?view=exchange-ps

$csv = Import-CSV 'C:\Users\YOURPATH\joesandboxiocs+11-03-23.csv'

foreach($line in $csv){
    if ($line.IndicatorType -eq "DomainName"){
        $url = $line.IndicatorValue + "/*"
        #$url.insert(0,"~") #adjust wildcards accordingly, see https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/tenant-allow-block-list-urls-configure?view=o365-worldwide#url-entry-scenarios
        New-TenantAllowBlockListItems -ListType Url -Block -Entries $url -NoExpiration -Notes $line.Description
        }
}

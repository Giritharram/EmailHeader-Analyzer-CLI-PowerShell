#insert your VT access token
$global:VT_token=''

#declaring variables to store extracted values from txt or eml file
$global:extracted_ip = @();
$global:extracted_domain = @();
$global:extracted_url = @();
#declaring variables to store extracted values from API calls
$global:malicious_ip = @();
$global:malicious_domain = @();
$global:malicious_url = @();

$global:Retrived_content = Get-Content .\Input\sample.txt

#function to extract IP 
function Extract_ip([REF]$f) {
    $temp_extracted_ip = @()
    foreach($line in $Retrived_content) {
        $IPregex='(?<Address>((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))'
        $temp_extracted_ip += ([regex]::Matches($line, $IPregex) | Foreach-Object { $_.Value })
    }
    foreach($i in $temp_extracted_ip | Select-Object -Unique){
        if($i -eq '127.0.0.1'){
            continue
        }
        $f.Value += $i
    }
    Write-Output $global:extracted_ip    
}

#function to extract Domain
function Extract_domain([REF]$f) {
    $temp_extracted_domain = @()
    foreach($line in $Retrived_content) {
        $Domainregex='\b((?=[a-z0-9-]{1,63}\.)(xn--)?[a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,63}\b'
        $temp_extracted_domain += ([regex]::Matches($line, $Domainregex) | Foreach-Object { $_.Value })
    }
    foreach($i in $temp_extracted_domain | Select-Object -Unique){
        $f.Value += $i
    }
    Write-Output $global:extracted_domain 
}

#function to extract URL 
function Extract_url([REF]$f) {
    $temp_extracted_URL = @()
    foreach($line in $Retrived_content) {
        $URLregex='https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)'
        $temp_extracted_URL += ([regex]::Matches($line, $URLregex) | Foreach-Object { $_.Value })
    }
        foreach($i in $temp_extracted_URL | Select-Object -Unique){
        $f.Value += $i
    }
    Write-Output $global:extracted_url
}

#function to find malicious IPs
function IP_VT_Info([REF]$f){ 
    foreach($ip in $f.Value){
        $obj = Get-VirusReport -ApiKey $global:VT_token -Search $ip
        if ($obj.data.attributes.last_analysis_stats.malicious -gt 0){
                $global:malicious_ip += $ip
            }
    }
    Write-Output $global:malicious_ip
}

#function to find malicious domain names
function Domain_VT_Info([REF]$f){ 
    foreach($domain in $f.Value){
        $obj = Get-VirusReport -ApiKey $global:VT_token -Search $domain
        if ($obj.data.attributes.last_analysis_stats.malicious -gt 0){
                $global:malicious_domain += $domain
            }
    }
    Write-Output $global:malicious_domain
}

#function to find malicious URLs
function URL_VT_Info([REF]$f){ 
    foreach($url in $f.Value){
        $obj = Get-VirusReport -ApiKey $global:VT_token -Search $url
        if ($obj.data.attributes.last_analysis_stats.malicious -gt 0){
                $global:malicious_url += $url
            }
    }
    Write-Output $global:malicious_url
}

#function to find passive DNS information for the extracted malicious IP
function PassiveDNS_VT_Info([REF]$f){ 
    foreach($ip in $f.Value){
        $response = Invoke-RestMethod "https://www.virustotal.com/vtapi/v2/ip-address/report?ip=$ip&apikey=$global:VT_token"
            
        if($response.resolutions.Object.Count -eq 0){
            continue
        }
        Write-Output `n"Info for $ip"
        Write-Host '***********************'
        $response.resolutions
    }
}

#function to find Whois information for the extracted malicious Domains
function whois_VT_info_for_domain([REF]$domains){
    foreach($domain in $domains.Value){
        $response = Invoke-RestMethod "http://www.virustotal.com/vtapi/v2/domain/report?domain=$domain&apikey=$global:VT_token"
        if($response.whois.Count -eq 0){
            continue
        }
        Write-Output `n"Whois info for $domain"
        Write-Host '*******************************'
        $response.whois
    }   
}

#function to find Whois information for the extracted malicious IPs
function whois_VT_info_for_ip([REF]$ips) {
    foreach($ip in $ips.Value){
        $headers=@{}
        $headers.Add("accept", "application/json")
        $headers.Add("x-apikey", "$global:VT_token")
        $response = Invoke-RestMethod -Uri "https://www.virustotal.com/api/v3/ip_addresses/$ip" -Method GET -Headers $headers
        if($response.data.attributes.whois.Count -eq 0){
            continue
        }
        Write-Output `n"Whois info for $ip"
        Write-Host '******************************'
        $response.data.attributes.whois
    }
}

#function to display IP address info
function Display_IP_Info{
    Write-Host `n'--------------'
    Write-Host 'IP address Info'
    Write-Host '--------------'`n
    Write-Host `n'Extracted IPs'
    Write-Host '--------------'
    Extract_ip ([REF]$global:extracted_ip)
    Write-Host `n'Malicious IPs'
    Write-Host '--------------'
    IP_VT_Info([REF]$global:extracted_ip)
    Write-Host `n
}

#function to display malicious Domain info
function Display_Domain_info {
    Write-Host `n'--------------'
    Write-Host 'Domain Info'
    Write-Host '--------------'`n
    Write-Host `n'Extracted Domains'
    Write-Host '--------------'
    Extract_domain([REF]$global:extracted_domain)
    Write-Host `n'Malicious Domains'
    Write-Host '--------------'
    Domain_VT_Info([REF]$global:extracted_domain)
    Write-Host `n
    
}

#function to display malicious URL info
function Display_URL_info {
    Write-Host `n'--------------'
    Write-Host 'URL Info'
    Write-Host '--------------'`n
    Write-Host `n'Extracted URLs'
    Write-Host '--------------'
    Extract_url([REF]$global:extracted_url)
    Write-Host `n'Malicious URLs'
    Write-Host '--------------'
    URL_VT_Info([REF]$global:extracted_url)
    Write-Host `n
    
}

#function to display PassiveDNS info for the mailicious IP
function Display_PassiveDns_info {
    Write-Host `n'--------------'
    Write-Host 'PassiveDNs Info'
    Write-Host '--------------'`n
    PassiveDNS_VT_Info([REF]$global:malicious_ip)
    Write-Host `n
}

#function to display whois info for the mailicious IP
function Whois_IP_info {
    Write-Host `n'--------------'
    Write-Host 'Whois Info for IP'
    Write-Host '--------------'`n
    whois_VT_info_for_ip([REF]$global:malicious_ip)
    Write-Host `n
}
#function to display whois info for the mailicious domain
function Whois_Domain_info {
    Write-Host `n'--------------'
    Write-Host 'Whois Info for Domain'
    Write-Host '--------------'`n
    whois_VT_info_for_domain([REF]$global:malicious_domain)
    Write-Host `n
}

#Declaring Varibles to store the extracted content
$global:sender_host = @();
$global:receiving_host = @();
$global:Protocol_Used = @();
$global:Dateof_host = @();
$global:time_difference = @();
#Variable to check and extract the summary headers
$global:summary_headers = @('^Message-ID:','^Subject:','^From:','^Reply-To:','^To:','^Date:');
#Variable to check and extract the standard headers
$global:standard_headers = @('^Accept-Language: ','^Approved: ','^ARC-Authentication-Results: ','^ARC-Message-Signature: ','^ARC-Seal: ','^Archive: ','^Archived-At: ','^Authentication-Results: ','^Auto-Submitted: ','^Bcc: ','^Body: ','^Cancel-Key: ','^Cancel-Lock: ','^Cc: ','^Comments: ','^Alternate-Recipient: ','^Autoforwarded: ','^Autosubmitted: ','^Content-Alternative: ','^Content-Description: ','^Content-Disposition: ','^Content-Duration: ','^Content-features: ','^Content-ID: ','^Content-Identifier: ','^Content-Language: ','^Content-Location: ','^Content-MD5: ','^Content-Return: ','^Content-Transfer-Encoding: ',
'^Content-Translation-Type: ','^Content-Type: ','^Control: ','^Conversion: ','^Conversion-With-Loss: ','^DL-Expansion-History: ','^Deferred-Delivery: ','^Delivery-Date: ','^Discarded-X400-IPMS-Extensions: ','^Discarded-X400-MTS-Extensions: ','^Disclose-Recipients: ','^Disposition-Notification-Options: ','^Disposition-Notification-To: ','^Distribution: ','^DKIM-Signature: ','^Downgraded-Final-Recipient: ','^Downgraded-In-Reply-To: ','^Downgraded-Message-Id: ','^Downgraded-Original-Recipient: ','^Downgraded-References: ','^Encoding: ','^Encrypted: ','^Expires: ','^Expiry-Date: ','^Followup-To: ','^Generate-Delivery-Report: ',
'^Importance: ','^In-Reply-To: ','^Incomplete-Copy: ','^Injection-Date: ','^Injection-Info: ','^Keywords: ','^Language: ','^Latest-Delivery-Time: ','^Lines: ','^List-Archive: ','^List-Help: ','^List-ID: ','^List-Owner: ','^List-Owner: ','^List-Subscribe: ','^List-Unsubscribe: ','^List-Unsubscribe-Post: ','^Message-Context: ','^Message-ID: ','^Message-Type: ','^MIME-Version: ','^MMHS-Exempted-Address: ','^MMHS-Extended-Authorisation-Info: ','^MMHS-Subject-Indicator-Codes: ','^MMHS-Handling-Instructions: ','^MMHS-Message-Instructions: ','^MMHS-Codress-Message-Indicator: ','^MMHS-Originator-Reference: ','^MMHS-Primary-Precedence: ','^MMHS-Copy-Precedence: ',
'^MMHS-Message-Type: ','^MMHS-Other-Recipients-Indicator-To: ','^MMHS-Other-Recipients-Indicator-CC: ','^MMHS-Acp127-Message-Identifier: ','^MMHS-Originator-PLAD: ','^MT-Priority: ','^Newsgroups: ','^Obsoletes: ','^Organization: ','^Original-Encoded-Information-Types: ','^Original-From: ','^Original-Message-ID: ','^Original-Recipient: ','^Original-Sender: ','^Originator-Return-Address: ','^Original-Subject: ','^Path: ','^PICS-Label: ','^Posting-Version: ','^Prevent-NonDelivery-Report: ','^Priority: ','^Received-SPF: ','^References: ','^Relay-Version: ','^Reply-By: ','^Require-Recipient-Valid-Since: ','^Resent-Bcc: ','^Resent-Cc: ','^Resent-Date: ','^Resent-From: ',
'^Resent-Message-ID: ','^Resent-Reply-To: ','^Resent-Sender: ','^Resent-To: ','^Return-Path: ','^Sender: ','^Sensitivity: ','^Solicitation: ','^Summary: ','^Supersedes: ','^TLS-Report-Domain: ','^TLS-Required: ','^TLS-Report-Submitter: ','^User-Agent: ','^VBR-Info: ','^VBR-Info: ','^X400-Content-Identifier: ','^X400-Content-Return: ','^X400-Content-Type: ','^X400-MTS-Identifier: ','^X400-Originator: ','^X400-Received: ','^X400-Recipients: ','^X400-Trace: ','^Xref: ');

#Variable to store the content
$global:file_var = Get-Content .\Input\sample.txt
$split_recv = [regex]::Escape('Received:')

try {
    $b = [regex]::Split($file_var, $split_recv) | Select-Object -Skip 1   
}
catch {
    Write-Host `n'Please have a content inside the file' -ForegroundColor Red `n
}

#Function to extract sender addresses
function senderhost_extract($b, [REF]$f){
    foreach($i in $b){
        $p = [regex]::Escape('by')
        $q = [regex]::Split($i, $p)
        $r = $q[0].replace('from','').replace(' ','')
        $f.Value+= @($r)
    }
}

#Function to extract receiver addresses
function receivinghost_extract($b, [REF]$f){
    foreach($i in $b){
        $p = [regex]::Escape('by')
        $q = [regex]::Split($i,$p)
        $r = [regex]::Escape('with')
        $t = [regex]::split($q[1],$r)
        if ($t[0].contains('id'))  {
            $t[0] = $t[0].Substring(0, $t[0].IndexOf('id'))
        }
        $f.Value += @($t[0].replace(' ',''))
    }
}

#Function to extract protocol used
function protocolused_extract($b, [REF]$f){
    foreach($i in $b){
        try {
            if ($i.Contains('with'))  {
                $p = [regex]::Escape('by')
                $q = [regex]::Split($i,$p)
                $r = [regex]::Escape('with')
                $t = [regex]::split($q[1],$r)
                if($i.Contains('id')){
                    $t[1] = $t[1].Substring(0, $t[1].IndexOf('id'))
                }
                if($i.Contains(';')){
                    $t[1] = $t[1].Substring(0, $t[1].IndexOf(';'))
                }
                $f.Value += @($t[1].replace(' ',''))
                }
            else{
                $f.Value += @('None')
            }
        }
        catch {
            $f.Value += @($t[1].replace(' ',''))
        }           
}
}

#Function to extract timestamp
function timestamp_extract($b, [REF]$f){
    foreach($i in $b){
        $p = [regex]::Escape('by')
        $q = [regex]::Split($i,$p)
        $r = [regex]::Escape(';')
        $t = [regex]::split($q[1],$r)
        $temp = $t[1].replace("`n","").replace("`r","").replace('  ',' ')
        $final = $temp -match '\w\w\w, ([0-9]|[0-9][0-9]) \w\w\w [0-9][0-9][0-9][0-9] [0-9][0-9]:[0-9][0-9]:[0-9][0-9] .[0-9][0-9][0-9][0-9]'
        if ($final -eq $False){
            $final = $temp -match '([0-9]|[0-9][0-9]) \w\w\w [0-9][0-9][0-9][0-9] [0-9][0-9]:[0-9][0-9]:[0-9][0-9] .[0-9][0-9][0-9][0-9]'
        }
        $f.Value += @($Matches[0])
    }
}

#Function to extract timedifference
function time_difference($b, [REF]$f){
    $count1 = 0
    $count2 = 0
    $count3 = 1
    foreach($i in $b){
        if($count1 -eq 0){
            $f.Value +=@('-')
            $count1 += 1 
            continue
        }
        $st = Get-Date $b[$count2]
        $fi = Get-Date $b[$count3]
        $final =  $fi - $st
        $f.Value +=@($final.TotalSeconds)
        $count2 += 1
        $count3 += 1
    }
}

#calling all the functions and reversing the order of the stored values 
senderhost_extract $b ([REF]$global:sender_host)
[array]::Reverse($global:sender_host)
receivinghost_extract $b ([REF]$global:receiving_host)
[array]::Reverse($global:receiving_host)
protocolused_extract $b([REF]$global:Protocol_Used)
[array]::Reverse($global:Protocol_Used)
timestamp_extract $b ([REF]$global:Dateof_host)
[array]::Reverse($global:Dateof_host)
time_difference $global:Dateof_host ([REF]$global:time_difference)


#function to transpose the values to print it in a certain format
function Transpose{
    param(
        [String[]]$Names,
        [Object[][]]$Data
    )
    for($i = 0;; ++$i){
        $Props = [ordered]@{}
        for($j = 0; $j -lt $Data.Length; ++$j){
            if($i -lt $Data[$j].Length){
                $Props.Add($Names[$j], $Data[$j][$i])
            }
        }
        if(!$Props.get_Count()){
            break
        }
        [PSCustomObject]$Props
    }
}

#Function to extract summary
function summary_extract {
    Write-Output Summary
    Write-Output ----------
    foreach($line in $file_var) {
        foreach($header in $global:summary_headers){
            if($line -match $header){
                Write-Output $line
            }
        }
    }
}

#Function to extract X headers
function Xheaders_extract {
    Write-Output Headers
    Write-Output ----------
    foreach($line in $file_var) {
        if($line -match "^X-"){
            Write-Output $line
        }
    }
}

#Function to extract Standard headers
function Standardheaders_extract {
    foreach($line in $file_var) {
        foreach($header in $global:standard_headers){
            if($line -match $header){
                Write-Output $line
            }
    }
}
}

#Function to print all the functions in a table format by calling the transpose function
function header_parsing {
    Transpose Sender-Host, Receving-Host, Protocol-Used, Time-Stamp, Lantency $global:sender_host, $global:receiving_host, $global:Protocol_Used, $global:Dateof_host, $global:time_difference | Format-Table
    summary_extract
    Write-Output `n
    Xheaders_extract
    Standardheaders_extract
}


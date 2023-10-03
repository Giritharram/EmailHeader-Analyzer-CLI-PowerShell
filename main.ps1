#Importing required files 
. .\OSINT_Feature.ps1
. .\Header_Parser.ps1

#Variable to check the allowed arguments and extensions
$global:argument_list = @('-h','-Eh','-Ipinfo','-Domaininfo','-URLinfo','-IPpassive','-PortScan','-Whois');
$global:allowed_extension = @('EML','TXT');

#calculating the number of arguments and storing the argument object in a variable
$global:len_of_arguments = $args.Count
$global:arguments = $args

#function to check the argument and display user instruction
function user_instruction {
    if(($len_of_arguments -lt 2 -or $arguments[1] -eq '-h') -and $arguments[1] -ne '-Eh'){
        Write-Host `n"****************************************************"
        Write-Host "                 How To Run:                       *"
        Write-Host "****************************************************"
        Write-Host '                                                   |'
        Write-Host ".\main.ps1 'eml or txt file' -argument             |"
        Write-Host '                                                   |'
        Write-Host '_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _|'
        Write-Host "`n"
        Write-Host "`n****************************************************"
        Write-Host "                  Arguments:                       *"
        Write-Host "****************************************************"
        Write-Host '                                                   | '
        Write-Host "      -h                -> Help                    |"
        Write-Host "      -Eh               -> Email header analysis   |"
        Write-Host "      -IPinfo           -> IP Information          |"            
        Write-Host "      -Domaininfo       -> Domain Information      |"
        Write-Host "      -URLinfo          -> URL Information         |"
        Write-Host '                                                   |'
        Write-Host '****************************************************'
        Write-Host " Try The Following After : -Domaininfo & -IPinfo   *"
        Write-Host '****************************************************'
        Write-Host '                                                   |'
        Write-Host "      -IPpassive        -> Passive DNS Information |"
        Write-Host "      -WhoisforIP       -> Whois for IP            |"
        Write-Host "      -WhoisforDomain   -> Whois for Domain        |" 
        Write-Host '_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _|'`n
    }
    if($arguments[1] -eq '-Eh'){
        header_parsing
    }
}

#function check allowed file extension
function allowed_file(){
    try {
        $extension = $arguments[0].Split('.')[-1].ToUpper()
    }
    catch {
        return 0
    }
    
    if($allowed_extension -contains $extension){
        #returns when 'Extension is allowed'
        return 1
    }
    else {
        #returns when 'Extension is not allowed'
        return 0
    }
}

function file_present(){
    $file_location = $PWD
    $file = $arguments[0]
    if(Test-Path -Path (Join-Path $file_location $file) -PathType Leaf){
        #returns when "File is in directory"
        return 1
    }
    else{
        #returns when "File is not in the directory"
        return 0
    }
}

function check_error{
    $Allowed_File_result = allowed_file 
    $File_Presence_result = file_present
    if($Allowed_File_result -eq 0){
        #returns when "The file type is not allowed"
        return 1
    }
    elseif($File_Presence_result -eq 0){
        #returns when "File named $($arguments[0]) is not present"
        return 0
    }
    if(($Allowed_File_result -and $File_Presence_result) -eq 1){
        #returns when "file type is allowed and the file is present" 
        return 2
    }

}

#function to check for any error and save the file
function save_file{
    $check_error = check_error
    if($check_error -eq 2){
    $src_path = $PWD.ToString()+'\'+$arguments[0]
    $dst_path = $PWD.ToString()+'\Input\sample.txt'
    Copy-Item $src_path $dst_path
    }
}

save_file

#function to check and call the functions according to the user's argument
function call_function_arguments {

    switch ($arguments[1]) {
        '-Eh' { 
            header_parsing
         }
         '-IPinfo'{
            Display_IP_Info
         }
         '-Domaininfo'{
            Display_Domain_info
         }
         '-URLinfo'{
            Display_URL_info
         }
    }
}

#Aggregating all the functions and calling them according to the user's argument
if ($MyInvocation.MyCommand.Path -eq $PSCommandPath) {
    user_instruction
    $check_error=check_error
    switch ($check_error) {
        0 {
            Write-Host "File named $($arguments[0]) is not present" -ForegroundColor Red `n
        }
        1 {
            Write-Host 'This file type is not allowed' -ForegroundColor Red `n
        }
        2 {
            while ($true) {
                Write-Host ""
                Write-Host "****************************************************"
                Write-Host "                  Arguments:                       *"
                Write-Host "****************************************************"
                Write-Host '                                                   |'
                Write-Host "      -h                -> Help                    |"
                Write-Host "      -Eh               -> Email header analysis   |"
                Write-Host "      -Ipinfo           -> IP Information          |"            
                Write-Host "      -Domaininfo       -> Domain Information      |"
                Write-Host "      -URLinfo          -> URL Information         |"
                Write-Host '                                                   |'
                Write-Host '****************************************************'
                Write-Host " Try The Following After : -Domaininfo & -IPinfo   *"
                Write-Host '****************************************************'
                Write-Host '                                                   |'
                Write-Host "      -IPpassive        -> Passive DNS Information |"
                Write-Host "      -WhoisforIP       -> Whois for IP            |"
                Write-Host "      -WhoisforDomain   -> Whois for Domain        |" 
                Write-Host '_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _|'
                Write-Host ""
            
                $user_input = Read-Host "Enter any of the above to know further Info or give exit"
                switch ($user_input) {
                    '-Eh' {
                        header_parsing
                    }
                    '-Ipinfo' {
                        Display_IP_Info
                    }
                    '-URLinfo' {
                        Display_URL_info
                    }
                    '-Domaininfo' {
                        Display_Domain_info
                    }
                    '-IPpassive' {
                        Display_PassiveDns_info
                    }
                    '-WhoisforIP' {
                        Whois_IP_info
                    }
                    '-WhoisforDomain' {
                        Whois_Domain_info
                    }
                }
                if($user_input -eq 'exit'){
                    break
                }
            }
        }
    }
}
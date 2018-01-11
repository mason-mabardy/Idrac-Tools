Function Set-iDRACPassword{
    <#
    .SYNOPSIS
    Set iDRAC password for rotations
    
    .DESCRIPTION
    Uses IP address, old password, new password, and plink to change password for one iDRAC
    
    .EXAMPLE
    Set-iDRACPassword -iDRACIP "10.10.10.12" -OldPassword $oldpass -NewPassword $newpass -UserName "root"
    Set-iDRACPassword -iDRACIP $idrac -OldPassword $oldpass -NewPassword $newpass
    NOTE: Function requires password parameters to be secure strings


    .PARAMETER iDRACIP
    IP address for individual iDRAC

    .Parameter OldPassword
    Old iDRAC password, MUST be secure string

    .Parameter NewPassword
    New iDRAC password, MUST be secure string

    .Parameter UserName
    User name of account to change can be either root or svcuser

    #>
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline=$true,Mandatory=$true,Position=0)]
        [ValidateScript({$_ -match [IPAddress]$_})]
        [String]$iDRACIP,
        [Parameter(ValueFromPipeline=$true,Mandatory=$true,Position=1)]
        [Security.SecureString]$OldPassword,
        [Parameter(ValueFromPipeline=$true,Mandatory=$true,Position=2)]
        [Security.SecureString]$NewPassword,
        [Parameter(ValueFromPipeline=$true,Mandatory=$true,Position=3)]
        [String]$UserName
    )

    $PlainTextOldPass = Decrypt-SecureString $OldPassword
    $PlainTextNewPass = Decrypt-SecureString $NewPassword
    
    switch ($UserName){
        "root"{
            $target = 'root@'+$iDRACIP
            plink $target -pw $PlainTextOldPass "racadm set iDRAC.Users.2.Password" $PlainTextNewPass
        }
        "svcuser"{
            $target = 'root@'+$iDRACIP
            plink $target -pw $PlainTextOldPass "racadm set iDRAC.Users.3.Password" $PlainTextNewPass
        }
        default{
            Write-Error -Message $username" is not a valid username"
        }
    }
    #$target = 'root@'+$iDRACIP
    #plink $target -pw $PlainTextOldPass "racadm set iDRAC.Users.2.Password" $PlainTextNewPass

}


Function Decrypt-SecureString {
    <#
    .SYNOPSIS
    Decrypts secure strings
    
    .DESCRIPTION
    This function accepts a secure string from the pipeline, decrypts it, and returns the plain text
    
    .PARAMETER sstr
    Secure string from the pipeline
    
    .EXAMPLE
    Decrypt-SecureString $securestring
    $PlainTextPass = Decrypt-SecureString $SecureString

    .Notes
    This function originally posted here: https://blogs.msdn.microsoft.com/besidethepoint/2010/09/21/decrypt-secure-strings-in-powershell/
    #>
    param(
    [Parameter(ValueFromPipeline=$true,Mandatory=$true,Position=0)]
    [System.Security.SecureString]
    $sstr
    )

    $marshal = [System.Runtime.InteropServices.Marshal]
    $ptr = $marshal::SecureStringToBSTR( $sstr )
    $str = $marshal::PtrToStringBSTR( $ptr )
    $marshal::ZeroFreeBSTR( $ptr )
    $str
}

function Set-AlliDRACPasswords {
    <#
    .SYNOPSIS
    Set iDRAC passwords for rotations
    
    .DESCRIPTION
    Gets the current iDRAC pass, new pass, dhcp server, and OOB IP scope.
    Using this info, extracts the IPs for the iDRACs, loops through the list, logs in, and changes password
    
    .EXAMPLE
    Set-iDRACPassword -DHCPServer "lab-dhcp-01" -ScopeID "10.10.10.0" -OldPassword $oldpass -NewPassword $newpass -UserName "svcuser"
    Note: function will ask for passwords interactively so they are never on screen as plain text

    .PARAMETER DHCPServer
    Valid DHCP server address, can be hostname or IP, prefer hostname

    .PARAMETER ScopeID
    Scope ID for OOB scope on DHCP server

    .Parameter OldPassword
    Old iDRAC password, MUST be secure string

    .Parameter NewPassword
    New iDRAC password, MUST be secure string

    .Parameter UserName
    Target username of password change
    #>

    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline=$true,Mandatory=$true,Position=0)]
        [String]$DHCPServer,
        [Parameter(ValueFromPipeline=$true,Mandatory=$true,Position=1)]
        [ValidateScript({$_ -match [IPAddress]$_})]
        [String]$ScopeID,
        [Parameter(ValueFromPipeline=$true,Mandatory=$true,Position=2)]
        [Security.SecureString]$OldPassword,
        [Parameter(ValueFromPipeline=$true,Mandatory=$true,Position=3)]
        [Security.SecureString]$NewPassword,
        [Parameter(ValueFromPipeline=$true,Mandatory=$true,Position=4)]
        [String]$UserName
    )
    
    #Create HashTable of iDRACs from DHCP server
    $idracs = Get-DhcpServerv4Lease -ComputerName $DHCPServer -ScopeId $ScopeID | Where-Object {($_.Hostname -like "idrac-*") -and ($_.AddressState -eq "ActiveReservation")}

    foreach($idrac in $idracs){
        $tempIP = ($idrac.IPAddress.IPAddressToString)
        $tempverbose = (Get-DhcpServerv4Lease -ComputerName $DHCPServer -ScopeId $ScopeID | Where-Object {$_.ipaddress -eq $tempIP}).hostname
        Write-Verbose -Message "Changing password for: $tempverbose"    
        Set-iDRACPassword -iDRACIP $tempIP -OldPassword $OldPassword -NewPassword $NewPassword -UserName $UserName
    }
}

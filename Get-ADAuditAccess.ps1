<# 

Slightly modified version of Ben Wilkinson's Get-ADAuditAccess:
https://gallery.technet.microsoft.com/scriptcenter/Auditing-Directory-Service-53574749

If you setup AD Auditing on Server 2008 DC's using the following article, 
 
 ++++ AD DS Auditing Step-by-Step Guide ++++  
http://technet.microsoft.com/en-us/library/cc731607(v=WS.10).aspx 
 
Then you will get events written to the Security event logs when objects in AD 
are modified/written to. 
 
Once you export the logs you lose some of the integrity of the message, 
since the Guid is not converted to the actual Usernames of the account 
making the changes. 
 
This script helps to export the data in a consumable format (A PSOBJECT). 
 
If you setup auditing on User/s and Group/s, then select those for the ObjectType, 
 
The Event logs look like the format below (A multi line string). 
 
----------------------------------------- 
An operation was performed on an object. 
 
Subject : 
    Security ID:        MARGIESTRAVEL\administrator 
    Account Name:        administrator 
    Account Domain:        MARGIESTRAVEL 
    Logon ID:            0x361c6 
 
Object: 
    Object Server:        DS 
    Object Type:        group 
    Object Name:        CN=Test3,OU=Groups,OU=NYC,OU=US,DC=MargiesTravel,DC=com 
    Handle ID:          0x0 
 
Operation: 
    Operation Type:        Object Access 
    Accesses:            Write Property 
                 
    Access Mask:        0x20 
    Properties:            Write Property 
                        {e48d0154-bcf8-11d1-8702-00c04fb96050} 
                        {bf967961-0de6-11d0-a285-00aa003049e2} 
                        {bf967a9c-0de6-11d0-a285-00aa003049e2} 
 
Additional Information: 
    Parameter 1:        - 
    Parameter 2:         
----------------------------------------- 
#> 

function Get-ADAuditAccess { 
 
    [CmdletBinding(DefaultParametersetName="Domain")]  
    Param  
    (  
        # ComputerName - A String array (list) of computernames 
        # Provide the computernames else the domain controllers in the current domain will be used  
        [Parameter(ParameterSetName="ComputerName", 
                   ValueFromPipeline=$true,  
                   ValueFromPipelineByPropertyName=$true,  
                   Position=0)]  
        [String[]]$ComputerName,  
  
        # Events - These are the associated Events 
        [String[]]$EventID = ("4662"),  
  
        # LogName - The EventLogs to search 
        [String[]]$LogName = "Security",  
  
        # DaysAgo - The number of days logs to retrieve 
        [Int32]$DaysAgo = 0,  
  
        # Starttime - Defaults to the same day, can provide a DateTime object 
        [DateTime]$StartTime = ([DateTime]::Today).AddDays(-$DaysAgo), 
 
        # ObjectType - Change the object type to the class of object that you setup the auditng on 
        # E.g. "User","Group" 
        [String[]]$ObjectType = ("Group","User","SecretObject","domainDNS") 
    ) 
 
Begin { 
 
    try {     
        # Ensure the active directory module is loaded. 
        Get-Module -Name ActiveDirectory -ErrorAction Stop | Out-Null 
 
        $PsCmdlet.ParameterSetName | Out-Host 
 
        if ( $ComputerName ) 
           { 
                write-host "Using provided ComputerNames" 
                # Custom computerlist supplied 
           } 
        elseif ($PsCmdlet.ParameterSetName -eq "Domain") 
            { 
                # Check every DC in the current domain for events. 
                Write-Host "checking for domain controllers . . ." 
                 
                $ADDetails=@{ 
                    SearchBase = ((Get-ADDomain).DomainControllersContainer) 
                    Filter     = {ObjectClass -eq "Computer"} 
                    } 
                 
                $ComputerName = Get-ADComputer @ADDetails | Select-Object -ExpandProperty Name 
                "Checking logs against {0} domain controllers:`n`n {1}" -f $ComputerName.count,($ComputerName -join ', ') | Out-Host 
            } 
 
        $FilterSearch = @{ 
            ID        = $EventID 
            LogName   = $LogName 
            StartTime = $StartTime 
            } 
 
 
    }#Try  
    catch  
    { 
        "The ActiveDirectory Module must be imported." 
        Break        
    }#Catch 
} 
 
Process { 

try {
    # Taken from https://gallery.technet.microsoft.com/Active-Directory-OU-1d09f989 by Ashley McGlone
	$ErrorActionPreference = 'SilentlyContinue'
	$GUIDMap = @{}
    Get-ADObject -SearchBase (Get-ADRootDSE).schemaNamingContext -LDAPFilter '(schemaIDGUID=*)' -Properties name, schemaIDGUID | ForEach-Object {$GUIDMap.add([String][System.GUID]$_.schemaIDGUID,$_.name)}
    Get-ADObject -SearchBase "CN=Extended-Rights,$((Get-ADRootDSE).configurationNamingContext)" -LDAPFilter '(objectClass=controlAccessRight)' -Properties name, rightsGUID |ForEach-Object {$GUIDMap.add([String][System.GUID]$_.rightsGUID,$_.name)}
	$ErrorActionPreference = 'Continue'
}
catch {
}

try{ 
 
    $ComputerName | ForEach-Object { 
        $Computer = $_ 
         
        $computer 
 
        # Check the security logs for the event. 
        Get-WinEvent -ComputerName $Computer -FilterHashtable $FilterSearch -ErrorAction Stop |  
        ForEach-Object { 
         
        #Full String Event Log Message 
        $FullMessage = $_.Message 
         
        # Portions of the Full Message 
        $Message = $FullMessage -split "Subject :" | select -Index 1 
        $Subject,$Message = $Message -split "Object:" 
        $Object,$Message  = $Message -split "Operation:" 
        $Operation,$Additional = $Message -split "Additional Information:" 
         
        # Smaller portions of the Message 
        $SubjectArray   = ($Subject  -split '\n') -split ':' | foreach {$_.trim()} 
        $ObjectArray    = ($Object -split '\n') -split ':' | foreach {$_.trim()} 
        $OperationArray = ($Operation -split '\n') -split ':' | foreach {$_.trim()} 
        #$AdditionalArray= ($Additional -split '\n') -split ':' | foreach {$_.trim()} 
         
        # The following code allows this to be run on a non domain controller (i.e. no guid is used) 
        try { 
            if ( $ObjectArray[6] -match '%') 
                { 
                    # Convert the Guid in the event log to the Byte Array to find the ObjectType 
                    [GUID]$guid = $ObjectArray[4].substring(2,36) 
                    $schemaIDGUID = $guid.ToByteArray() -join " " 
                    $Base = Get-ADRootDSE | Select-Object -ExpandProperty schemaNamingContext 
                    $Principal = Get-ADObject -Filter 'objectClassCategory -eq 1' -Properties schemaIDGUID -SearchBase $Base | 
                    ForEach-Object {$_ | Add-Member noteproperty -Name SGUID -Value ($_.schemaIDGUID -join " ") -Force;$_} |  
                    Where-Object {$_.SGUID -eq $schemaIDGUID} | Select -ExpandProperty Name  
                } 
            else 
                { 
                    $Principal = $ObjectArray[4]                
                } 
        }#try 
        catch { 
            $Principal = $ObjectArray[4]    
        }#catch 
         
        # The following code allows this to be run on a non domain controller (i.e. no guid is used) 
        try { 
            if ( $ObjectArray[6] -match '\\') 
                { 
                    $ObjectName = $ObjectArray[6] 
                } 
            else 
                { 
                    $ObjectName = (Get-ADObject -Identity $ObjectArray[6].substring(2,36)) 
                } 
        }#try 
        catch { 
            $ObjectName = $ObjectArray[6]    
        }#catch 
        
		# Add each accessed property to $AccessedProps
		[System.Collections.ArrayList]$AccessedProps=@()
		$AccessedProps.Add($GUIDMap[$OperationArray[10].replace('{','').replace('}','')]) | Out-Null
		$AccessedProps.Add($GUIDMap[$OperationArray[10].replace('{','').replace('}','')]) | Out-Null
        $AccessedProps.Add($GUIDMap[$OperationArray[10].replace('{','').replace('}','')]) | Out-Null
		$AccessedProps.Add($GUIDMap[$OperationArray[10].replace('{','').replace('}','')]) | Out-Null
		$AccessedProps.Add($GUIDMap[$OperationArray[10].replace('{','').replace('}','')]) | Out-Null
		$AccessedProps.Add($GUIDMap[$OperationArray[10].replace('{','').replace('}','')]) | Out-Null
		$AccessedProps.Add($GUIDMap[$OperationArray[10].replace('{','').replace('}','')]) | Out-Null
		$AccessedProps.Add($GUIDMap[$OperationArray[10].replace('{','').replace('}','')]) | Out-Null
		$AccessedProps.Add($GUIDMap[$OperationArray[10].replace('{','').replace('}','')]) | Out-Null

		#Write-Host $GUIDMap[$OperationArray[10].replace('{','').replace('}','')] 
		
		# Remove empty entries
		$AccessedProps = $AccessedProps | ?{$_ -ne ""}
		
        #$GUIDS = Get-DomainGUIDMap
		
		#$guidmap[$b[0].replace('{','').replace('}','')]
		
		ForEach ($item in $AccessedProps){
            # Put the pieces of the Message back together.
            $hash = @{ 
            TimeCreated=$_.TimeCreated 
            SecurityID   =$SubjectArray[2] 
            AccountName  =$SubjectArray[4] 
            AccountDomain=$SubjectArray[6] 
            LogonID      =$SubjectArray[8] 
            ObjectServer =$ObjectArray[2] 
            ObjectType   =$Principal 
            ObjectName   =$ObjectName 
            HandleID     =$ObjectArray[8] 
            OperationType=$OperationArray[2] 
            Accesses     =$OperationArray[4]
		    AccessedProp =$item
            } 
         
            New-Object psobject -Property $hash | select TimeCreated,SecurityID,AccountName,Accountdomain,` 
            LogonID,ObjectServer,ObjectType,ObjectName,HandleID,OperationType,Accesses,AccessedProp		
		}
		
        # Put the pieces of the Message back together.
        #$hash = @{ 
        #TimeCreated=$_.TimeCreated 
        #SecurityID   =$SubjectArray[2] 
        #AccountName  =$SubjectArray[4] 
        #AccountDomain=$SubjectArray[6] 
        #LogonID      =$SubjectArray[8] 
        #ObjectServer =$ObjectArray[2] 
        #ObjectType   =$Principal 
        #ObjectName   =$ObjectName 
        #HandleID     =$ObjectArray[8] 
        #OperationType=$OperationArray[2] 
        #Accesses     =$OperationArray[4]
		#AccessedProps=$AccessedProps
        #} 
         
        #New-Object psobject -Property $hash | select TimeCreated,SecurityID,AccountName,Accountdomain,` 
        #LogonID,ObjectServer,ObjectType,ObjectName,HandleID,OperationType,Accesses,AccessedProps
		
		#$A = New-Object psobject -Property $hash | select TimeCreated,SecurityID,AccountName,Accountdomain,` 
        #LogonID,ObjectServer,ObjectType,ObjectName,HandleID,OperationType,Accesses,AccessedProps
		
		#$Props = $A.AccessedProps.replace('}{',',').split(',').replace('{','').replace('}','')
		
		#$Props
 
        }#Foreach-Object(EventLog) 
         
    } #| Where-Object {$ObjectType -contains $_.ObjectType}    
 
}#Try 
catch{ "`nYou need permissions to query the event logs." } 	
 
}#Process 
     
}#function(Get-ADAuditAccess)

#requires -version 2

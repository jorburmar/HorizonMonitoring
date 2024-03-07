#cfg
$EventLogSource = "HorizonMonitor"
$EventSendMailMachines =  @('maquina1','maquina2','maquina3','maquina4')

#cfg


if (![System.Diagnostics.EventLog]::SourceExists($EventLogSource)) {
    New-EventLog -LogName Application -Source $EventLogSource
}

function Get-MapEntry {
  param(
    [Parameter(Mandatory = $true)] $Key,
    [Parameter(Mandatory = $true)] $Value
  )

  $update = New-Object VMware.Hv.MapEntry
  $update.key = $key
  $update.value = $value

  return $update
}

function Write-Log {
	param (
		[Parameter(Mandatory=$true)]				[string]$file='',
		[Parameter()]								[string]$message = '',
		[Parameter()]								[string]$color = 'White',
		[Parameter()]	[ValidateSet('1','2','3')]	[int]$severity = 1, ## Default to a low severity. Otherwise, override
		[Parameter()]								[bool]$WriteHost = $true,
		[Parameter()]								[bool]$TimeStamp = $true
	)
	if ($WriteHost) { Write-Host $message -ForegroundColor $color } # write to host console
	if ($TimeStamp) { $message = "$(Get-Date -Format 's'): $($message)" } # add TimeStamp to log
	Add-Content -Path $file -Value $message
}

filter timestamp {"$(Get-Date -Format 'dd/MM/yyyy HH:mm:ss'): $_"}
function Write-Event-Log {
	param (
		[Parameter(Mandatory)]		                   [string] $file,
		[Parameter()]				                   [string] $message = '',
        [Parameter()]				                   [int]    $event = '',
        [Parameter()] [ValidateSet('Error','Warning')] [string] $type = 'Error'
    )
    
    # offset para diferenciar los eventos/CPD
    if ($CPD -eq 'POD1')    { $event += 0 }
    if ($CPD -eq 'POD2') { $event += 1000 }

    if (!$([Environment]::UserInteractive)) {
        Write-EventLog -LogName "Application" -Source $EventLogSource -EventID $event -EntryType $type -Message $message
    }
	#Add-Content $file_name -Value $message
	#"[$($event)] " + $message | timestamp >> $file
	#$message >> $file
	#$message = "$(Get-Date -Format 'dd/MM/yyyy HH:mm:ss'): [$($event)] " + $message # marca de tiempo
	$message = "$(Get-Date -Format 's'): [$($event)@$($env:COMPUTERNAME)] $($message)"
    Add-Content -Path $file -Value $message

    # temporal, peticion extra de correo
    $remitente = "avisos@correo.com"
    $destinatarios = "avisos@correo.com"
    #$destinatarios = "j.burgos@ibermatica.com"
    $subjet = "[$scriptName] [$($event)][$($CPD)] $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')"
    $Smtpserver = 'servidorcorreo.com'
    $body = "Evento generado:"+"`r`n"+"`r`n"
    $body += $message
    if (!$([Environment]::UserInteractive)) {
        if ($type -eq 'Error') {
            if ($EventSendMailMachines -contains $([Environment]::MachineName)) {
                Send-MailMessage -From $remitente -To $destinatarios -Subject $subjet -Body $body -SmtpServer $Smtpserver
            }
        }
    }
}

function Get-Pod {
    param(
    [Parameter(Mandatory = $true)] $pods
    )

    $Timeout = 3 # Minutos
    $jobs = @{}
    $completed = $false
    $pod = $null

    foreach($CS in $pods) {
        $job = Start-Job -ArgumentList $cs,$encryptedPassword -ScriptBlock {
            param (
                $pod_temp,
                $pass
            )
            try {
                $portStatus = Test-NetConnection -ComputerName "$($pod_temp).dominioprincipal.com" -Port 443 -InformationLevel Quiet
                if (!$portStatus) { throw 'ERROR' }
            } catch {
                throw 'ERROR'
            }
        }
        $jobs.$cs = $job
    }
    $str = "Comprobando $($jobs.keys.Count) jobs."
    Write-Host $str
    $fechaTimeout = (Get-Date).AddMinutes($Timeout)
    do {
        foreach ($key in $jobs.keys) {
            if ($jobs.$key.State -eq "Completed" -and $jobs.$key.HasMoreData -eq $true) {
                Write-Host "Job $key completado $(get-date)"
                $completed = $true
                $pod = $key
                break
            }
        }
    } while (($completed -eq $false) -and ((Get-Date) -lt $fechaTimeout))
    return "$($pod).dominioprincipal.com"
}

function Get-VMEvents {
 <#
   .Synopsis
 
    Get events for an entity or for query all events.
 
   .Description
 
    This function returns events for entities. It's very similar to 
    get-vievent cmdlet.Note that get-VMEvent can handle 1 vm at a time.
    You can not send array of vms in this version of the script.
 
    .Example
 
    Get-VMEvents -types "VmCreatedEvent","VmDeployedEvent","VmClonedEvent"
 
    This will receive ALL events of types "VmCreatedEvent","VmDeployedEvent",
    "VmClonedEvent". 
     
   .Example
 
    Get-VMEvents -name 'vm1' -types "VmCreatedEvent"
 
    Will ouput creation events for vm : 'vm1'. This was is faster than piping vms from
    get-vm result. There is no need to use get-vm to pass names to get-vmevents.
    Still, it is ok when you will do it, it will make it just a little bit slower 😉
     
   .Example
 
    Get-VMEvents -name 'vm1' -category 'warning'
 
    Will ouput all events for vm : 'vm1'. This was is faster than piping names from
    get-vm cmdlet. Category will make get-vmevent to search only defined category
    events. 
     
   .Example
 
    get-vm 'vm1' | Get-VMEvents -types "VmCreatedEvent","VmMacAssignedEvent"
 
    Will display events from vm1 which will be regarding creation events,
    and events when when/which mac address was assigned
 
 
    .Parameter name
 
    This parameter is a single string representing vm name. It expects single vm name that
    exists in virtual center. At this moment in early script version it will handle only a case
    where there is 1 instance of vm of selected name. In future it will handle multiple as 
    well.
     
   .Parameter types
 
    If none specified it will return all events. If specified will return
    only events with selected types. For example : "VmCreatedEvent",
    "VmDeployedEvent", "VmMacAssignedEvent" "VmClonedEvent" , etc...
     
    .Parameter category
 
    Possible categories are : warning, info, error. Please use this parameter if you
    want to filter events.
 
   .Notes
 
    NAME:  Get-VMEvents
 
    AUTHOR: Grzegorz Kulikowski
 
    LASTEDIT: 11/09/2012
     
    NOT WORKING ? #powercli @ irc.freenode.net 
 
   .Link
 
    https://psvmware.wordpress.com
 
 #>
 
param(
[Parameter(ValueFromPipelineByPropertyName=$true)]
[string]$name,
[String[]]$types,
[string]$category,
[DateTime]$StartTime,
[DateTime]$EndTime
)
    $si = Get-View ServiceInstance
    $em = Get-View $si.Content.EventManager
    $EventFilterSpec = New-Object VMware.Vim.EventFilterSpec
    $EventFilterSpec.Type = $types
    if($category){
        $EventFilterSpec.Category = $category
    }
     
    if ($name){
        $vmentity = Get-View -ViewType virtualmachine -Filter @{'name'=$name}
        $EventFilterSpec.Entity = New-Object VMware.Vim.EventFilterSpecByEntity
        $EventFilterSpec.Entity.Entity = $vmentity.moref
        $EventFilterSpec.Time = New-Object VMware.Vim.EventFilterSpecByTime
        $EventFilterSpec.Time.BeginTime = $StartTime
        $EventFilterSpec.Time.EndTime = $EndTime
        $em.QueryEvents($EventFilterSpec)
    }else {
        $em.QueryEvents($EventFilterSpec)
    }
}

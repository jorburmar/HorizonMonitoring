<#
.SYNOPSIS
    Script que monitoriza las sesiones de los GlobalEntitlement para que sus respectivas granjas o pools no lleguen a llenarse

.DESCRIPTION
    Script que monitoriza las sesiones de los GlobalEntitlement para que sus respectivas granjas o pools no lleguen a llenarse

.PARAMETER <Parameter_Name>
    <Brief description of parameter input required. Repeat this attribute if required>

.INPUTS
    <Inputs if any, otherwise state None>

.OUTPUTS
    <Outputs if any, otherwise state None - example: Log file stored in C:\Windows\Temp\<name>.log>

.NOTES
    Version:        1.0
    Author:         <Name>
    Creation Date:  <Date>
    Purpose/Change: Initial script development

.EXAMPLE
    <Example goes here. Repeat this attribute for more than one example>

#>

#region CFG

$logNum = 90 # cantidad de logs a mantener / cantidad de dias a mantener en el log
$rdsh_session_percent_error = 90
$rdsh_session_percent_warning = 80
$vdi_session_percent_error = 95
$vdi_session_percent_warning = 90
$pattern = "\[AUTOMATIZACIONES\]((.|\n)*)\[/AUTOMATIZACIONES\]"
$maxTries = 3

#endregion


#region FUNCTIONS

function Write-Log {
	param (
		[Parameter(Mandatory)]						[string]$file,
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

#endregion


#region BEGIN

Clear-Host

# Set Error Action to Silently Continue
$ErrorActionPreference = "Stop"

$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

# Generamos nombres y rutas
$scriptName     = [System.IO.Path]::GetFileNameWithoutExtension($MyInvocation.MyCommand.Name)
$scriptPath     = Split-Path $script:MyInvocation.MyCommand.Path
$logPath        = "$($scriptPath)\logs\$($scriptName)"
$logFile        = "$($logPath)\$($scriptName)_$([DateTime]::Now.ToString('yyyyMMdd')).log"
$logFileError   = "$($logPath)\$($scriptName)_$([DateTime]::Now.ToString('yyyyMMdd'))_error.log"
if (-not(Test-Path $logPath -pathType Container)) { New-Item -ItemType Directory -Path $logPath | Out-Null }

# Purgado logs: varios ficheros
if (-not $logNum) { $logNum++ }
while ((Get-ChildItem "$($logPath)\" -File -Filter "$($scriptName)_*").Count -ge $logNum) {
    Get-ChildItem "$($logPath)\" -File -Filter "$($scriptName)_*" | Sort-Object CreationTime | Select-Object -First 1 | Remove-Item -Force
}

#Datos para el envio de email por errores
$email = $false
$from = "avisos@correo.com"
$to = @('avisos@correo.com')
$Smtpserver = 'servidorcorreo'
$subject = "Error en Script $($scriptName)"
$body = @("EQUIPO: $($env:COMPUTERNAME)",
        "USUARIO: $($env:USERNAME)",
        "SCRIPT: $($scriptName)",
        "SCRIPT PATH: $($scriptPath)")

Write-Host "logFile: $logFile" -ForegroundColor DarkCyan
if (Test-Path $logFile) {
    $str = "================================================================================"
	Write-Log $logFile $str -WriteHost:$false -TimeStamp:$false
}

# Registramos datos del comienzo de la ejecucion
$str = "Script [$($scriptName)] started - PowerShell version [$($PSVersionTable.PSVersion.ToString()) - $([IntPtr]::Size * 8) bit process]"
Write-Log $logFile $str DarkYellow
$str = "UserName: $([Environment]::UserName) - UserDomainName: $([Environment]::UserDomainName) - MachineName: $([Environment]::MachineName) - Date: $(Get-Date -Format 's')"
Write-Log $logFile $str DarkYellow

if ($([Environment]::UserInteractive)) {
    $str = "MANUAL Execution"
	Write-Log $logFile $str DarkYellow
} else {
    $str = "AUTOMATIC Execution"
	Write-Log $logFile $str DarkYellow
}
if ($PSBoundParameters.Count) {
    $str = "PARAMETERS Execution[$($PSBoundParameters.Count)]: $($PSBoundParameters.Keys -join ', ')"
	Write-Log $logFile $str DarkYellow
}
Write-Log $logFile

#endregion


#region PROCESS

try {

    Import-Module VMware.VimAutomation.Core
    Import-Module VMware.VimAutomation.HorizonView
    Import-Module "$($scriptPath)\Load-Functions.ps1" -Force

    if ($([Environment]::UserName) -ne 'nagusi-euc-connect') {
        throw "No se puede ejecutar $($scriptName) con el usuario '$([Environment]::UserName)', ejecutar con 'nagusi-euc-connect'"
    }

    $file_credentials = "$($scriptPath)\credentials\$([Environment]::UserDomainName)_$([Environment]::UserName).xml"
    try {
        $encryptedPassword = Import-Clixml -Path $file_credentials
    } catch {
        $str = "ERROR al cargar las credenciales."
        Write-Log $logFile $str
    }
    if ($null -eq $encryptedPassword) {
        throw "No se han cargado correctamente las credenciales."
    }

    #Recoger datos de la conexion
    $groupsToMonitor = @{}
    $farmsToMonitor = @{}
    $farmsTotal = @()
    $poolsTotal = @()
    $apps = @()
    $sessions = @()

    $files_pod = Get-ChildItem "$($scriptPath)\cfg" -File -Filter "*_pod"
    foreach ($file_pod in $files_pod) {
        Write-Log $logFile
        $pod = $file_pod.Name.Split('_')[0]
        $str = "Recogiendo informacion de: $pod"
        Write-Log $logFile $str Green
        $pod_server = $null
        $pod_servers = $null
        do {
            try {
                $pod_servers = [array](Get-Content $file_pod.FullName -ErrorAction SilentlyContinue)
            } catch {
                $str = "`tError al leer el archivo con los Connection Server."
                Write-Log $logFile $str
                Start-Sleep -Seconds 1
            }
            $maxTries--
        } while (($null -eq $pod_servers) -and ($maxTries -gt 0))
        if ($null -eq $pod_servers) {
            throw "No se han podido obtener los CS de $($pod)"
        }

        $podDataOK = $false
        $indexPodServer = $pod_servers.count - 1
        do {
            try {
                $pod_server = $pod_servers[$indexPodServer]
                $HVServer = $null
                $str = "Conectando con $($pod_server)"
                Write-Log $logFile $str DarkYellow

                Set-Variable -Name "HVServer_$($pod)" -Value (Connect-HVServer -Server "$($pod_server).dominioprincipal.com" -User $([Environment]::UserName) -Password $($encryptedPassword.GetNetworkCredential().Password) -Domain $([Environment]::UserDomainName) -ErrorAction Stop)
                $HVServer = (Get-Variable -Name "HVServer_$($pod)").Value
                Set-Variable -Name "HVServices_$($pod)" -Value $HVServer.ExtensionData
                $HVServices = (Get-Variable -Name "HVServices_$($pod)").Value

                $sesiones_pod = (get-HVlocalsession -HvServer $HVServer).namesdata
                $str = "Sesiones totales en $($pod): $($sesiones_pod.count)"
                Write-Log $logFile $str

                $pools_pod = Get-HVPool -HvServer $HVServer | Select-Object *, @{ Name = "POD" ; Expression = { $pod } }

                $appqueryservice = New-Object VMware.Hv.QueryServiceService
                $appdefn = New-Object VMware.Hv.QueryDefinition
                $appdefn.QueryEntityType = 'ApplicationInfo'
                $appdefn.SortBy = 'data.name'
                $appqueryResults = $appqueryService.QueryService_Create($HVServices, $appdefn)

                $GEs = Get-HVGlobalEntitlement -HvServer $HVServer #| Where-Object { $_.gettype().name -eq 'GlobalApplicationEntitlementInfo'}

                $farms_pod = Get-HVFarm -HvServer $HVServer | Select-Object *, @{ Name = "POD" ; Expression = { $pod } }
                $HVServices.QueryService.QueryService_DeleteAll()

                $sessions += $sesiones_pod
                $poolsTotal += $pools_pod
                $apps += $appqueryResults.results
                $farmsTotal += $farms_pod
                $podDataOK = $true
            } catch {
                $str = "Error al recoger informacion del CS $($pod_server): $($_.Exception.Message)"
                Write-Log $logFile $str Red
                if ($null -ne $HVServer) {
                    Disconnect-HVServer -Server $HVServer -Force -Confirm:$false
                }
                $indexPodServer--
            }
        } while (($podDataOK -eq $false) -and ($indexPodServer -ge 0))
        if ($indexPodServer -lt 0) {
            throw "No se ha podido recoger la informacion para el pod $($pod)."
        }
    }

    foreach ($GE in $GEs) {
        $result = [regex]::match($GE.Base.Description, $pattern).Groups[1].Value
        $tags = ($result.Split([Environment]::NewLine)) | Where-Object { $_ }
        if (!($tags -match "^SESSIONS_MONITOR")) { continue }

        switch ($GE.GetType().Name) {
            'GlobalEntitlementSummaryView' {
                Write-Log $logFile
                $str = "GlobalEntitlement: $($GE.Base.DisplayName)"
                Write-Log $logFile $str Green
                $pool = $poolsTotal | Where-Object { $_.GlobalEntitlementData.GlobalEntitlement.Id -eq $GE.Id.Id }
                $str = "Pool: $($pool.Base.Name)"
                Write-Log $logFile $str Green
                if ($pool.Type -ne 'AUTOMATED') {
                    $str = "`tEl pool a monitorizar $($pool.Base.Name) no es de tipo AUTOMATED."
                    Write-Log $logFile $str DarkYellow
                    continue
                }
                $result = [regex]::match($pool.Base.Description, $pattern).Groups[1].Value
                $tags = ($result.Split([Environment]::NewLine)) | Where-Object { $_ }

                if ($tags -match '^FULL_BLACKOUT$') {
                    $str = "`tSKIPPED - Pool in BLACKOUT"
                    Write-Log $logFile $str DarkYellow
                    continue
                }
                $HVServer = (Get-Variable -Name "HVServer_$($pool.POD)").Value
                $ics = Get-HVMachineSummary -HvServer $HVServer -PoolName $pool.Base.Name #-State AVAILABLE
                $pool_vdi_available = ($ics | Where-Object {$_.base.basicstate -eq 'AVAILABLE'}).count
                try {
                    $pool_sessions_percent_use = 100 - [math]::Round(($pool_vdi_available * 100 / $ics.count),2)
                }
                catch {
                    $pool_sessions_percent_use = 0
                }

                $ics_status = @{}
                foreach ($ic in $ics) {
                    if ($ics_status.Keys -notcontains $ic.base.basicstate) {
                        $ics_status."$($ic.base.basicstate)" = 1
                    }
                    else {
                        $ics_status."$($ic.base.basicstate)" += 1
                    }
                }
                foreach ($key in ($ics_status.Keys | Sort-Object)) {
                    $str = "`t$($key): $($ics_status.$key)"
                    Write-Log $logFile $str
                }
                $str = "`tPorcentaje de sesiones VDI en uso: $($pool_sessions_percent_use)%"
                Write-Log $logFile $str
                if($pool_sessions_percent_use -gt $vdi_session_percent_error) {
                    $str = "ERROR - GE: $($GE.Base.DisplayName): El pool $($pool.Base.Name) tiene en uso el $($pool_sessions_percent_use)% de las sesiones."
                    Write-Log $logFile $str Red
                    Write-Event-Log -file $logFileError -message $str -event 1021
                }
                #elseif ($pool_sessions_percent_use -gt $vdi_session_percent_warning) {
                #    $str = "WARNING - GE: $($GE.Base.DisplayName): El pool $($pool.Base.Name) tiene en uso el $($pool_sessions_percent_use)% de las sesiones."
                #    Write-Log $logFile $str Red
                #    Write-Event-Log $logFileError $str 1021 'Warning'
                #}
            }
            'GlobalApplicationEntitlementInfo' {
                $farms = @()
                $GAEApps = $apps | Where-Object {$_.data.GlobalApplicationEntitlement.id -eq $GE.id.id}
                foreach ($GAEApp in $GAEApps) {
                    $farm = $farmsTotal | Where-Object { $_.Id.Id -eq $GAEApp.ExecutionData.Farm.Id }
                    $farms += $farm
                }
                if ($groupsToMonitor.Keys -notcontains "$($farms.Data.Name -join '|')") {
                    $groupsToMonitor."$($farms.Data.Name -join '|')" = @{}
                    $groupsToMonitor."$($farms.Data.Name -join '|')".APPS = @()
                    $groupsToMonitor."$($farms.Data.Name -join '|')".FULLBLACKOUT = $true
                    $groupsToMonitor."$($farms.Data.Name -join '|')".RDSH_COUNT = 0
                    $groupsToMonitor."$($farms.Data.Name -join '|')".RDSH_ACTIVE_COUNT = 0
                    $groupsToMonitor."$($farms.Data.Name -join '|')".SESSION_COUNT = 0
                    $groupsToMonitor."$($farms.Data.Name -join '|')".SESSION_ACTIVE_COUNT = 0
                    $groupsToMonitor."$($farms.Data.Name -join '|')".SESSION_ACTIVE_LIMIT = 0
                }
                $groupsToMonitor."$($farms.Data.Name -join '|')".APPS += $GE.Base.DisplayName
                foreach ($farm in $farms) {
                    $farmsToMonitor.$($farm.Data.Name) = @{}
                    $farmsToMonitor.$($farm.Data.Name).POD = $farm.POD
                }
            }
        }
    }

    # Recogemos las sesiones de las granjas a monitorizar en sus respectivos RDSH
    foreach($session in $sessions) {
        if($farmsToMonitor.Keys -contains $session.FarmName) {
            if ($farmsToMonitor."$($session.FarmName)".Keys -notcontains $session.MachineOrRDSServerName) {
                $farmsToMonitor."$($session.FarmName)"."$($session.MachineOrRDSServerName)" = 1
            }
            else {
                $farmsToMonitor."$($session.FarmName)"."$($session.MachineOrRDSServerName)" += 1
            }
        }
    }

    #Realizamos QueryService para los RDSH
    $RDSHqueryService = New-Object VMware.Hv.QueryServiceService
    $RDSHdefn = New-Object VMware.Hv.QueryDefinition
    $RDSHdefn.queryEntityType = 'RDSServerSummaryView'
    $RDSHdefn.SortBy = 'base.name'

    Write-Log $logFile
    foreach ($farm in $farmsToMonitor.Keys) {
        $HVServer = (Get-Variable -Name "HVServer_$($farmsToMonitor.$farm.POD)").Value
        $HVServices = (Get-Variable -Name "HVServices_$($farmsToMonitor.$farm.POD)").Value

        $session_count = ($farmsToMonitor.$farm.Values | Where-Object { $_ -match "\d" } | Measure-Object -Sum).Sum
        $farmResult = Get-HVFarmSummary -HvServer $HVServer -FarmName $farm
        $result = [regex]::match($farmResult.Data.Description, $pattern).Groups[1].Value
        $farmTags = ($result.Split([Environment]::NewLine)) | Where-Object { $_ }
        $maxSessions = $farmResult.data.MaximumNumberOfSessions
        $rdsh_count = $farmResult.data.rdsServerCount
        $farm_id = $farmResult.Id

        if ($farmResult.data.maxSessionsType -eq "UNLIMITED") {
            $str = "La granja $($farm) tiene sesiones ilimitadas."
            Write-Log $logFile $str
            foreach ($farmGroup in $groupsToMonitor.keys | Where-Object { $_.Split('|') -contains $farm }) {
                $groupsToMonitor.$farmGroup.UNLIMITED = $true
            }
            continue
        }
        if ($farmTags -match "^FULL_BLACKOUT") {
            $str = "La granja $($farm) está en FULL BLACKOUT."
            Write-Log $logFile $str
            continue
        }
        foreach ($farmGroup in $groupsToMonitor.keys | Where-Object { $_.Split('|') -contains $farm }) {
            $groupsToMonitor.$farmGroup.FULLBLACKOUT = $false
        }
        if ($farmResult.data.Enabled -eq $false) {
            $str = "La granja $($farm) está deshabilitada."
            Write-Log $logFile $str
            continue
        }

        $rdshActive = @()
        $rdshActiveNoSessions = @()
        $RDSHdefnFilter1 = New-Object VMware.Hv.QueryFilterEquals -Property @{'memberName'='base.farm'; 'value'=$farm_id}
        $RDSHdefnFilter2 = New-Object VMware.Hv.QueryFilterEquals -Property @{'memberName'='settings.enabled'; 'value'=$true}
        $filters = @()
        $filters += $RDSHdefnFilter1
        $filters += $RDSHdefnFilter2
        $filterAnd = New-Object VMware.Hv.QueryFilterAnd
        $filterAnd.Filters = $filters
        $RDSHdefn.Filter = $filterAnd
        $RDSHqueryResults = $RDSHqueryService.QueryService_Create($HVServices, $RDSHdefn)
        foreach ($result in $RDSHqueryResults.Results) {
                $rdshActive += $result.base.name
                if ($farmsToMonitor.$farm.Keys -notcontains $result.base.name) {
                    $rdshActiveNoSessions += $result.base.name
                }
        }
        $rdsh_active_count = $rdshActive.count
        try {
            $maxSessions_active = $maxSessions * $rdsh_active_count / $rdsh_count
        } catch {
            $maxSessions_active = 0
        }
        $session_count_active_rdsh = 0
        $session_max = @()
        $farmsToMonitor.$farm.GetEnumerator() | ForEach-Object {
            if ($rdshActive -contains $_.key) {
                $session_count_active_rdsh += $_.Value
                $session_max += $_.Value
            }
        }
        $ICMaxSessions = ($session_max | Measure-Object -Maximum).Maximum
        if (($ICMaxSessions -ge 2) -and $rdshActiveNoSessions -and ($rdsh_count -ge 4) -and !(($farmsToMonitor.$farm.GetEnumerator() | ? { $rdshActive -contains $_.Key } | Select -ExpandProperty Value) -eq 1)) {
            $str = "`nGranja: $($farm) con problemas de sesiones en ICs activos.`n"
            Write-Log $logFile $str Red

            $str = "`tSesiones totales: $($farmsToMonitor.$farm.getenumerator() | ? {$_.key -ne 'POD'} | Select -ExpandProperty Value | measure -Sum | Select -ExpandProperty Sum)`n"
            $str = "`tICs totales: $($rdsh_count)`n"
            $str += "`tMedia de sesiones en ICs activos con sesiones: $([math]::Round(($farmsToMonitor.$farm.GetEnumerator() | ? {$rdshActive -contains $_.Key} | Select -ExpandProperty Value | Measure -Average | Select -ExpandProperty Average),2))`n"
            $str += "`tIC's activos: $(@($rdshActive).count)`n"
            $farmsToMonitor.$farm.GetEnumerator() | ? { $rdshActive -contains $_.Key -and $_.key -ne 'POD'} | % { $str += "`t - RDSH: $($_.key): $($_.value) sesiones`n" }
            $str += "`tIC's activos sin sesiones $(@($RDSHActiveNoSessions).count): $($RDSHActiveNoSessions -join ', ')`n"
            $str += "`tIC's inactivos con sesiones: $(($farmsToMonitor.$farm.GetEnumerator() | ? { $rdshActive -notcontains $_.Key -and $_.key -ne 'POD'}).count)`n"
            $farmsToMonitor.$farm.GetEnumerator() | ? { $rdshActive -notcontains $_.Key -and $_.key -ne 'POD'} | % { $str += "`t - RDSH: $($_.key): $($_.value) sesiones`n" }
            Write-Log $logFile $str
        
            $str = "ERROR - Granja: [$($farm)] con $(@($RDSHActiveNoSessions).count) RDSHs sin sesiones: $($RDSHActiveNoSessions -join ', ')"
            Write-Event-Log -file $logFileError -message $str -event 1023
        }

        foreach ($farmGroup in $groupsToMonitor.keys | Where-Object { $_.Split('|') -contains $farm }) {
            $groupsToMonitor.$farmGroup.RDSH_COUNT += $rdsh_count
            $groupsToMonitor.$farmGroup.RDSH_ACTIVE_COUNT += $rdsh_active_count
            $groupsToMonitor.$farmGroup.SESSION_COUNT += $session_count
            $groupsToMonitor.$farmGroup.SESSION_ACTIVE_COUNT += $session_count_active_rdsh
            $groupsToMonitor.$farmGroup.SESSION_ACTIVE_LIMIT += $maxSessions_active
        }

        $RDSHqueryService.QueryService_DeleteAll($HVServices)
    }

    foreach ($farmGroup in ($groupsToMonitor.keys | Sort-Object)) {
        Write-Log $logFile
        $str = "Granjas: $($farmGroup.Split('|') -join ' y ')"
        Write-Log $logFile $str Green
        $str = "GlobalEntitlements: $($groupsToMonitor.$farmGroup.APPS -join ', ')"
        Write-Log $logFile $str Green
        if ($groupsToMonitor.$farmGroup.UNLIMITED -eq $true) {
            $str = "`t-> SKIPPED: Al menos una de las granjas está con sesiones ilimitadas."
            Write-Log $logFile $str DarkYellow
            continue
        }
        if ($groupsToMonitor.$farmGroup.FULLBLACKOUT -eq $true) {
            $str = "`t-> SKIPPED: Todas las granjas están con el tag FULL_BLACKOUT."
            Write-Log $logFile $str DarkYellow
            continue
        }
        $str = "`tServidores RDSH totales: $($groupsToMonitor.$farmGroup.RDSH_COUNT)"
        Write-Log $logFile $str
        $str = "`tServidores activos: $($groupsToMonitor.$farmGroup.RDSH_ACTIVE_COUNT)"
        Write-Log $logFile $str
        $str = "`tNumero total de sesiones: $($groupsToMonitor.$farmGroup.SESSION_COUNT)"
        Write-Log $logFile $str
        $str = "`tNumero total de sesiones en servidores activos: $($groupsToMonitor.$farmGroup.SESSION_ACTIVE_COUNT)"
        Write-Log $logFile $str
        $str = "`tLimite máximo de sesiones: $($groupsToMonitor.$farmGroup.SESSION_ACTIVE_LIMIT)"
        Write-Log $logFile $str
        if (($groupsToMonitor.$farmGroup.SESSION_ACTIVE_LIMIT -eq 0) -or ($null -eq $groupsToMonitor.$farmGroup.SESSION_ACTIVE_LIMIT)) {
            $str = "`tERROR: El límite máximo de sesiones es 0"
            Write-Log $logFile $str Red
            $str = "ERROR - GE: $($groupsToMonitor.$farmGroup.APPS -join ', '): El conjunto de granjas $($farmGroup.Split('|') -join ' y ') no tiene servidores RDSH activos."
            Write-Log $logFile $str Red
            Write-Event-Log -file $logFileError -message $str -event 1022
        }
        else {
            try {
                $percent_use = [math]::Round(($groupsToMonitor.$farmGroup.SESSION_ACTIVE_COUNT * 100 / $groupsToMonitor.$farmGroup.SESSION_ACTIVE_LIMIT),2)
            }
            catch {
                $percent_use = 0
            }
            $str = "`tPorcentaje de sesiones en uso: $($percent_use)%"
            Write-Log $logFile $str
            if($percent_use -ge $rdsh_session_percent_error) {
                $str = "ERROR - GE: $($groupsToMonitor.$farmGroup.APPS -join ', '): El conjunto de granjas $($farmGroup.Split('|') -join ' y ') tiene en uso el $($percent_use)% de las sesiones."
                Write-Log $logFile $str red
                Write-Event-Log -file $logFileError -message $str -event 1022
            }
            elseif ($percent_use -ge $rdsh_session_percent_warning) {
                $str = "WARNING - GE: $($groupsToMonitor.$farmGroup.APPS -join ', '): El conjunto de granjas $($farmGroup.Split('|') -join ' y ') tiene en uso el $($percent_use)% de las sesiones."
                Write-Log $logFile $str red
				Write-Event-Log -file $logFileError -message $str -event 1022 -type 'Warning'
            }
        }
    }

    Disconnect-HVServer -Server * -Force -Confirm:$false

} catch {
    $email = $true
    $str = "ERROR: $($_.Exception.Message). At Line:$($_.InvocationInfo.ScriptLineNumber) Char: $($_.InvocationInfo.OffsetInLine)"
    Write-Log $logFile $str Red
	Write-Log $logFileError $str -WriteHost $false
	$body += $str
}

#endregion


#region END
Write-Log $logFile
# Registramos datos del fin de la ejecucion
$stopwatch.Stop()

$str = "Script [$($scriptName)] finished - Elapsed time: $($stopwatch.Elapsed.ToString())"
Write-Log $logFile $str DarkYellow

if (!([Environment]::UserInteractive)) {
    if ($email) {
        Send-MailMessage -From $from -To $to -Subject $subject -Body $($body -join "`r`n") -SmtpServer $Smtpserver
    }
}

#endregion

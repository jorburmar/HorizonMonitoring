<#
.SYNOPSIS
    Scripts para monitorizar la infraestructura de Horizon View.

.DESCRIPTION
    Scripts para monitorizar la infraestructura de Horizon View.

.PARAMETER <Parameter_Name>
    <Brief description of parameter input required. Repeat this attribute if required>

.INPUTS
    <Inputs if any, otherwise state None>

.OUTPUTS
    <Outputs if any, otherwise state None - example: Log file stored in C:\Windows\Temp\<name>.log>

.NOTES
    Version:        1.0
    Author:         Jorge Burgos
    Creation Date:  14/03/2019
    Purpose/Change: Initial script development

.EXAMPLE
    <Example goes here. Repeat this attribute for more than one example>

===Tested Against Environment====
vSphere Version: 6.0
PowerCLI Version: VMware PowerCLI 11.5.0 build 14912921
PowerCLI Component Version: VMware Common PowerCLI Component 11.5 build 14898112
							VMware Cis Core PowerCLI Component PowerCLI Component 11.5 build 14898113
							VMware VimAutomation VICore Commands PowerCLI Component PowerCLI Component 11.5 build 14899560
PowerShell Version: 5.1
OS Version: Windows Server 2012 R2
Keyword: HV, Farm, RDSH, CS, POD....
#>

Param (
    [Parameter()] [ValidateSet('POD1','POD2')] [string] $CPD = 'POD1'
)

#region CFG

$ResultStatus = 'Success'
$logNum = 60 # cantidad de logs a mantener / cantidad de dias a mantener en el log
$pattern = "\[AUTOMATIZACIONES\]((.|\n)*)\[/AUTOMATIZACIONES\]"
$maxTries = 3

#endregion


#region FUNCTIONS

function Write-Log {
	param (
		[Parameter(Mandatory)]						[string]$file='',
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
$scriptName      = [System.IO.Path]::GetFileNameWithoutExtension($MyInvocation.MyCommand.Name)
$scriptPath      = Split-Path $script:MyInvocation.MyCommand.Path
$logPath         = "$($scriptPath)\logs\$($scriptName)"
$logFile         = "$($logPath)\$($scriptName)_$($CPD)_$([DateTime]::Now.ToString('yyyyMMdd')).log"
$logFileError    = "$($logPath)\$($scriptName)_$($CPD)_$([DateTime]::Now.ToString('yyyyMMdd'))_error.log"
$file_name       = $logFile
$file_name_error = $logFileError
if (-not(Test-Path $logPath -pathType Container)) { New-Item -ItemType Directory -Path $logPath | Out-Null }

# Purgado logs: varios ficheros
if (-not $logNum) { $logNum++ }
while ((Get-ChildItem "$($logPath)\" -File -Filter "$($scriptName)_$($CPD)_*").Count -ge $logNum) {
    Get-ChildItem "$($logPath)\" -File -Filter "$($scriptName)_$($CPD)_*" | Sort-Object CreationTime | Select-Object -First 1 | Remove-Item -Force
}

#Datos para el envio de email por errores
$email = $false
$from = "avisos@correo.com"
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
$beginExecutionTime = $stopwatch

#endregion


#region PROCESS

try {
    
    Import-Module VMware.VimAutomation.Core
    Import-Module VMware.VimAutomation.HorizonView
    Import-Module "$($scriptPath)\Load-Functions.ps1" -Force
    Import-Module "$($scriptPath)\Load-Server-Data.ps1" -Force

    if ($([Environment]::UserName) -ne 'nagusi-euc-connect') {
        throw "No se puede ejecutar $($scriptName) con el usuario '$([Environment]::UserName)', ejecutar con 'nagusi-euc-connect'"
    }

    $podDataOK = $false
    $indexPodServer = $pod_servers.count - 1
    do {
        try {
            $pod_server = $pod_servers[$indexPodServer]
            $HVServer = $null
            $str = "Conectando con $($pod_server)"
            Write-Log $logFile $str DarkYellow

            $HVServer = Connect-HVServer -Server "$($pod_server).dominioprincipal.com" -User $([Environment]::UserName) -Password $($encryptedPassword.GetNetworkCredential().Password) -Domain $([Environment]::UserDomainName) -ErrorAction Stop
            $HVServices = $HVServer.ExtensionData

            # Sacamos toda la informacion necesaria
            $podsInfo = $HVServices.pod.pod_list() | Where-Object {$_.localpod -eq $true}
            $conserversInfo = $HVServices.ConnectionServerHealth.ConnectionServerHealth_List()
            $UAGsInfo = $HVServices.GatewayHealth.GatewayHealth_List()
            $HVFarmInfo = Get-HVFarm
            $HVPoolsInfo = Get-HVPool
            $appqueryservice = New-Object VMware.Hv.QueryServiceService
            $appdefn = New-Object VMware.Hv.QueryDefinition
            $appdefn.QueryEntityType = 'ApplicationInfo'
            $appdefn.SortBy = 'data.name'
            $appqueryResults = $appqueryService.QueryService_Create($HVServices, $appdefn)

            $pods = $podsInfo
            $conservers = $conserversInfo
            foreach ($conserver in $conservers) { $conserver | Add-Member -MemberType NoteProperty -Name Enabled -Value ($HVServices.ConnectionServer.ConnectionServer_Get($conserver.Id)).General.Enabled }
            $UAGs = $UAGsInfo
            $HVFarm = $HVFarmInfo
            foreach ($farm in $HVFarm) { $farm | Add-Member -MemberType NoteProperty -Name Health -Value $HVServices.Farmhealth.farmhealth_get($farm.id) }
            $HVPools = $HVPoolsInfo
            $apps = $appqueryResults.results
            $podDataOK = $true
        } catch {
            $str = "Error al recoger informacion del CS $($pod_server): $($_.Exception.Message)"
            Write-Log $logFile $str Red
            #Write-Log $logFileError $str -WriteHost $false
            if ($HVServer -ne $null) {
                Disconnect-HVServer -Server $HVServer -Force -Confirm:$false
            }
            $indexPodServer--
        }
    } while (($podDataOK -eq $false) -and ($indexPodServer -ge 0))
    if ($indexPodServer -lt 0) {
        $str = "POD: $($CPD) - ERROR ALL CONNECTION SERVERS [$($pod_servers -join (', '))]"
        Write-Event-Log -file $logFileError -message $str -event 1050 -pod $CPD
        throw "No se ha podido recoger la informacion para el pod $($pod)."
    }
	
    $HVServices.QueryService.QueryService_DeleteAll()
    Disconnect-HVServer -Server * -Force -Confirm:$false

    Write-Log $logFile
    $str = "POD[$($HVServer.Name)]"
    Write-Log $logFile $str Magenta
    Write-Log $logFile

    # Pod
    $str = "Pod"
    Write-Log $logFile $str Magenta
    foreach ($pod in $pods) {
        $str = "$($pod.DisplayName)"
        Write-Log $logFile $str
    }
    Write-Log $logFile

    # Connection Servers Status
    $str = "Connection Servers Status"
    Write-Log $logFile $str Magenta
    $compare = Compare-Object -ReferenceObject $conservers.name -DifferenceObject $pod_servers
    if($compare -and $conservers.name.count -gt 0) {
        $str = "Se han encontrado diferencias entre los CS, se actualiza el archivo del share."
        Write-Log $logFile $str
        try {
            $conservers.name | Out-File $file_pod_server -Encoding utf8 -Force
        } catch {
		    $str = "Error al actualizar archivo de CS [$($file_pod_server)]: $($_.Exception.Message)"
		    Write-Log $logFile $str Red
        }
    }
    foreach ($conserver in $conservers) {
        $str = "$($conserver.Name) - Status: $($conserver.Status) - Enabled: $($conserver.Enabled)"
        Write-Log $logFile $str
        if (($conserver.Status -ne 'OK') -and ($conserver.Enabled -ne $false)) {
            $str = "Conection Server: $($conserver.Name) - Status: $($conserver.Status) - Enabled: $($conserver.Enabled)"
            Write-Event-Log -file $logFileError -message $str -event 1001 -pod $CPD
            $str = "`t" + $str
            Write-Log $logFile $str Red
        }
    }
    Write-Log $logFile

    # Unified Access Gateway Status
    $str = "Unified Access Gateway Status"
    Write-Log $logFile $str Magenta
    $str_final = ''
    foreach ($UAG in $UAGs) {
        $str = "$($UAG.Name) - Status: $($UAG.GatewayStatusActive) - Contacted: $($UAG.GatewayContacted) - Stale: $($UAG.GatewayStatusStale)"
        Write-Log $logFile $str
        if (($UAG.GatewayStatusActive -ne $true) -or ($UAG.GatewayContacted -ne $true) -or ($UAG.GatewayStatusStale -ne $false)) {
            $str = "`tUnified Access Gateway: $($UAG.Name) - Status: $($UAG.GatewayStatusActive) - Contacted: $($UAG.GatewayContacted) - Stale: $($UAG.GatewayStatusStale)"
            Write-Log $logFile $str Red
            $str_final += "`r`n" + $str
        }
    }
    if (![string]::IsNullOrEmpty($str_final)) {
        Write-Event-Log -file $logFileError -message $str_final -event 1015 -pod $CPD
    }
    Write-Log $logFile

    # Farm Health
    $str = "Farm Health"
    Write-Log $logFile $str Magenta
    $contador = 0
    foreach ($farm in $HVFarm) {
        $result = [regex]::match($farm.Data.Description, $pattern).Groups[1].Value
        $tags = ($result.Split([Environment]::NewLine)) | Where-Object { $_ }
        if (!($tags -match '^24x7') -and !($tags -match '^8x5')) { continue }
        $rdsh_blackout = @()
        if ($tags -match '^IC_BLACKOUT\[(.+)\].*') {
            $farm.data.description -match '.*IC_BLACKOUT\[(.+?)\].*'
            $rdsh_blackout = ($Matches[1]).Split(',')
        }
        $contador++
        $str_final = ''
        $str = "$($farm.Data.Name) - $($farm.Data.Enabled) - $($farm.Health.Health)"
        Write-Log $logFile $str
        if ($tags -match '^FULL_BLACKOUT$') {
            $str = "`tSKIPPED - Farm in BLACKOUT"
            Write-Log $logFile $str DarkYellow
            continue
        }
        if (!$farm.Data.Enabled) {
            $str = "`tPOD: $($CPD) Farm: $($farm.Data.Name) `tEnabled: $($farm.Data.Enabled)"
            Write-Log $logFile $str Red
            $str_final += "`r`n" + $str
        }
        if ($farm.Health.Health -ne 'OK') {
            $str_tmp = $null
            #$str_tmp = ($health.RdsServerHealth | Where-Object {($_.Status -ne 'AVAILABLE') -and ($_.Status -ne 'DISABLED') -and ($_.Status -ne 'DISABLE_IN_PROGRESS')}).Name -join ', '
            #$str_tmp = ($health.RdsServerHealth | Where-Object {($_.Health -ne 'OK') -and ($_.Health -ne 'DISABLED')}).Name -join ', '
            $str_tmp = ($farm.Health.RdsServerHealth | Where-Object {($_.Health -ne 'OK') -and ($_.Health -ne 'DISABLED') -and ($rdsh_blackout -notcontains $_.Name)}).Name -join ', '
            if ($str_tmp) {
                $str = "`tPOD: $($CPD) Farm: $($farm.Data.Name) `tHealth: $($farm.Health.Health) `tError Servers: $str_tmp"
                Write-Log $logFile $str Red
                $str_final += "`r`n" + $str
            }
        }
        if (![string]::IsNullOrEmpty($str_final)) {
            if ($tags -match '^8x5') {
                Write-Event-Log -file $logFileError -message $str_final -event 1004 -type 'Warning' -pod $CPD
            } else {
				Write-Event-Log -file $logFileError -message $str_final -event 1004 -pod $CPD
            }
        }
    }
    $str = "Total: $($contador)/$($HVFarm.Count)"
    Write-Log $logFile $str Yellow
    Write-Log $logFile

    # Pools Health
    $str = "Pools Health"
    Write-Log $logFile $str Magenta
    foreach ($pool in $HVPools) {
        $result = [regex]::match($pool.Base.Description, $pattern).Groups[1].Value
        $tags = ($result.Split([Environment]::NewLine)) | Where-Object { $_ }
        #if (($pool.Base.Description -notmatch '24x7') -and ($pool.Base.Description -notmatch '8x5')) { continue }
        if (!($tags -match '^24x7') -and !($tags -match '^8x5')) { continue }
        $contador++
        $str_final = ''
        if ($pool.Type -eq 'AUTOMATED') {
            $ProvisioningStatus = $pool.AutomatedDesktopData.VirtualCenterProvisioningSettings.enableprovisioning
            $str = "$($pool.Base.Name) - $($pool.DesktopSettings.Enabled) - $($pool.type) - $ProvisioningStatus"
        } else {
            $str = "$($pool.Base.Name) - $($pool.DesktopSettings.Enabled) - $($pool.type)"
        }
        Write-Log $logFile $str
        if ($tags -match '^FULL_BLACKOUT$') {
            $str = "`tSKIPPED - Pool in BLACKOUT"
            Write-Log $logFile $str DarkYellow
            continue
        }
        if (!$pool.DesktopSettings.Enabled) {
            $str = "`tPool: $($pool.Base.Name) `tEnabled: $($pool.DesktopSettings.Enabled)"
            Write-Log $logFile $str Red
            $str_final += "`r`n" + $str
        }
        if (($pool.Type -eq 'AUTOMATED') -and (!$ProvisioningStatus)) {
            $str = "`tPool: $($pool.Base.Name) `tProvisioningStatus: $($ProvisioningStatus)"
            Write-Log $logFile $str Red
            $str_final += "`r`n" + $str
        }
        if (![string]::IsNullOrEmpty($str_final)) {
            if ($tags -match '^8x5') {
                Write-Event-Log -file $logFileError -message $str_final -event 1005 -type 'Warning' -pod $CPD
            } else {
				Write-Event-Log -file $logFileError -message $str_final -event 1005 -pod $CPD
            }
        }
    }
    $str = "Total: $($contador)/$($HVPools.Count)"
    Write-Log $logFile $str Yellow
    Write-Log $logFile

    # Aplications Health
    $str = "Aplications Health"
    Write-Log $logFile $str Magenta
    $contador = 0
    foreach ($app in $apps) {
        $result = [regex]::match($app.data.description, $pattern).Groups[1].Value
        $tags = ($result.Split([Environment]::NewLine)) | Where-Object { $_ }
        if (!($tags -match '^24x7') -and !($tags -match '^8x5')) { continue }
        $farm = $HVfarm | Where-Object { $_.Id.Id -eq $app.ExecutionData.Farm.Id }
        $rdsh_blackout = @()
        $result = [regex]::match($farm.data.description, $pattern).Groups[1].Value
        $tags_farm = ($result.Split([Environment]::NewLine)) | Where-Object { $_ }
        if ($tags_farm -match '^IC_BLACKOUT\[(.+)\].*') {
            $farm.data.description -match '.*IC_BLACKOUT\[(.+?)\].*'
            $rdsh_blackout = ($Matches[1]).Split(',')
        }
        $contador++
        $str_final = ''
        $str = "$($app.Data.Name) - $($app.Data.DisplayName) - $($app.Data.Enabled) - $($farm.Data.Name) [$($farm.AutomatedFarmData.RdsServerNamingSettings.PatternNamingSettings.MaxNumberOfRDSServers)] - $($app.ExecutionData.ExecutablePath)"
        Write-Log $logFile $str
        if (!$app.Data.Enabled) {
            $str = "App: $($app.Data.Name) - $($app.Data.DisplayName) `tEnabled: $($app.Data.Enabled)"
            Write-Log $logFile $str Red
            $str_final += "`r`n" + $str
        }

        # check RDSHs
        $health = $HVFarm | Where-Object { $_.Id.Id -eq $farm.Id.Id } | Select -ExpandProperty Health
	    foreach ($rdsserver in $health.RdsServerHealth | Sort-Object Name){
            #Write-Host "`t$($rdsserver.Name)"
            if ($rdsserver.MissingApplications) {
                #Write-Host "`t`t$($rdsserver.Name) - $($rdsserver.MissingApplications.name -join ', ')"
                if ($rdsserver.MissingApplications.name -contains $app.Data.Name) {
                    $str = "`tRdsServerHealth: $($rdsserver.Name) @ $($farm.Data.Name) - MissingApplications: $($rdsserver.MissingApplications.name -join ', ')"
                    Write-Log $logFile $str Red
                    #$str_final += "`r`n" + $str
                }
            }
	    }

        if (![string]::IsNullOrEmpty($str_final)) {
            if ($tags -match '^8x5') {
                Write-Event-Log -file $logFileError -message $str_final -event 1006 -type 'Warning' -pod $CPD
            } else {
				Write-Event-Log -file $logFileError -message $str_final -event 1006 -pod $CPD
            }
        }
    }
} catch {
    $email = $true
    $ResultStatus = 'Failed'
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

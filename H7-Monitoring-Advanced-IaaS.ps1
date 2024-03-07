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
    Author:         <Name>
    Creation Date:  <Date>
    Purpose/Change: Initial script development

.EXAMPLE
    <Example goes here. Repeat this attribute for more than one example>

#>

Param (
    [Parameter()] [ValidateSet('POD1','POD2')] [string]   $CPD = 'POD1'
)

#region CFG

$ResultStatus = 'Success'
$logNum = 30 # cantidad de logs a mantener / cantidad de dias a mantener en el log
$pattern = "\[AUTOMATIZACIONES\]((.|\n)*)\[/AUTOMATIZACIONES\]"
$CHECK_VM = $true
$CHECK_EXE = $true
$HASH_EXE = $true
$HASH_CONFIG = $true
$HASH_FOLDER = $false
$CHECK_APPSTACKS = $true
$bateraDC = @{}
$bateraDC.'dominio-1.com' = 'dominio-1.dns'
$bateraDC.'dominio-2.com' = 'dominio-2.dns'

$reintentos_ping = 5
$reintentos_exe = 10

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

# Set Error Action to Stop
$ErrorActionPreference = "Stop"

$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

# Generamos nombres y rutas
$scriptName      = [System.IO.Path]::GetFileNameWithoutExtension($MyInvocation.MyCommand.Name)
$scriptPath      = Split-Path $script:MyInvocation.MyCommand.Path
$logPath         = "$($scriptPath)\logs\$($scriptName)"
$logFile         = "$($logPath)\$($scriptName)_$($CPD)_$([DateTime]::Now.ToString('yyyyMMdd')).log"
$logFileError    = "$($logPath)\$($scriptName)_$($CPD)_$([DateTime]::Now.ToString('yyyyMMdd'))_error.log"
$logFileDebug    = "$($logPath)\$($scriptName)_$($CPD)_$([DateTime]::Now.ToString('yyyyMMdd'))_debug.log"
$file_name       = $logFile
$file_name_error = $logFileError
if (-not(Test-Path $logPath -pathType Container)) { New-Item -ItemType Directory -Path $logPath | Out-Null }

# Purgado logs: varios ficheros
if (-not $logNum) { $logNum++ }
while ((Get-ChildItem "$($logPath)\" -File -Filter "$($scriptName)_$($CPD)_*").Count -ge $logNum) {
    Get-ChildItem "$($logPath)\" -File -Filter "$($scriptName)_$($CPD)_*" | Sort-Object CreationTime | Select-Object -First 1 | Remove-Item -Force
}

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
    $str = "PARAMETERS Execution[$($PSBoundParameters.Count)]:"
    Write-Log $logFile $str DarkYellow
    foreach ($key in $PSBoundParameters.Keys) {
        $str = " - $($key)[$($PSBoundParameters.$key.GetType().Name)]: $($PSBoundParameters.$key -join ', ')"
        Write-Log $logFile $str DarkYellow
    }
}

$beginExecutionTime = $stopwatch

#endregion


#region PROCESS

Write-Log $logFile

try {
    
    Import-Module VMware.VimAutomation.Core
    Import-Module VMware.VimAutomation.HorizonView
    Import-Module "$($scriptPath)\Load-Functions.ps1" -Force
    Import-Module "$($scriptPath)\Load-Server-Data.ps1" -Force
    Import-Module "$($scriptPath)\Invoke-Parallel.ps1" -Force

    if ($([Environment]::UserName) -ne 'nagusi-euc-connect') {
        throw "No se puede ejecutar $($scriptName) con el usuario '$([Environment]::UserName)', ejecutar con 'nagusi-euc-connect'"
    }

	$file_credentials = "$($scriptPath)\credentials\$([Environment]::UserDomainName)_$([Environment]::UserName).xml"
	try {
		$credHV = Import-Clixml -Path $file_credentials
	} catch {
		$str = "ERROR al cargar las credenciales."
		Write-Log $logFile $str
	}
	if ($null -eq $credHV) {
		throw "No se han cargado correctamente las credenciales."
	}
	
    $podDataOK = $false
    $indexPodServer = $pod_servers.count - 1
    do {
        try {
            $pod_server = $pod_servers[$indexPodServer]
            $HVServer = $null
            $str = "Conectando con $($pod_server)"
            Write-Log $logFile $str DarkYellow

            $HVServer = Connect-HVServer -Server "$($pod_server).dominioprincipal.com" -Credential $credHV -ErrorAction Stop
            $HVServices = $HVServer.ExtensionData

            # Sacamos toda la informacion necesaria
            $HVFarmInfo = Get-HVFarm
            $appqueryservice = New-Object VMware.Hv.QueryServiceService
            $appdefn = New-Object VMware.Hv.QueryDefinition
            $appdefn.QueryEntityType = 'ApplicationInfo'
            $appdefn.SortBy = 'data.name'
            $appqueryResults = $appqueryService.QueryService_Create($HVServices, $appdefn)

            $apps = $appqueryResults.results
            $HVFarms = $HVFarmInfo
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
        throw "No se ha podido recoger la informacion para el pod $($CPD)."
    }

    $VIServer = Connect-VIServer -Server $vcenter_server -Protocol https -User "$([Environment]::UserDomainName)\$([Environment]::UserName)" -Password $($encryptedPassword.GetNetworkCredential().Password) -ErrorAction Stop
    if (!$VIServer.IsConnected) {
        $str = "vCenter: $($CPD) - $($VIServer.Name) CONNECTION ERROR [$vcenter_server]"
        Write-Event-Log -file $logFileError -message $str -event 1001 -type Warning -pod $CPD
        $str = "`t" + $str
        Write-Log $logFile $str Red
        $CHECK_VM = $false
    }

    Set-Variable -Name appvolumes_server -value $appvolumes_server -Scope global
    Import-Module "$($scriptPath)\AppVolumes.ps1" -Force

    Write-Log $logFile
    $str = "POD[$($HVServer.Name)]"
    Write-Log $logFile $str Magenta

    # Farm AppStacks
    $str = "Farm AppStacks"
    Write-Log $logFile $str Magenta
    foreach ($farm in $HVFarms) {
        $result = [regex]::match($farm.Data.Description, $pattern).Groups[1].Value
        $tags = ($result.Split([Environment]::NewLine)) | Where-Object { $_ }
        if (!($tags -match '^24x7') -and !($tags -match '^8x5')) { continue }
        $rdsh_blackout = @()
        if ($tags -match '^IC_BLACKOUT\[(.+)\].*') {
            $farm.data.description -match '.*IC_BLACKOUT\[(.+?)\].*'
            $rdsh_blackout = ($Matches[1]).Split(',')
        }
        $str_final = ''
        $health = $HVServices.Farmhealth.farmhealth_get($farm.id)
        $str = "$($farm.Data.Name) - $($farm.Data.Enabled) - $($health.Health)"
        Write-Log $logFile $str
        if ($tags -match '^FULL_BLACKOUT$') {
            $str = "`tSKIPPED - Farm in BLACKOUT"
            Write-Log $logFile $str DarkYellow
            continue
        }
        if (!$farm.Data.Enabled) {
            $str = "`tSKIPPED - Farm DISABLED"
            Write-Log $logFile $str DarkYellow
            continue
        }

        $file_name_diurnos = "$($path_share)logs\$($farm.Data.Name)\diurnos.log"
        $file_name_nocturnos = "$($path_share)logs\$($farm.Data.Name)\nocturnos.log"
        $equipos_diurnos = $null
        $equipos_nocturnos = $null
        if (Test-Path $file_name_diurnos) { $equipos_diurnos = Get-Content $file_name_diurnos }
        if (Test-Path $file_name_nocturnos) { $equipos_nocturnos = Get-Content $file_name_nocturnos }

        $vmdk_ou_tmp = $null
        $servers_app_check = @{}
        $servers_app_check_diurnos = @{}
        $servers_app_check_nocturnos = @{}
    
        # check RDSHs AppStacks
        $queryService = New-Object VMware.Hv.QueryServiceService
        $defn = New-Object VMware.Hv.QueryDefinition
        $defn.queryEntityType = 'RDSServerSummaryView'
        $defn.Filter = New-Object VMware.Hv.QueryFilterEquals -Property @{'memberName'='base.farm'; 'value'=$($farm.Id)}
        $defn.SortBy = 'base.name'
        $queryResults = $queryService.QueryService_Create($HVServices, $defn)

        $sufijo = $queryResults.Results[0].AgentData.DnsName.Split('.',2)[1]
        if ($bateraDC.$sufijo) {
            $proxyDC = $bateraDC.$sufijo
        }
        else {
            $proxyDC = $sufijo
        }

        # Comprobamos si la granja tiene AppStacks
        $computer_tmp = Get-ADComputer $queryResults.Results[0].Base.Name -Server $proxyDC -ErrorAction SilentlyContinue
        $OU_equipo_tmp = ($computer_tmp.DistinguishedName.Split(',',2))[1]
        try {
            $vmdk_ou_tmp = Get-AppVolume-vmdk-OU -OrganizationalUnit $OU_equipo_tmp | Sort-Object
        } catch {
            $str = "`tError al sacar los AppStacks: $($_.Exception.Message)"
            Write-Log $logFile $str Red
            Write-Log $logFileError $str -WriteHost:$false
            continue
        }
        if (!($vmdk_ou_tmp)) {
            $str = "`tSKIPPED - Farm without AppStacks"
            Write-Log $logFile $str DarkYellow
            $HVServices.QueryService.QueryService_DeleteAll()
            continue
        }
        if ((Test-Path $file_name_diurnos) -and (Test-Path $file_name_nocturnos)) {
            Write-Host "`tGRANJA DIRUNOS/NOCTURNOS" -ForegroundColor Yellow
            $generica = $false
        } else {
            Write-Host "`tGRANJA GENERICA" -ForegroundColor Yellow
            $generica = $true
        }

        foreach ($rdsh in $queryResults.Results) {
            if ($rdsh_blackout -contains $rdsh.Base.Name) {
                $str = "`tSe omite el IC $($rdsh.Base.Name) ya que está en BLACKOUT."
                Write-Log $logFile $str
                continue
            }
            $AppCheck = $null
            try {
                $AppCheck = @()
                $vm = Get-VM $($rdsh.Base.Name) -ErrorAction Stop
                $discos = ($vm | Get-HardDisk -ErrorAction Stop | Where-Object { $_.Persistence -eq 'IndependentNonPersistent'} | Sort-Object Filename | Select-Object Filename).Filename
                foreach ($disco in $discos) {
                    $AppCheck += $($disco.Split('/')[-1])
                }
            } catch {
                $AppCheck = 'ERROR'
                $str = "`tERROR [$($rdsh.Base.Name): $($_.Exception.Message)"
                Write-Log $logFile $str
            }
            if (!$AppCheck) { $AppCheck = "NODISK" }
            if ($equipos_diurnos -contains $rdsh.Base.Name) {
                if ($servers_app_check_diurnos.Keys -notcontains $($AppCheck)) { $servers_app_check_diurnos."$($AppCheck)" = @() }
                $servers_app_check_diurnos."$($AppCheck)" += "$($rdsh.Base.Name)"
            } elseif ($equipos_nocturnos -contains $rdsh.Base.Name) {
                if ($servers_app_check_nocturnos.Keys -notcontains $($AppCheck)) { $servers_app_check_nocturnos."$($AppCheck)" = @() }
                $servers_app_check_nocturnos."$($AppCheck)" += "$($rdsh.Base.Name)"
            } else {
                if ($servers_app_check.Keys -notcontains $($AppCheck)) { $servers_app_check."$($AppCheck)" = @() }
                $servers_app_check."$($AppCheck)" += "$($rdsh.Base.Name)"
            }
        }

        if ((Test-Path $file_name_diurnos) -and (Test-Path $file_name_nocturnos)) {
            # Check AppStacks level 1:
            #if (($servers_app_check_diurnos.Keys.Count -gt 1) -or (("ERROR","NODISK") -contains $servers_app_check_diurnos.Keys)) {
            if (($servers_app_check_diurnos.Keys.Count -gt 1) -or ($servers_app_check_diurnos.Keys -ne $vmdk_ou_tmp)) {
                $str = "`tAppVolumes Disks: $($vmdk_ou_tmp -join ', ') -> AppStacks problems [diurnos][$($equipos_diurnos.Count)]"
                Write-Log $logFile $str Red
                $str_final += "`r`n" + $str
                $contador_hash = 0
                foreach ($key in $servers_app_check_diurnos.Keys) {
                    if ($key -ne $vmdk_ou_tmp) {
                        $contador_hash += ($servers_app_check_diurnos.$key.Count)
                        $str = "`t`tAppStacks[$($servers_app_check_diurnos.$key.Count)][$(($key -split ' ') -join ', ')]: $($servers_app_check_diurnos.$key -join ', ')"
                        Write-Log $logFile $str Red
                        $str_final += "`r`n" + $str
                    }
                }
                if ($contador_hash -ne $equipos_diurnos.Count) {
                    $str = "`t`tERROR EQUIPOS [diurnos][$($equipos_diurnos.Count)/$($contador_hash)]"
                    Write-Log $logFile $str Red
                    $str_final += "`r`n" + $str
                }
            }
            #if (($servers_app_check_nocturnos.Keys.Count -gt 1) -or (("ERROR","NODISK") -contains $servers_app_check_nocturnos.Keys)) {
            if (($servers_app_check_nocturnos.Keys.Count -gt 1) -or ($servers_app_check_nocturnos.Keys -ne $vmdk_ou_tmp)) {
                $str = "`tAppVolumes Disks: $($vmdk_ou_tmp -join ', ') -> AppStacks problems [nocturnos][$($equipos_nocturnos.Count)]"
                Write-Log $logFile $str Red
                $str_final += "`r`n" + $str
                $contador_hash = 0
                foreach ($key in $servers_app_check_nocturnos.Keys) {
                    if ($key -ne $vmdk_ou_tmp) {
                        $contador_hash += ($servers_app_check_nocturnos.$key.Count)
                        $str = "`t`tAppStacks[$($servers_app_check_nocturnos.$key.Count)][$(($key -split ' ') -join ', ')]: $($servers_app_check_nocturnos.$key -join ', ')"
                        Write-Log $logFile $str Red
                        $str_final += "`r`n" + $str
                    }
                }
                if ($contador_hash -ne $equipos_nocturnos.Count) {
                    $str = "`t`tERROR EQUIPOS [nocturnos][$($equipos_nocturnos.Count)/$($contador_hash)]"
                    Write-Log $logFile $str Red
                    $str_final += "`r`n" + $str
                }
            }
        } else {
            # Check AppStacks level 1:
            #if (($servers_app_check.Keys.Count -gt 1) -or (("ERROR","NODISK") -contains $servers_app_check.Keys)) {
            if (($servers_app_check.Keys.Count -gt 1) -or ($servers_app_check.Keys -ne $vmdk_ou_tmp)) {
                $str = "`tFarm: $($farm.Data.Name) [$($queryResults.Results.Count)] -> AppVolumes Disks: $($vmdk_ou_tmp -join ', ') -> AppStacks problems"
                Write-Log $logFile $str Red
                $str_final += "`r`n" + $str
                $contador_hash = 0
                foreach ($key in $servers_app_check.Keys) {
                    if ($key -ne $vmdk_ou_tmp) {
                        $contador_hash += ($servers_app_check.$key.Count)
                        $str = "`t`tAppStacks[$($servers_app_check.$key.Count)][$(($key -split ' ') -join ', ')]: $($servers_app_check.$key -join ', ')"
                        Write-Log $logFile $str Red
                        $str_final += "`r`n" + $str
                    }
                }
                if ($contador_hash -ne $queryResults.Results.Count) {
                    $str = "`t`tERROR EQUIPOS [$($queryResults.Results.Count)/$($contador_hash)]"
                    Write-Log $logFile $str Red
                    $str_final += "`r`n" + $str
                }
            }
        }

        if (![string]::IsNullOrEmpty($str_final)) {
            if ($tags -match '^8x5') {
                Write-Event-Log -file $logFileError -message $str_final -event 1007 -type 'Warning' -pod $CPD
            } else {
                Write-Event-Log -file $logFileError -message $str_final -event 1007 -pod $CPD
            }
        }

        $HVServices.QueryService.QueryService_DeleteAll()

    }
    Write-Log $logFile

    # Aplications Health
    $str = "Aplications Health"
    Write-Log $logFile $str Magenta
    $contador = 0
    foreach ($app in $apps) {
        $result = [regex]::match($app.data.description, $pattern).Groups[1].Value
        $tags = ($result.Split([Environment]::NewLine)) | Where-Object { $_ }

        if (!($tags -match '^24x7') -and !($tags -match '^8x5')) { continue }
        $farm = $HVServices.Farm.Farm_Get($app.ExecutionData.Farm)
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
        if ($tags_farm -match '^FULL_BLACKOUT$') {
            $str = "`tSKIPPED - Farm in BLACKOUT"
            Write-Log $logFile $str DarkYellow
            continue
        }
        if (!$app.Data.Enabled) {
            $str = "App: $($app.Data.Name) - $($app.Data.DisplayName) `tEnabled: $($app.Data.Enabled)"
            Write-Log $logFile $str Red
            $str_final += "`r`n" + $str
        }

        # check RDSHs advanced monitoring
        $queryService = New-Object VMware.Hv.QueryServiceService
        $defn = New-Object VMware.Hv.QueryDefinition
        $defn.queryEntityType = 'RDSServerSummaryView'
        $defn.Filter = New-Object VMware.Hv.QueryFilterEquals -Property @{'memberName'='base.farm'; 'value'=$($farm.Id)}
        $defn.SortBy = 'base.name'
        $queryResults = $queryService.QueryService_Create($HVServices, $defn)

        foreach ($rdsh in $queryResults.Results) {
            $str = "`tCheck[$([array]::IndexOf($queryResults.Results, $rdsh)+1)/$($queryResults.Results.Count)]: POD:$($CPD) ->"
            #Write-Log $logFile $str

            # RDSH data problems
            if ($rdsh_blackout -contains $rdsh.Base.Name) {
                $str = "Se omite el IC $($rdsh.Base.Name) ya que está en BLACKOUT."
                Write-Log $logFile $str
                continue
            }
            if (($rdsh.Base.Name -eq $null) -or ($rdsh.Base.Name -eq '')) {
                $str += " SIN_NOMBRE -> $($farm.Data.Name) -> $($app.Data.Name) -> RDSH SIN DATOS"
                Write-Log $logFile $str Red
                $str_final += "`r`n" + $str
                continue
            }
            if (($rdsh.AgentData.DnsName -eq $null) -or ($rdsh.AgentData.DnsName -eq '')) {
                $str += " $($rdsh.Base.Name) SIN_NOMBRE_DNS -> $($farm.Data.Name) -> $($app.Data.Name) -> RDSH SIN DATOS DNS"
                Write-Log $logFile $str Red
                $str_final += "`r`n" + $str
                continue
            }

            # VM exists?
            if ($CHECK_VM) {
                try {
                    $vm = Get-VM $($rdsh.Base.Name) -ErrorAction Stop
                } catch {
                    $str += " $($rdsh.Base.Name) -> NO EXISTE LA MV [$($rdsh.Base.Name)] en [$($vcenter_server)] -> $($farm.Data.Name) -> $($app.Data.Name) -> ERROR: $($_.Exception.Message)"
                    Write-Log $logFile $str Red
                    $str_final += "`r`n" + $str
                    continue
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

        $HVServices.QueryService.QueryService_DeleteAll()
    }
    $str = "Total: $($contador)/$($apps.Count)"
    Write-Log $logFile $str Yellow
    Write-Log $logFile
    $HVServices.QueryService.QueryService_DeleteAll()

    Disconnect-HVServer -Server * -Force -Confirm:$false
    Disconnect-VIServer -Server * -Force -Confirm:$false

} catch {
    $ResultStatus = 'Failed'
    $str = "ERROR: $($_.Exception.Message). At Line:$($_.InvocationInfo.ScriptLineNumber) Char: $($_.InvocationInfo.OffsetInLine)"
    Write-Log $logFile $str Red
    Write-Log $logFileError $str -WriteHost $false
}

Write-Log $logFile

#endregion


#region END

# Registramos datos del fin de la ejecucion
$stopwatch.Stop()

$str = "Script [$($scriptName)] finished - Elapsed time: $($stopwatch.Elapsed.ToString())"
Write-Log $logFile $str DarkYellow

#endregion

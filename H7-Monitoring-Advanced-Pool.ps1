<#
.SYNOPSIS
    Script que monitoriza las VDI de las pools

.DESCRIPTION
    Script que monitoriza las VDI de las pools

.PARAMETER <Parameter_Name>
    <Brief description of parameter input required. Repeat this attribute if required>

.INPUTS
    <Inputs if any, otherwise state None>

.OUTPUTS
    <Outputs if any, otherwise state None - example: Log file stored in C:\Windows\Temp\<name>.log>

.NOTES
    Version:        1.0
    Author:         Soporte Puesto Automatización
    Creation Date:  10/2023

.EXAMPLE
    .\HV-Monitoring-Advanced-Pool.ps1 -CPD 'POD1'

#>

#region CFG

Param (
    [Parameter()] [ValidateSet('POD1','POD2')] [string]   $CPD = 'POD1'
)

#region CFG

$ResultStatus = 'Success'
$logNum = 30 # cantidad de logs a mantener / cantidad de dias a mantener en el log
$pattern = "\[AUTOMATIZACIONES\]((.|\n)*)\[/AUTOMATIZACIONES\]"

$reintentos_ping = 5

$dominios = @{}

$dominios['dominio-1.com'] = @{}
$dominios['dominio-1.com']['credenciales'] = 'dominio-1_superuser'
$dominios['dominio-1.com']['proxy'] = 'proxy_dominio-1'
$dominios['dominio-1.com']['sufijo'] = '.dominio-1.com'

$dominios['dominio-2.com'] = @{}
$dominios['dominio-2.com']['credenciales'] = 'dominio-2_superuser'
$dominios['dominio-2.com']['proxy'] = 'proxy_dominio-2'
$dominios['dominio-2.com']['sufijo'] = '.dominio-2.com'

$dominios['dominio-3.com'] = @{}
$dominios['dominio-3.com']['credenciales'] = 'dominio-3_superuser'
$dominios['dominio-3.com']['proxy'] = 'proxy_dominio-3'
$dominios['dominio-3.com']['sufijo'] = '.dominio-3.com'

$vditenants = @{}

$vditenants['01'] = @{}
$vditenants['01']['credenciales'] = 'dominio-1_superuser'
$vditenants['01']['proxy'] = 'proxy_dominio-1'

$vditenants['02'] = @{}
$vditenants['02']['credenciales'] = 'dominio-2_superuser'
$vditenants['02']['proxy'] = 'proxy_dominio-2'

$vditenants['03'] = @{}
$vditenants['03']['credenciales'] = 'dominio-3_superuser'
$vditenants['03']['proxy'] = 'proxy_dominio-3'

$srvsmon = @{}

$srvsmon.'wuauserv' = @{}
$srvsmon.'wuauserv'.Name = 'WINDOWS UPDATE'
$srvsmon.'wuauserv'.Required = $false

$srvsmon.'svservice' = @{}
$srvsmon.'svservice'.Name = 'APPVOLUMES'
$srvsmon.'svservice'.Required = $true

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

function Soy-Proxy {
    param(
    #[Parameter(Mandatory = $true)] $server
    )
    foreach ($key in $dominios.Keys) {
        if ($dominios.$key.proxy -eq $env:COMPUTERNAME) {
            return $true
        }
    }
    
    return $false
}

#endregion


#region BEGIN

Clear-Host

# Set Error Action to Stop
$ErrorActionPreference = 'Stop'

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
    $str = 'MANUAL Execution'
	Write-Log $logFile $str DarkYellow
} else {
    $str = 'AUTOMATIC Execution'
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

$beginExecutionTime = $stopwatch.Elapsed.TotalSeconds

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
		$str = 'ERROR al cargar las credenciales.'
		Write-Log $logFile $str
	}
	if ($null -eq $credHV) {
		throw 'No se han cargado correctamente las credenciales.'
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

            $pools_pod = Get-HVPool -HvServer $HVServer | Select-Object *, @{ Name = "POD" ; Expression = { $CPD } }

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

    Write-Log $logFile
    $str = "POD [$($HVServices.pod.Pod_List() | Where-Object {$_.LocalPod -eq $true} | Select-Object -ExpandProperty DisplayName)] - CS [$($HVServer.Name)]"
    Write-Log $logFile $str Magenta

    $str = "Pools Health [$($pools_pod.Count)]"
    Write-Log $logFile $str Magenta
    $contador = 0
    foreach ($pool in $pools_pod) {
        $result = [regex]::match($pool.Base.Description, $pattern).Groups[1].Value
        $tags = ($result.Split([Environment]::NewLine)) | Where-Object { $_ }
        if (!($tags -match '^24x7') -and !($tags -match '^8x5')) { continue }
        
        $contador++
        $vdis = Get-HVMachineSummary -HvServer $HVServer -PoolName $pool.Base.Name

        $str = "Pool: $($pool.Base.name) [$($vdis.Count)]"
        Write-Log $logFile $str

        if ($pool.Type -eq 'MANUAL') {
            $str = "`tSKIPPED: Pool MANUAL"
            Write-Log $logFile $str DarkGreen
            continue
        }

        if ($tags -match '^FULL_BLACKOUT$') {
            $str = "`tSKIPPED: Pool in BLACKOUT"
            Write-Log $logFile $str DarkGreen
            continue
        }

        $poolDomain = $vdis[0].Base.DnsName.Split('.',2)[1]
        $sufijo = $dominios.$poolDomain.sufijo
        if ($vdis[0].Base.Name -match '^v(\d\d).*' ) { $tenantpool = $Matches[1] } else { $tenantpool = $false }
        if (($dominios.$poolDomain.proxy) -and ($dominios.$poolDomain.proxy -ne $env:COMPUTERNAME)) {
            $str = "`tSKIPPED: Dominio [$($poolDomain)] se monitoriza en $($dominios.$poolDomain.proxy)"
            Write-Log $logFile $str DarkGreen
            continue
        } elseif ( $tenantpool ) {
            if ($vditenants.$tenantpool.proxy -and ($vditenants.$tenantpool.proxy -ne $env:COMPUTERNAME)){
                $str = "`tSKIPPED: VDI en tenant [$($tenantpool)] se monitoriza en $($vditenants.$tenantpool.proxy)"
                Write-Log $logFile $str DarkGreen
                continue
            } elseif ($vditenants.keys -notcontains $tenantpool) {
                $str = "`tSKIPPED: VDI en tenant [$($tenantpool)]. Tenant no gestionado para monitorizacion."
                Write-Log $logFile $str DarkGreen
                continue
            }
        
        }
        elseif ((Soy-Proxy) -and ($dominios.$poolDomain.proxy -ne $env:COMPUTERNAME)) {
            $str = "`tSKIPPED: Soy PROXY"
            Write-Log $logFile $str DarkGreen
            continue
        }

        #SACAMOS UN VDI PARA COMPROBACIONES GENÉRICAS DE GOLD
        $VDICheck = $vdis[$(Get-Random -Maximum $vdis.Count)].Base.Name

         if (!(Test-Connection -ComputerName $VDICheck -Count 2 -Quiet -ErrorAction SilentlyContinue)) { 
            $str = "`tSKIPPED: No se puede contactar con el VDI $($VDICheck)"
            Write-Log $logFile $str Yellow
            continue
        }

        # Comprobamos servicios genéricos (no definidos en tags)
        $str_final = ''

        foreach($srvmon in $srvsmon.Keys){
            try {
                if (!(Get-Service -ComputerName "$($VDICheck)$($sufijo)" | ? { $_.Name -eq $srvmon }) ) { 
                    $str = "`t-[$($srvsmon.$srvmon.Name)($($srvmon))]@[$($VDICheck)] SKIP CHECK: No existe el servicio en el equipo."
                    Write-Log $logFile $str Yellow
                    continue
                }

                $service = Get-Service $srvmon -ComputerName "$($VDICheck)$($sufijo)"
                if ($($srvsmon.$srvmon.Required)){
                    if ($service.Status -eq 'Stopped') {
                        $str = "`t-[$($srvsmon.$srvmon.Name)($($srvmon))]@[$($VDICheck)] CHECK ERROR: El servicio se encuentra parado. (Estado actual: [$($service.Status)])"
                        $str_final += "`r`n" + $str
                        Write-Log $logFile $str Red
                    }
                    if ($service.StartType -ne 'Automatic') {
                        $str = "`t-[$($srvsmon.$srvmon.Name)($($srvmon))]@[$($VDICheck)] CHECK ERROR: El arranque del servicio no esta establecido como automatico. (Configuracion actual: [$($service.StartType)])"
                        $str_final += "`r`n" + $str
                        Write-Log $logFile $str Red
                    }
                } else {
                    if ($service.Status -ne 'Stopped') {
                        $str = "`t-[$($srvsmon.$srvmon.Name)($($srvmon))]@[$($VDICheck)] CHECK ERROR: El servicio no se encuentra parado. (Estado actual: [$($service.Status)] y tipo de arranque: [$($service.StartType)])"
                        $str_final += "`r`n" + $str
                        Write-Log $logFile $str Red
                    }
                    if ($service.StartType -ne 'Manual' -and $service.StartType -ne 'Disabled') {
                        $str = "`t-[$($srvsmon.$srvmon.Name)($($srvmon))]@[$($VDICheck)] CHECK ERROR: El arranque del servicio no esta establecido como manual ni deshabilitado. (Configuracion actual: [$($service.StartType)])"
                        $str_final += "`r`n" + $str
                        Write-Log $logFile $str Red
                    }
                }
                if ([string]::IsNullOrEmpty($str_final)) {
                    $str = "`t-[$($srvsmon.$srvmon.Name)($($srvmon))]@[$VDICheck] CHECK OK: Servicio [$($service.Status)] y arranque [$($service.StartType)]."
                    Write-Log $logfile $str Green
                }
            } catch [System.InvalidOperationException] {
                $str = "`t-[$($srvsmon.$srvmon.Name)($($srvmon))]@[$($VDICheck)] CHECK ERROR: Sin permisos para obtener informacion de servicios de la Pool [$($pool.base.Name)]: $($_.Exception.Message)"
                Write-Log $logFile $str Red
                $str_final += "`r`n" + $str
            } catch {
                $str = "`t-[$($srvsmon.$srvmon.Name)($($srvmon))]@[$($VDICheck)] CHECK ERROR: No se pudo gestionar servicio [$($srvmon)] de la Pool [$($pool.base.Name)]: $($_.Exception.Message)"
                Write-Log $logFile $str Red
                $str_final += "`r`n" + $str
            }
        }
        
        if (!([string]::IsNullOrEmpty($str_final))) {
            $str_final = "$($pool.Base.Name) - $($pool.Base.DisplayName) - " + "$($str_final)"
            if ($tags -match '^8x5') {
                Write-Event-Log -file $logFileError -message $str_final -event 1019 -type 'Warning' -pod $CPD
            } else {
                Write-Event-Log -file $logFileError -message $str_final -event 1019 -pod $CPD
            }
        }
    }

    $str = "Total: $($contador)/$($pools_pod.Count)"
    Write-Log $logFile $str Yellow
    Write-Log $logFile

    Disconnect-HVServer -Server * -Force -Confirm:$false

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

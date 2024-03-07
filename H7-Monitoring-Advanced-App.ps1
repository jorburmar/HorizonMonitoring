<#
.SYNOPSIS
    <Overview of script>

.DESCRIPTION
    <Brief description of script>

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
$CHECK_EXE = $true
$HASH_EXE = $true
$HASH_CONFIG = $true
$HASH_FOLDER = $false

$reintentos_ping = 5
$reintentos_exe = 10

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

            # Sacamos toda la informacion necesaria
            $appqueryservice = New-Object VMware.Hv.QueryServiceService
            $appdefn = New-Object VMware.Hv.QueryDefinition
            $appdefn.QueryEntityType = 'ApplicationInfo'
            $appdefn.SortBy = 'data.name'
            $appqueryResults = $appqueryService.QueryService_Create($HVServices, $appdefn)

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
        throw "No se ha podido recoger la informacion para el pod $($CPD)."
    }

    Write-Log $logFile
    $str = "POD[$($HVServer.Name)]"
    Write-Log $logFile $str Magenta

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

        $file_name_diurnos = "$($path_share)logs\$($farm.Data.Name)\diurnos.log"
        $file_name_nocturnos = "$($path_share)logs\$($farm.Data.Name)\nocturnos.log"

        if ((Test-Path $file_name_diurnos) -and (Test-Path $file_name_nocturnos)) {
            Write-Host "`tGRANJA DIRUNOS/NOCTURNOS" -ForegroundColor Yellow
            $generica = $false
        } else {
            Write-Host "`tGRANJA GENERICA" -ForegroundColor Yellow
            $generica = $true
        }

        $equipos_diurnos = $null
        $equipos_nocturnos = $null
        if (Test-Path $file_name_diurnos) { $equipos_diurnos = Get-Content $file_name_diurnos }
        if (Test-Path $file_name_nocturnos) { $equipos_nocturnos = Get-Content $file_name_nocturnos }

        $servers_app_check = @{}
        $servers_app_check_diurnos = @{}
        $servers_app_check_nocturnos = @{}
        $servers_exe_hash = @{}
        $servers_exe_hash_diurnos = @{}
        $servers_exe_hash_nocturnos = @{}
        $servers_configs_hash = @{}
        $servers_configs_hash_diurnos = @{}
        $servers_configs_hash_nocturnos = @{}
        $servers_folder_hash = @{}
        $servers_folder_hash_diurnos = @{}
        $servers_folder_hash_nocturnos = @{}
        $checks = @{}

        # check RDSHs advanced monitoring
        $queryService = New-Object VMware.Hv.QueryServiceService
        $defn = New-Object VMware.Hv.QueryDefinition
        $defn.queryEntityType = 'RDSServerSummaryView'
        $defn.Filter = New-Object VMware.Hv.QueryFilterEquals -Property @{'memberName'='base.farm'; 'value'=$($farm.Id)}
        $defn.SortBy = 'base.name'
        $queryResults = $queryService.QueryService_Create($HVServices, $defn)

        $farmDomain = $queryResults.Results[0].AgentData.DnsName.Split('.',2)[1]
        $sufijo = $dominios.$farmdomain.sufijo
        if (($dominios.$farmdomain.proxy) -and ($dominios.$farmdomain.proxy -ne $env:COMPUTERNAME)) {
            $str = "`tSKIPPED -> Se monitoriza en $($dominios.$farmdomain.proxy)"
            Write-Log $logFile $str Green
            $HVServices.QueryService.QueryService_DeleteAll()
            continue
        }
        elseif ((Soy-Proxy) -and ($dominios.$farmdomain.proxy -ne $env:COMPUTERNAME)) {
            $str = "`tSKIPPED -> Soy PROXY"
            Write-Log $logFile $str Green
            $HVServices.QueryService.QueryService_DeleteAll()
            continue
        }

        # consulta de datos en paralelo
        $queryResults.Results.Base.Name | Invoke-Parallel -ImportVariables -Throttle 50 {
            $rdsh_name = $_
            $rdsh_name_tmp = $_
            $checks.$rdsh_name = @{}
            $ping_retries = $reintentos_ping
            $checks.$rdsh_name.PING_RETRY = 0
            $checks.$rdsh_name.PING_IP = $null
            do {
                $pingresult = Test-Connection -ComputerName "$($rdsh_name_tmp)$($sufijo)" -Count 1 -ErrorAction SilentlyContinue
                if ($pingresult) {
                    $checks.$rdsh_name.PING = $true
                    $ExecutablePath = '\\' + $rdsh_name + '\' + ($app.ExecutionData.ExecutablePath -replace ":","$")
                    $StartFolder = '\\' + $rdsh_name + '\' + ($app.ExecutionData.StartFolder -replace ":","$")
                    if ($CHECK_EXE) {
                        try { # version con reintentos
                            $exe_retries = $reintentos_exe
                            $checks.$rdsh_name.EXE = $false
                            $checks.$rdsh_name.EXE_RETRY = 0
                            $checks.$rdsh_name.EXE_PINGS = @()
                            $checks.$rdsh_name.SF = @()
                            $checks.$rdsh_name.C = @()
                            $checks.$rdsh_name.GCI = @()
                            do {
                                if (Test-Path -ErrorAction Stop -PathType Leaf $ExecutablePath) {
                                    $checks.$rdsh_name.EXE = $true
                                } else {
								    $checks.$rdsh_name.EXE_RETRY++
								    $exe_retries--
                                    $ping_result = Test-Connection -ComputerName "$($rdsh_name)$($sufijo)" -Count 1 -ErrorAction SilentlyContinue
								    if ($ping_result) {
                                        $checks.$rdsh_name.EXE_PINGS += 'PING_OK'
                                        $checks.$rdsh_name.EXE_IP = $($ping_result.IPV4Address.IPAddressToString)
								    } else {
									    $checks.$rdsh_name.EXE_PINGS += 'PING_ERROR'
								    }
                                    try {
                                        if (Test-Path -PathType Container $StartFolder -ErrorAction Stop) {
                                            $checks.$rdsh_name.SF += 'SF_OK'
                                        } else {
                                            $checks.$rdsh_name.SF += 'SF_ERROR'
                                        }
                                    } catch {
                                        $checks.$rdsh_name.SF += 'SF_ERROR_N'
                                    }
                                    $tmp_folder = '\\' + $($ping_result.IPV4Address.IPAddressToString) + '\C$'
                                    try {
                                        if (Test-Path -PathType Container $tmp_folder -ErrorAction Stop) {
                                            $checks.$rdsh_name.C += 'C_OK'
                                        } else {
                                            $checks.$rdsh_name.C += 'C_ERROR'
                                        }
                                    } catch {
                                        $checks.$rdsh_name.C += 'C_ERROR_N'
                                    }
                                    $exe = $ExecutablePath.Split('\')[-1]
                                    if (Get-ChildItem -Path $StartFolder -Filter $exe -ErrorAction SilentlyContinue) {
                                        $checks.$rdsh_name.GCI += 'GCI_OK'
                                    } else {
                                        $checks.$rdsh_name.GCI += 'GCI_ERROR'
                                    }
                                    if ($exe_retries) {
                                        Start-Sleep -Seconds 1
                                        Clear-DnsClientCache
                                        if ($ping_result.IPV4Address) {
                                            $ExecutablePath = $ExecutablePath -replace "$($rdsh_name)$($sufijo)", "$($ping_result.IPV4Address.IPAddressToString)"
                                            $StartFolder = $StartFolder -replace "$($rdsh_name)$($sufijo)", "$($ping_result.IPV4Address.IPAddressToString)"
                                        }
                                    }
                                }
                            } while (($exe_retries -ne 0) -and !($checks.$rdsh_name.EXE))
                        } catch {
                            $checks.$rdsh_name.EXE_ERROR = " -> ERROR: $($_.Exception.Message)"
                            if ($_.Exception.Message -eq 'Access is denied') { $checks.$rdsh_name.EXE_ERROR += " [$([Environment]::UserDomainName)\$([Environment]::UserName)]" }
                        }
                    }
                    if ($HASH_EXE) {
                        try {
                            $checks.$rdsh_name.HASH_EXE = (Get-FileHash –Path $ExecutablePath -ErrorAction Stop).Hash
                        } catch {
                            $checks.$rdsh_name.HASH_EXE = 'ERROR'
                        }
                    }
                    if ($HASH_CONFIG) {
                        try {
                            $checks.$rdsh_name.HASH_CFG = (Get-ChildItem -Path $StartFolder -Filter "*.config" -Recurse -ErrorAction Stop | Get-FileHash -ErrorAction Stop | Sort-Object Hash).Hash
                        } catch {
                            $checks.$rdsh_name.HASH_CFG = 'ERROR'
                        }
                    }
                    if ($HASH_FOLDER) {
                        try {
                            $checks.$rdsh_name.HASH_FOLDER = (Get-ChildItem -Path $StartFolder -Recurse -ErrorAction Stop | Get-FileHash -ErrorAction Stop | Sort-Object Hash).Hash
                        } catch {
                            $checks.$rdsh_name.HASH_FOLDER = 'ERROR'
                        }
                    }
                } else {
                    $checks.$rdsh_name.PING_RETRY++
                    if (!$checks.$rdsh_name.PING_IP) {
                        $checks.$rdsh_name.PING_IP = (Resolve-DnsName -Type A $rdsh_name -ErrorAction SilentlyContinue | Select-Object -ExpandProperty IPAddress -ErrorAction SilentlyContinue) -join ', '
                    }
                    $checks.$rdsh_name.PING = $false
                    $ping_retries--
                    if ($ping_retries) {
                        Start-Sleep -Seconds 1
                        Clear-DnsClientCache
                        #if ($pingresult.IPV4Address.IPAddressToString) {
                        #    $rdsh_name_tmp = "$($pingresult.IPV4Address.IPAddressToString)"
                        #}
                    }
                }
            } while (($ping_retries -ne 0) -and !($checks.$rdsh_name.PING))
        }
        foreach ($rdsh in $queryResults.Results) {
            $ExecutablePath = '\\' + $rdsh.Base.Name + '\' + ($app.ExecutionData.ExecutablePath -replace ":","$")
            $StartFolder = '\\' + $rdsh.Base.Name + '\' + ($app.ExecutionData.StartFolder -replace ":","$")
            $str = "`tCheck[$([array]::IndexOf($queryResults.Results, $rdsh)+1)/$($queryResults.Results.Count)]:"

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

            # Computer exists?
            try {
                if ($dominios.Keys -contains $farmDomain) {
                    $file_credentials = "$($scriptPath)\credentials\$($dominios[$farmDomain].credenciales).xml"
                    $credentials = Import-Clixml -Path $file_credentials
                    $computer = Get-ADComputer $rdsh.Base.Name -Server $($farmDomain) -Credential $credentials -Properties ServicePrincipalName -ErrorAction Stop
                    $computer_spn = $computer.ServicePrincipalName
                } else {
                    $computer = Get-ADComputer $rdsh.Base.Name -Server $($farmDomain) -Properties ServicePrincipalName -ErrorAction Stop
                    $computer_spn = $computer.ServicePrincipalName            
                }
            } catch {
                $str += " $($rdsh.Base.Name) -> NO EXISTE [$($rdsh.Base.Name)] en [$($farmDomain)] -> $($farm.Data.Name) -> $($app.Data.Name) -> ERROR: $($_.Exception.Message)"
                Write-Log $logFile $str Red
                $str_final += "`r`n" + $str
                continue
            }

            # Computer attributes?
            # HOST
            if ( ($computer_spn -notcontains "HOST/$($rdsh.Base.Name)") -or ($computer_spn -notcontains "HOST/$($rdsh.AgentData.DnsName)") ) {
                $str += " $($rdsh.Base.Name) -> $($farm.Data.Name) -> $($app.Data.Name) -> falta SPN -> HOST"
                Write-Log $logFile $str Red
                $str_final += "`r`n" + $str
                continue
            }
            # RestrictedKrbHost
            if ( ($computer_spn -notcontains "RestrictedKrbHost/$($rdsh.Base.Name)") -or ($computer_spn -notcontains "RestrictedKrbHost/$($rdsh.AgentData.DnsName)") ) {
                $str += " $($rdsh.Base.Name) -> $($farm.Data.Name) -> $($app.Data.Name) -> falta SPN -> RestrictedKrbHost"
                Write-Log $logFile $str Red
                $str_final += "`r`n" + $str
                continue
            }
            # TERMSRV
            if ( ($computer_spn -notcontains "TERMSRV/$($rdsh.Base.Name)") -or ($computer_spn -notcontains "TERMSRV/$($rdsh.AgentData.DnsName)") ) {
                $str += " $($rdsh.Base.Name) -> $($farm.Data.Name) -> $($app.Data.Name) -> falta SPN -> TERMSRV"
                Write-Log $logFile $str Red
                $str_final += "`r`n" + $str
                continue
            }
            # WSMAN
            #if ( ($computer_spn -notcontains "WSMAN/$($rdsh.Base.Name)") -or ($computer_spn -notcontains "WSMAN/$($rdsh.AgentData.DnsName)") ) {
            #    $str += " $($rdsh.Base.Name) -> $($farm.Data.Name) -> $($app.Data.Name) -> falta SPN -> WSMAN"
            #    Write-Log $file_name $str Red
            #    $str_final += "`r`n" + $str
            #    continue
            #}

            # Test computer?
            $testping = $true
            if (!$checks.$($rdsh.Base.Name).PING) {
                $str += " $($rdsh.Base.Name) -> $($farm.Data.Name) -> $($app.Data.Name) -> SIN CONECTIVIDAD [$($checks.$($rdsh.Base.Name).PING_RETRY)] - $($checks.$($rdsh.Base.Name).PING_IP)"
                Write-Log $logFile $str Red
                $str_final += "`r`n" + $str
                $testping = $false
                #continue
            }
            if ($checks.$($rdsh.Base.Name).PING_RETRY -and $testping) {
                $str_debug = $str + " $($rdsh.Base.Name) -> $($farm.Data.Name) -> $($app.Data.Name) ->DEBUG - PING_RETRY<- [$($checks.$($rdsh.Base.Name).PING_RETRY)] - $($checks.$($rdsh.Base.Name).PING_IP)"
                Write-Log $logFileDebug $str_debug Red -WriteHost $false
            }

            # Check exe
            $str += " $($ExecutablePath)"
            if ($CHECK_EXE -and $testping) {
                if ($checks.$($rdsh.Base.Name).EXE) {
                    #$str += " -> OK [$($checks.$($rdsh.Base.Name).EXE_RETRY)] [$($checks.$($rdsh.Base.Name).EXE_PINGS  -join ', ')] [$($checks.$($rdsh.Base.Name).SF -join ', ')] [$($checks.$($rdsh.Base.Name).C -join ', ')] [$($checks.$($rdsh.Base.Name).GCI -join ', ')]"
                    $str += " -> OK [$($checks.$($rdsh.Base.Name).EXE_RETRY)]"
                    Write-Host $str -ForegroundColor Green
                    if ($checks.$($rdsh.Base.Name).EXE_RETRY) {
                        $str_debug = $str + " ->DEBUG - EXE_RETRY<- [$($checks.$($rdsh.Base.Name).EXE_RETRY)] - $($checks.$($rdsh.Base.Name).EXE_IP)"
                        Write-Log $logFileDebug $str_debug Red -WriteHost $false
                    }
                } else {
                    $str += " -> $($farm.Data.Name)"
                    $str += " -> $($app.Data.Name)"
                    #$str += " -> NO EXISTE [$($checks.$($rdsh.Base.Name).EXE_RETRY)] [$($checks.$($rdsh.Base.Name).EXE_PINGS  -join ', ')] [$($checks.$($rdsh.Base.Name).SF -join ', ')] [$($checks.$($rdsh.Base.Name).C -join ', ')] [$($checks.$($rdsh.Base.Name).GCI -join ', ')]"
                    $str += " -> NO EXISTE [$($checks.$($rdsh.Base.Name).EXE_RETRY)]"
                    Write-Log $logFile $str Red
                    $str_final += "`r`n" + $str
                }
                if ($checks.$($rdsh.Base.Name).EXE_ERROR) {
                    $str += $checks.$($rdsh.Base.Name).EXE_ERROR
                    Write-Log $logFile $str Red
                    $str_final += "`r`n" + $str
                }
            }

            # Hash exe:
            if ($HASH_EXE -and $testping) {
                $ExecutablePathHash = $checks.$($rdsh.Base.Name).HASH_EXE
                if (!$ExecutablePathHash) { $ExecutablePathHash = "NOEXEHASH" }
                if ($equipos_diurnos -contains $rdsh.Base.Name) {
                    if ($servers_exe_hash_diurnos.Keys -notcontains "$($ExecutablePathHash)") { $servers_exe_hash_diurnos."$($ExecutablePathHash)" = @() }
                    $servers_exe_hash_diurnos."$($ExecutablePathHash)" += "$($rdsh.Base.Name)"
                } elseif ($equipos_nocturnos -contains $rdsh.Base.Name) {
                    if ($servers_exe_hash_nocturnos.Keys -notcontains "$($ExecutablePathHash)") { $servers_exe_hash_nocturnos."$($ExecutablePathHash)" = @() }
                    $servers_exe_hash_nocturnos."$($ExecutablePathHash)" += "$($rdsh.Base.Name)"
                } else {
                    if ($servers_exe_hash.Keys -notcontains "$($ExecutablePathHash)") { $servers_exe_hash."$($ExecutablePathHash)" = @() }
                    $servers_exe_hash."$($ExecutablePathHash)" += "$($rdsh.Base.Name)"
                }
            }

            # Hash .config:
            if ($HASH_CONFIG -and $testping) {
                $ConfigsHash = $checks.($rdsh.Base.Name).HASH_CFG
                if (!$ConfigsHash) { $ConfigsHash = "NOCONFIGHASH" }
                if ($equipos_diurnos -contains $rdsh.Base.Name) {
                    if ($servers_configs_hash_diurnos.Keys -notcontains $ConfigsHash) { $servers_configs_hash_diurnos."$($ConfigsHash)" = @() }
                    $servers_configs_hash_diurnos."$($ConfigsHash)" += "$($rdsh.Base.Name)"
                } elseif ($equipos_nocturnos -contains $rdsh.Base.Name) {
                    if ($servers_configs_hash_nocturnos.Keys -notcontains $ConfigsHash) { $servers_configs_hash_nocturnos."$($ConfigsHash)" = @() }
                    $servers_configs_hash_nocturnos."$($ConfigsHash)" += "$($rdsh.Base.Name)"
                } else {
                    if ($servers_configs_hash.Keys -notcontains $ConfigsHash) { $servers_configs_hash."$($ConfigsHash)" = @() }
                    $servers_configs_hash."$($ConfigsHash)" += "$($rdsh.Base.Name)"
                }
            }

            # Hash folder: muy lento
            if ($HASH_FOLDER -and $testping) {
                $StartFolderHash = $checks.($rdsh.Base.Name).HASH_FOLDER
                if (!$StartFolderHash) { $StartFolderHash = "NOFOLDERHASH" }
                if ($equipos_diurnos -contains $rdsh.Base.Name) {
                    if ($servers_folder_hash_diurnos.Keys -notcontains $StartFolderHash) { $servers_folder_hash_diurnos."$StartFolderHash" = @() }
                    $servers_folder_hash_diurnos."$($StartFolderHash.Hash)" += "$($rdsh.Base.Name)"
                } elseif ($equipos_nocturnos -contains $rdsh.Base.Name) {
                    if ($servers_folder_hash_nocturnos.Keys -notcontains $StartFolderHash) { $servers_folder_hash_nocturnos."$StartFolderHash" = @() }
                    $servers_folder_hash_nocturnos."$($StartFolderHash.Hash)" += "$($rdsh.Base.Name)"
                } else {
                    if ($servers_folder_hash.Keys -notcontains $StartFolderHash) { $servers_folder_hash."$StartFolderHash" = @() }
                    $servers_folder_hash."$($StartFolderHash.Hash)" += "$($rdsh.Base.Name)"
                }
            }

        }

        if ((Test-Path $file_name_diurnos) -and (Test-Path $file_name_nocturnos)) {

            # Hash Executable:
            $str = "`t$($app.Data.Name) @ $($farm.Data.Name)"
            if ($servers_exe_hash_diurnos.Keys.Count -and ($servers_exe_hash_diurnos.Keys.Count -gt 1)) {
                $str += " -> HASH exe problems [diurnos][$($equipos_diurnos.Count)]"
                Write-Log $logFile $str Red
                $str_final += "`r`n" + $str
                $contador_hash = 0
                foreach ($key in $servers_exe_hash_diurnos.Keys) {
                    $contador_hash += ($servers_exe_hash_diurnos.$key.Count)
                    $str = "`t`tHASH[$($servers_exe_hash_diurnos.$key.Count)]: $($servers_exe_hash_diurnos.$key -join ', ')"
                    Write-Log $logFile $str Red
                    $str_final += "`r`n" + $str
                }
                if ($contador_hash -ne $equipos_diurnos.Count) {
                    $str = "`t`tERROR EQUIPOS [diurnos][$($equipos_diurnos.Count)/$($contador_hash)]"
                    Write-Log $logFile $str Red
                    $str_final += "`r`n" + $str
                }
            }
            $str = "`t$($app.Data.Name) @ $($farm.Data.Name)"
            if ($servers_exe_hash_nocturnos.Keys.Count -and ($servers_exe_hash_nocturnos.Keys.Count -gt 1)) {
                $str += " -> HASH exe problems [nocturnos][$($equipos_nocturnos.Count)]"
                Write-Log $logFile $str Red
                $str_final += "`r`n" + $str
                $contador_hash = 0
                foreach ($key in $servers_exe_hash_nocturnos.Keys) {
                    $contador_hash += ($servers_exe_hash_nocturnos.$key.Count)
                    $str = "`t`tHASH[$($servers_exe_hash_nocturnos.$key.Count)]: $($servers_exe_hash_nocturnos.$key -join ', ')"
                    Write-Log $logFile $str Red
                    $str_final += "`r`n" + $str
                }
                if ($contador_hash -ne $equipos_nocturnos.Count) {
                    $str = "`t`tERROR EQUIPOS [nocturnos][$($equipos_nocturnos.Count)/$($contador_hash)]"
                    Write-Log $logFile $str Red
                    $str_final += "`r`n" + $str
                }
            }

            # Hash .config:
            $str = "`t$($app.Data.Name) @ $($farm.Data.Name)"
            if ($servers_configs_hash_diurnos.Keys.Count -and ($servers_configs_hash_diurnos.Keys.Count -gt 1)) {
                $str += " -> HASH configs problems [diurnos][$($equipos_diurnos.Count)]"
                Write-Log $logFile $str Red
                $str_final += "`r`n" + $str
                $contador_hash = 0
                foreach ($key in $servers_configs_hash_diurnos.Keys) {
                    $contador_hash += ($servers_configs_hash_diurnos.$key.Count)
                    $str = "`t`tHASH[$($servers_configs_hash_diurnos.$key.Count)]: $($servers_configs_hash_diurnos.$key -join ', ')"
                    Write-Log $logFile $str Red
                    $str_final += "`r`n" + $str
                }
                if ($contador_hash -ne $equipos_diurnos.Count) {
                    $str = "`t`tERROR EQUIPOS [diurnos][$($equipos_diurnos.Count)/$($contador_hash)]"
                    Write-Log $logFile $str Red
                    $str_final += "`r`n" + $str
                }
            }
            $str = "`t$($app.Data.Name) @ $($farm.Data.Name)"
            if ($servers_configs_hash_nocturnos.Keys.Count -and ($servers_configs_hash_nocturnos.Keys.Count -gt 1)) {
                $str += " -> HASH configs problems [nocturnos][$($equipos_nocturnos.Count)]"
                Write-Log $logFile $str Red
                $str_final += "`r`n" + $str
                $contador_hash = 0
                foreach ($key in $servers_configs_hash_nocturnos.Keys) {
                    $contador_hash += ($servers_configs_hash_nocturnos.$key.Count)
                    $str = "`t`tHASH[$($servers_configs_hash_nocturnos.$key.Count)]: $($servers_configs_hash_nocturnos.$key -join ', ')"
                    Write-Log $logFile $str Red
                    $str_final += "`r`n" + $str
                }
                if ($contador_hash -ne $equipos_nocturnos.Count) {
                    $str = "`t`tERROR EQUIPOS [nocturnos][$($equipos_nocturnos.Count)/$($contador_hash)]"
                    Write-Log $logFile $str Red
                    $str_final += "`r`n" + $str
                }
            }

            # Hash folder:
            $str = "`t$($app.Data.Name) @ $($farm.Data.Name)"
            if ($servers_folder_hash_diurnos.Keys.Count -and ($servers_folder_hash_diurnos.Keys.Count -gt 1)) {
                $str += " -> HASH folder problems [diurnos][$($equipos_diurnos.Count)]"
                Write-Log $logFile $str Red
                $str_final += "`r`n" + $str
                $contador_hash = 0
                foreach ($key in $servers_folder_hash_diurnos.Keys) {
                    $contador_hash += ($servers_folder_hash_diurnos.$key.Count)
                    $str = "`t`tHASH[$($servers_folder_hash_diurnos.$key.Count)]: $($servers_folder_hash_diurnos.$key -join ', ')"
                    Write-Log $logFile $str Red
                    $str_final += "`r`n" + $str
                }
                if ($contador_hash -ne $equipos_diurnos.Count) {
                    $str = "`t`tERROR EQUIPOS [diurnos][$($equipos_diurnos.Count)/$($contador_hash)]"
                    Write-Log $logFile $str Red
                    $str_final += "`r`n" + $str
                }
            }
            $str = "`t$($app.Data.Name) @ $($farm.Data.Name)"
            if ($servers_folder_hash_nocturnos.Keys.Count -and ($servers_folder_hash_nocturnos.Keys.Count -gt 1)) {
                $str += " -> HASH folder problems [nocturnos][$($equipos_nocturnos.Count)]"
                Write-Log $logFile $str Red
                $str_final += "`r`n" + $str
                $contador_hash = 0
                foreach ($key in $servers_folder_hash_nocturnos.Keys) {
                    $contador_hash += ($servers_folder_hash_nocturnos.$key.Count)
                    $str = "`t`tHASH[$($servers_folder_hash_nocturnos.$key.Count)]: $($servers_folder_hash_nocturnos.$key -join ', ')"
                    Write-Log $logFile $str Red
                    $str_final += "`r`n" + $str
                }
                if ($contador_hash -ne $equipos_nocturnos.Count) {
                    $str = "`t`tERROR EQUIPOS [nocturnos][$($equipos_nocturnos.Count)/$($contador_hash)]"
                    Write-Log $logFile $str Red
                    $str_final += "`r`n" + $str
                }
            }

        } else {

            # Hash Executable:
            $str = "`t$($farm.Data.Name) :  $($app.Data.Name)"
            if ($servers_exe_hash.Keys.Count -and ($servers_exe_hash.Keys.Count -gt 1)) {
                $str += " -> HASH exe problems [$($queryResults.Results.Count)]"
                Write-Log $logFile $str Red
                $str_final += "`r`n" + $str
                $contador_hash = 0
                foreach ($key in $servers_exe_hash.Keys) {
                    $contador_hash += ($servers_exe_hash.$key.Count)
                    $str = "`t`tHASH[$($servers_exe_hash.$key.Count)]: $($servers_exe_hash.$key -join ', ')"
                    Write-Log $logFile $str Red
                    $str_final += "`r`n" + $str
                }
                if ($contador_hash -ne $queryResults.Results.Count) {
                    $str = "`t`tERROR EQUIPOS [$($queryResults.Results.Count)/$($contador_hash)]"
                    Write-Log $logFile $str Red
                    $str_final += "`r`n" + $str
                }
            }

            # Hash .config:
            $str = "`t$($farm.Data.Name) :  $($app.Data.Name)"
            if ($servers_configs_hash.Keys.Count -and ($servers_configs_hash.Keys.Count -gt 1)) {
                $str += " -> HASH configs problems [$($queryResults.Results.Count)]"
                Write-Log $logFile $str Red
                $str_final += "`r`n" + $str
                $contador_hash = 0
                foreach ($key in $servers_configs_hash.Keys) {
                    $contador_hash += ($servers_configs_hash.$key.Count)
                    $str = "`t`tHASH[$($servers_configs_hash.$key.Count)]: $($servers_configs_hash.$key -join ', ')"
                    Write-Log $logFile $str Red
                    $str_final += "`r`n" + $str
                }
                if ($contador_hash -ne $queryResults.Results.Count) {
                    $str = "`t`tERROR EQUIPOS [$($queryResults.Results.Count)/$($contador_hash)]"
                    Write-Log $logFile $str Red
                    $str_final += "`r`n" + $str
                }
            }

            # Hash folder:
            $str = "`t$($farm.Data.Name) :  $($app.Data.Name)"
            if ($servers_folder_hash.Keys.Count -and ($servers_folder_hash.Keys.Count -gt 1)) {
                $str += " -> HASH folder problems [$($queryResults.Results.Count)]"
                Write-Log $logFile $str Red
                $str_final += "`r`n" + $str
                $contador_hash = 0
                foreach ($key in $servers_folder_hash.Keys) {
                    $contador_hash += ($servers_folder_hash.$key.Count)
                    $str = "`t`tHASH[$($servers_folder_hash.$key.Count)]: $($servers_folder_hash.$key -join ', ')"
                    Write-Log $logFile $str Red
                    $str_final += "`r`n" + $str
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
			    Write-Event-Log -file $logFileError -message $str_final -event 1006 -type 'Warning' -pod $CPD
            } else {
				Write-Event-Log -file $logFileError -message $str_final -event 1006 -pod $CPD
            }
        }

        #SACAMOS UN IC PARA COMPROBAR ARCHIVOS PARA EL TAG FILECHECK y CERTCHECK
        $rdshCheck = $queryResults.Results[$(Get-Random -Maximum $queryResults.Results.Count)].Base.Name
        #$appFolder = '\\' + $rdshCheck + $sufijo + '\' + ($app.ExecutionData.StartFolder -replace ":","$")
        $appFolder = "\\$($rdshCheck)\$($app.ExecutionData.StartFolder -replace ":","$")"

        $str_final = ''
        if ($tags -match '^FILECHECK.*') {
            $fileCheckTags = @()
            $tags -match '^FILECHECK\[(.*)\]' | ForEach-Object {
                $_ -match 'FILECHECK\[(.*)\]' | Out-Null
                $check = $matches[1]
                $fileToCheck = ($check -split '\|\|')[0]
                $wordToFind  = ($check -split '\|\|')[1]
                if (($fileToCheck) -and ($wordToFind)) {
                    try {
                        if ([System.IO.Path]::IsPathRooted($fileToCheck)){
                            # El string es una ruta, se intenta separar la carpeta del nombre del archivo
                            try{ 
                                $filefolder = "\\$($rdshCheck)\$((Split-Path $filetocheck) -replace ':','$')"
                                $filetocheck = Split-Path $filetocheck -leaf
                                if (!(Test-Path $filefolder)){
                                    $str = "`t-FILECHECK ERROR[$($rdshCheck)]: No se encuentra carpeta [$($filefolder)] en $($rdshCheck)"
                                    $str_final += "`r`n" + $str
                                    Write-Log $logFile $str red
                                    return
                                }
                            } catch {
                                throw
                            }
                        } else {
                            # El string es un archivo, se buscará en carpeta configurada en la app de Horizon
                            $filefolder = $appfolder
                        }
                        # Se construye objeto. Se implementa 'appFolder', ya que puede ser la original de la app o una especificada en el tag FILECHECK
                        $fileCheckTags += New-Object PSObject -Property @{
                            'fileToCheck' = $fileToCheck
                            'wordToFind' = $wordToFind
                            'appFolder' = $filefolder
                        }
                    } catch {
                        # No se pudo comprobar si es ruta o no
                        $str = "`t-FILECHECK ERROR: Sintaxis incorrecta en [$($fileToCheck)]"
                        Write-Log $logFile $str red
                        Write-Log $logFileError $str red -WriteHost $false
                    }
                }
                else {
                    # el tag FILECHECK no tiene la sintaxis de "<[Ruta]archivo>||<PalabraABuscar>"
                    $str = "`tFILECHECK ERROR: Sintaxis incorrecta en [$($matches[1])]"
                    #$str_final += "`r`n" + $str
                    Write-Log $logFile $str red
                    Write-Log $logFileError $str red
                }
            }

            $str = "`tSe chequean FILES en equipo $($rdshCheck)"
            #Write-Log $logFile  $str
            #$str = "Ubicacion: $($appFolder)"
            #Write-Log $logFile  $str

            foreach ($fileCheckTag in $fileCheckTags) {
                $str = "`tArchivo: $($fileCheckTag.fileToCheck)"
                #Write-Log $logFile  $str
                $str = "`tPalabra clave: $($fileCheckTag.wordToFind)"
                #Write-Log $logFile  $str
                $file = Get-ChildItem -Path $fileCheckTag.appFolder -Filter "$($fileCheckTag.fileToCheck)" -Recurse
                if ($file.count -eq 0) {
                    $str = "`t-FILECHECK ERROR[$($rdshCheck)]: No se encuentra archivo $($fileCheckTag.fileToCheck) en [$($fileCheckTag.appFolder)]"
                    $str_final += "`r`n" + $str
                    Write-Log $logFile $str red
                }
                elseif ($file.count -gt 1) {
                    $str = "`t-FILECHECK ERROR[$($rdshCheck)]: Se han encontrado varios archivos [$($fileCheckTag.fileToCheck)] en [$($fileCheckTag.appFolder)]"
                    $str_final += "`r`n" + $str
                    Write-Log $logFile $str red
                }
                else {
                    if (!((Get-Content $file.FullName) -match "$($fileCheckTag.wordToFind)")) {
                        $str = "`t-FILECHECK ERROR[$($rdshCheck)]: No se encuentra '$($fileCheckTag.wordToFind)' en archivo [$($fileCheckTag.appFolder)\$($fileCheckTag.fileToCheck)]"
                        $str_final += "`r`n" + $str
                        Write-Log $logFile $str red
                    }
                    else {
                        $str = "`t-FILECHECK OK[$($rdshCheck)]: '$($fileCheckTag.wordToFind)' en archivo $($fileCheckTag.fileToCheck)"
                        Write-Log $logFile $str
                    }
                }
                #Write-Log $logFile
            }

            if (![string]::IsNullOrEmpty($str_final)) {
                $str_final = "$($app.Data.Name) - $($app.Data.DisplayName) - $($app.Data.Enabled) - $($farm.Data.Name)" + "$($str_final)"
                if ($tags -match '^8x5') {
                    Write-Event-Log -file $logFileError -message $str_final -event 1008 -type 'Warning' -pod $CPD
                } else {
                    Write-Event-Log -file $logFileError -message $str_final -event 1008 -pod $CPD
                }
            }
        }

        $str_final = ''
        if ($tags -match '^CERTCHECK.*') {
            $certCheckTags = @()
            $tags -match '^CERTCHECK\[(.*)\]' | ForEach-Object {
                $_ -match 'CERTCHECK\[(.*)\]' | Out-Null
                $certCheckTags += $matches[1]
            }

            $str = "`tSe chequean CERTIFICADOS en equipo $($rdshCheck)"
            #Write-Log $logFile  $str

            foreach ($certCheckTag in $certCheckTags) {
                try {
                    #$certRO = [System.Security.Cryptography.X509Certificates.OpenFlags]"ReadOnly"
                    #$certPath=  [System.Security.Cryptography.X509Certificates.StoreLocation]"LocalMachine"
                    #$store = New-Object System.Security.Cryptography.X509Certificates.X509Store("\\$rdshCheck\my",$certPath)
                    #$store.Open($certRO)
                    #$cert = ($store.Certificates | Where-Object { ($_.FriendlyName -eq $certCheckTag) -and ($_.NotAfter -gt (Get-Date)) }) | Sort-Object -Descending notafter | Select-Object -First 1
                    $results = Invoke-Command -ComputerName "$($rdshCheck).$($farmDomain)" -Credential $credHV {
                        $results = @{}
                        $certObject = @()
                        $certs = ls Cert:localmachine\my
                        $cert = $certs | Where-Object { ($_.FriendlyName -eq $using:certCheckTag) }
                        if ($cert) {
                            $certObject += New-Object PSObject -Property @{
                                Subject = $cert.Subject
                                Issuer = $cert.Issuer
                                Thumbprint = $cert.Thumbprint
                                FriendlyName = $cert.FriendlyName
                                NotAfter = $cert.NotAfter
                                NotBefore = $cert.NotBefore
                                uniquekeycontainername = $cert.PrivateKey.cspkeycontainerinfo.uniquekeycontainername
                            }
                        }
                        $results.CERT = $certObject
                        return $results
                    }
                    $cert = $results.CERT
                    if ($cert.count -eq 0) {
                        $str = "`t-CERTCHECK ERROR[$($rdshCheck)]: No se encuentra certificado '$($certCheckTag)' en equipo $($rdshCheck)"
                        $str_final += "`r`n" + $str
                        Write-Log $logFile $str red
                        Write-Event-Log -file $logFileError -message $str_final -event 1009 -pod $CPD
                    }
                    else {
                        $daysToExpire = ($cert.NotAfter - (Get-Date)).days
                        if ($daysToExpire -lt 15) {
                            $str = "`tCERTCHECK ERROR[$($rdshCheck)] - Certificado '$($certCheckTag)': Faltan $($daysToExpire) dias para caducar"
                            $str_final += "`r`n" + $str
                            Write-Log $logFile $str
                            Write-Event-Log -file $logFileError -message $str_final -event 1009 -pod $CPD
                        }
                        elseif ($daysToExpire -lt 30) {
                            $str = "`t-CERTCHECK WARNING[$($rdshCheck)] - Certificado '$($certCheckTag)': Faltan $($daysToExpire) dias para caducar"
                            $str_final += "`r`n" + $str
                            Write-Log $logFile $str
                            Write-Event-Log -file $logFileError -message $str_final -event 1009 -type 'Warning' -pod $CPD
                        }
                        else {
                            $str = "`t-CERTCHECK OK[$($rdshCheck)]: Certificado '$($certCheckTag)' valido hasta $($cert.NotAfter.ToString("dd/MM/yyyy")) - Faltan $($daysToExpire) dias"
                            Write-Log $logFile $str
                        }
                        if (!($cert.uniquekeycontainername)) {
                            $str = "`tCERTCHECK ERROR[$($rdshCheck)] - Certificado '$($certCheckTag)': No se encuentra clave privada"
                            $str_final += "`r`n" + $str
                            Write-Log $logFile $str
                            Write-Event-Log -file $logFileError -message $str_final -event 1009 -pod $CPD
                        }
                    }
                } catch {
                    $str = "`t-CERTCHECK ERROR: ERROR al sacar el certificado '$($certCheckTag)' en equipo $($rdshCheck): $($_.Exception.Message)"
                    Write-Log $logFile $str Red
                    Write-Log $logFileError $str -WriteHost $false
                }
            }
        }

        # Comprobamos servicio windows update (debe estar parado)
        $servicename = 'wuauserv'
        $str_final = ''

        try {
            $service = Get-Service $servicename -ComputerName "$($rdshCheck)$($sufijo)"
            if ($service.Status -ne 'Stopped') {
                $str = "`t-WINDOWS UPDATE CHECK ERROR[$($rdshCheck)]: El servicio no se encuentra parado. (Estado actual: [$($service.Status)])"
                $str_final += "`r`n" + $str
                Write-Log $logFile $str red
            }
            if ($service.StartType -ne 'Manual' -and $service.StartType -ne 'Disabled') {
                $str = "`t-WINDOWS UPDATE CHECK ERROR[$($rdshCheck)]: El arranque del servicio no esta establecido como manual ni deshabilitado. (Configuracion actual: [$($service.StartType)])"
                $str_final += "`r`n" + $str
                Write-Log $logFile $str red
            }
        } catch [Microsoft.PowerShell.Commands.ServiceCommandException] {
            $str = "`t-WINDOWS UPDATE CHECK ERROR[$($rdshCheck)]: - El servicio [$($servicename)] de la App [$($app.Data.DisplayName)@$($farm.Data.Name)] no existe en el IC."
            Write-Log $logFile $str Red
            $str_final += "`r`n" + $str
        } catch {
            $str = "`t-WINDOWS UPDATE CHECK ERROR[$($rdshCheck)]: No se pudo gestionar servicio [$($servicename)] de la App [$($app.Data.DisplayName)@$($farm.Data.Name)]: $($_.Exception.Message)"
            Write-Log $logFile $str Red
            $str_final += "`r`n" + $str
        }

        if ([string]::IsNullOrEmpty($str_final)) {
            $str = "`t-WINDOWS UPDATE CHECK OK[$rdshCheck]: Servicio [$($service.Status)] y arranque [$($service.StartType)]. "
            Write-Log $logfile $str
        } else {
            $str_final = "$($app.Data.Name) - $($app.Data.DisplayName) - $($app.Data.Enabled) - $($farm.Data.Name)" + "$($str_final)"
            if ($tags -match '^8x5') {
                Write-Event-Log -file $logFileError -message $str_final -event 1018 -type 'Warning' -pod $CPD
            } else {
                Write-Event-Log -file $logFileError -message $str_final -event 1018 -pod $CPD
            }
        }


        $HVServices.QueryService.QueryService_DeleteAll()
    }
    $str = "Total: $($contador)/$($apps.Count)"
    Write-Log $logFile $str Yellow
    Write-Log $logFile
    $HVServices.QueryService.QueryService_DeleteAll()

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

#cfg
$path_share = '\\dominioprincipal.com\shares\HORIZON7\'

#cfg


# CFG
$cfgs = "$scriptPath\cfg"
if (!(Test-Path $cfgs -pathType Container)) {
	New-Item -ItemType directory -Path $cfgs | Out-Null
}

$file_pod_server = "$($path_share)$($CPD)\cfg\pod"
$file_pod_server_final = "$($scriptPath)\cfg\$($CPD)_pod"
$hash_pod_server = (Get-FileHash -Path $file_pod_server -ErrorAction SilentlyContinue).Hash
$hash_pod_server_final = (Get-FileHash -Path $file_pod_server_final -ErrorAction SilentlyContinue).Hash
if (Test-Path $file_pod_server) {
    if ($hash_pod_server -ne $hash_pod_server_final) {
        try {
            Copy-Item -Path $file_pod_server -Destination $file_pod_server_final -Force -ErrorAction Stop
            $copiado = $true
        } catch {
            $str = "ERROR al copiar: $($file_pod_server_final) - $($_.Exception.Message)"
            Write-Log $file_name_error $str
        }
    }
} else {
    $str = "ERROR al acceder [$($file_pod_server)]"
    Write-Log $file_name $str Red
    Write-Event-Log $file_name_error $str 1012 'Warning'
}
if (Test-Path $file_pod_server_final) {
    try {
        $pod_servers = ([array](Get-Content $file_pod_server_final))
        $pod_server = ([array](Get-Content $file_pod_server_final))[0]
    } catch {
        $str = "Conection Server: $($HVServer.Name) CONNECTION ERROR [$pod_server]: $($_.Exception.Message) - $($file_pod_server_final) - $($pod_servers)"
        Write-Log $file_name_error $str
        exit
    }
} else {
    $str = "ERROR al acceder [$($file_pod_server_final)]"
    Write-Log $file_name $str Red
    Write-Event-Log $file_name_error $str 1012
    exit
}
$str = "POD: $($pod_servers -join ', ') - $($file_pod_server_final)"
Write-Log $file_name $str Yellow

$file_vcenter_server = "$($path_share)$($CPD)\cfg\vcenter"
$file_vcenter_server_final = "$($scriptPath)\cfg\$($CPD)_vcenter"
$hash_vcenter_server = (Get-FileHash -Path $file_vcenter_server -ErrorAction SilentlyContinue).Hash
$hash_vcenter_server_final = (Get-FileHash -Path $file_vcenter_server_final -ErrorAction SilentlyContinue).Hash
if (Test-Path $file_vcenter_server) {
    if ($hash_vcenter_server -ne $hash_vcenter_server_final) {
        try {
            Copy-Item -Path $file_vcenter_server -Destination $file_vcenter_server_final -Force -ErrorAction Stop
            $copiado = $true
        } catch {
            $str = "ERROR al copiar: $($file_vcenter_server_final) - $($_.Exception.Message)"
            Write-Log $file_name_error $str
        }
    }
} else {
    $str = "ERROR al acceder [$($file_vcenter_server)]"
    Write-Log $file_name $str Red
    Write-Event-Log $file_name_error $str 1012 'Warning'
}
if (Test-Path $file_vcenter_server_final) {
    $vcenter_server = ([array](Get-Content $file_vcenter_server_final))[0]
} else {
    $str = "ERROR al acceder [$($file_vcenter_server_final)]"
    Write-Log $file_name $str Red
    Write-Event-Log $file_name_error $str 1012
    exit
}
$str = "vCenter: $($vcenter_server) - $($file_vcenter_server_final)"
Write-Log $file_name $str Yellow

$file_appvolumes_server = "$($path_share)$($CPD)\cfg\appvolumes"
$file_appvolumes_server_final = "$($scriptPath)\cfg\$($CPD)_appvolumes"
$hash_appvolumes_server = (Get-FileHash -Path $file_appvolumes_server -ErrorAction SilentlyContinue).Hash
$hash_appvolumes_server_final = (Get-FileHash -Path $file_appvolumes_server_final -ErrorAction SilentlyContinue).Hash
if (Test-Path $file_appvolumes_server) {
    if ($hash_appvolumes_server -ne $hash_appvolumes_server_final) {
        try {
            Copy-Item -Path $file_appvolumes_server -Destination $file_appvolumes_server_final -Force -ErrorAction Stop
            $copiado = $true
        } catch {
            $str = "ERROR al copiar: $($file_appvolumes_server_final) - $($_.Exception.Message)"
            Write-Log $file_name_error $str
        }
    }
} else {
    $str = "ERROR al acceder [$($file_appvolumes_server)]"
    Write-Log $file_name $str Red
    Write-Event-Log $file_name_error $str 1012 'Warning'
}
if (Test-Path $file_appvolumes_server_final) {
    $appvolumes_server = ([array](Get-Content $file_appvolumes_server_final))[0]
} else {
    $str = "ERROR al acceder [$($file_appvolumes_server_final)]"
    Write-Log $file_name $str Red
    Write-Event-Log $file_name_error $str 1012
    exit
}
$str = "AppVolumes: $($appvolumes_server) - $($file_appvolumes_server_final)"
Write-Log $file_name $str Yellow

$file_credentials = "$($scriptPath)\credentials\$([Environment]::UserDomainName)_$([Environment]::UserName).xml"
try {
    $encryptedPassword = Import-Clixml -Path $file_credentials
} catch {
    $str = "ERROR al cargar las credenciales [$($file_credentials)]"
    Write-Log $file_name $str Red
    $str = "$($_.Exception.Message)"
    Write-Log $file_name $str Red
    exit
}

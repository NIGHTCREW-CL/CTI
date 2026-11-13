#requires -Version 5.1
<#
.SYNOPSIS
Comprueba la version instalada de Outlook clasico frente a CVE-2026-124194.
.DESCRIPTION
Solo consulta el inventario Click-to-Run y la existencia de OUTLOOK.EXE.
No abre Outlook ni mensajes, modifica el registro o realiza conexiones de red.
Los resultados se basan en las versiones publicadas el 10 de noviembre de 2026.
NOT VULNERABLE significa que la version cumple el umbral cubierto por el script.
#>

function Get-OutlookPatchAssessment {
    param(
        [version]$Version,
        [string]$ProductIds,
        [string]$Channel
    )

    if (-not $Version -or $Version.Major -ne 16 -or
        $Version.Minor -ne 0 -or $Version.Revision -lt 0 -or
        [string]::IsNullOrWhiteSpace($ProductIds)) {
        throw 'METADATOS_INVALIDOS'
    }

    # No mezclar umbrales si el inventario contiene varias familias cubiertas.
    $families = @()
    $ids = @($ProductIds -split '[,;\s]+' | Where-Object { $_ })
    if ($ids -match '^(ProPlus|Standard|Outlook)2024Volume$') { $families += 'LTSC2024' }
    if ($ids -match '^(ProPlus|Standard|Outlook)2021Volume$') { $families += 'LTSC2021' }
    if ($ids -match '^O365(ProPlus|Business).*Retail$') { $families += 'M365' }
    if ($ids -match '^(Outlook|HomeBusiness|Professional|ProPlus|Standard)202(1|4)Retail$') {
        $families += 'RETAIL'
    }
    if ($families.Count -eq 0) { throw 'EDICION_NO_CUBIERTA' }
    if ($families.Count -gt 1) { throw 'EDICION_AMBIGUA' }

    switch ($families[0]) {
        'LTSC2024' {
            if ($Version.Build -ne 17932) { throw 'RAMA_NO_CUBIERTA' }
            $low = [version]'16.0.17932.21140'
            $high = $low
        }
        'LTSC2021' {
            if ($Version.Build -ne 14334) { throw 'RAMA_NO_CUBIERTA' }
            $low = [version]'16.0.14334.21048'
            $high = $low
        }
        'M365' {
            switch ($Version.Build) {
                20527 { $low = [version]'16.0.20527.20192'; $high = [version]'16.0.20527.20196' }
                20430 { $low = [version]'16.0.20430.20262'; $high = [version]'16.0.20430.20264' }
                20326 { $low = [version]'16.0.20326.20318'; $high = [version]'16.0.20326.20320' }
                default { throw 'RAMA_NO_CUBIERTA' }
            }
            # Usar GUID completos y comparar el canal, sin mostrar su URL.
            if ($Channel) {
                $channelId = ($Channel.Trim().TrimEnd('/') -split '/')[-1]
                switch ($channelId) {
                    '7ffbc6bf-bc32-4f92-8982-f9dd17fd3114' { $high = $low }
                    '55336b82-a18d-4dd6-b5f6-9e5095c314a6' {
                        if ($Version.Build -eq 20527) {
                            $low = [version]'16.0.20527.20194'
                            $high = $low
                        } else { $low = $high }
                    }
                    '492350f6-3a01-4f97-b9c0-c7c6ddf67d60' {
                        if ($Version.Build -ne 20527) { throw 'RAMA_CANAL_NO_CUBIERTA' }
                        $low = $high
                    }
                    default { throw 'CANAL_NO_CUBIERTO' }
                }
            }
        }
        'RETAIL' {
            if ($Version.Build -ne 20527) { throw 'RAMA_NO_CUBIERTA' }
            $low = [version]'16.0.20527.20196'
            $high = $low
        }
    }

    if ($Version -lt $low) { return 'VULNERABLE' }
    if ($Version -ge $high) { return 'NOT VULNERABLE' }
    return 'UNKNOWN'
}

& {
    $cve = 'CVE-2026-124194'
    $ErrorActionPreference = 'Stop'
    $keys = New-Object 'System.Collections.Generic.List[Microsoft.Win32.RegistryKey]'
    try {
        if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
            throw 'SO_NO_COMPATIBLE'
        }
        $hive = [Microsoft.Win32.RegistryHive]::LocalMachine
        $view = if ([Environment]::Is64BitOperatingSystem) {
            [Microsoft.Win32.RegistryView]::Registry64
        } else { [Microsoft.Win32.RegistryView]::Registry32 }

        $registry = [Microsoft.Win32.RegistryKey]::OpenBaseKey($hive, $view)
        $keys.Add($registry)
        $inventory = $registry.OpenSubKey('SOFTWARE\Microsoft\Office\ClickToRun\Inventory\Office\16.0')
        if (-not $inventory) { throw 'SIN_INVENTARIO_C2R' }
        $keys.Add($inventory)
        $version = $null
        if (-not [version]::TryParse([string]$inventory.GetValue('OfficePackageVersion'), [ref]$version)) {
            throw 'METADATOS_INVALIDOS'
        }
        $productIds = [string]$inventory.GetValue('OfficeProductReleaseIds')

        $paths = @()
        $views = @([Microsoft.Win32.RegistryView]::Registry32, $view) | Select-Object -Unique
        foreach ($registryView in $views) {
            $baseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey($hive, $registryView)
            $keys.Add($baseKey)
            $appPath = $baseKey.OpenSubKey('SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\OUTLOOK.EXE')
            if ($appPath) {
                $keys.Add($appPath)
                $paths += [string]$appPath.GetValue('')
            }
        }

        $channel = ''
        $configuration = $registry.OpenSubKey('SOFTWARE\Microsoft\Office\ClickToRun\Configuration')
        if ($configuration) {
            $keys.Add($configuration)
            $installPath = [string]$configuration.GetValue('InstallationPath')
            if ($installPath) { $paths += Join-Path $installPath 'root\Office16\OUTLOOK.EXE' }
            $channel = [string]$configuration.GetValue('UpdateChannel')
            if (-not $channel) { $channel = [string]$configuration.GetValue('CDNBaseUrl') }
        }

        $installed = $false
        foreach ($path in $paths) {
            # Evitar que metadatos con rutas UNC provoquen accesos de red.
            if ($path -match '^[A-Za-z]:[\\/](?![\\/])' -and
                (Test-Path -LiteralPath $path -PathType Leaf)) {
                $installed = $true
                break
            }
        }
        if (-not $installed) { throw 'OUTLOOK_CLASSIC_NO_CONFIRMADO' }

        $result = Get-OutlookPatchAssessment -Version $version -ProductIds $productIds -Channel $channel
        switch ($result) {
            'VULNERABLE' { Write-Host "VULNERABLE $cve" -ForegroundColor Red }
            'NOT VULNERABLE' { Write-Host "NOT VULNERABLE $cve" -ForegroundColor Green }
            default { Write-Host "UNKNOWN $cve DEBUG=CANAL_NO_DETERMINADO" -ForegroundColor Yellow }
        }
    } catch {
        # No publicar excepciones que puedan incluir nombres, rutas o URLs internas.
        $reason = $_.Exception.Message
        $knownReasons = @(
            'SO_NO_COMPATIBLE', 'SIN_INVENTARIO_C2R', 'METADATOS_INVALIDOS',
            'OUTLOOK_CLASSIC_NO_CONFIRMADO', 'EDICION_NO_CUBIERTA', 'EDICION_AMBIGUA',
            'RAMA_NO_CUBIERTA', 'RAMA_CANAL_NO_CUBIERTA', 'CANAL_NO_CUBIERTO'
        )
        if ($reason -notin $knownReasons) { $reason = 'ERROR_LECTURA_LOCAL' }
        Write-Host "UNKNOWN $cve DEBUG=$reason" -ForegroundColor Yellow
    } finally {
        for ($index = $keys.Count - 1; $index -ge 0; $index--) {
            $keys[$index].Dispose()
        }
    }
}
